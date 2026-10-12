package leakcheck

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The 429 the Hansestack gateway actually returns, verbatim from
// https://github.com/hansestack/hansestack-go/issues/4.
//
// Every other test in this package builds its headers from whatever the case
// needs to prove. This one is the opposite: it is the production response,
// copied, and nothing in it may be adjusted to make an assertion pass. If the
// gateway changes, this test fails and that is the point — it is the only
// place the library's behaviour is tied to the server it is written for.
//
// Two things about it decide what the library does, and neither is obvious
// from the parser in isolation:
//
//   - There is no Retry-After. The specified header this client prefers is
//     simply absent, so every live rate limit resolves through the
//     X-RateLimit-Reset fallback. The primary path never fires here.
//   - The reset is a Unix timestamp, and the window it describes is two
//     seconds wide.
//
// A two-second window read off an absolute timestamp is measured against this
// host's clock, not the gateway's. That is a real constraint on a security
// control and TestGatewayWindowIsClockSkewSensitive below pins how far it
// bends.
const (
	// date: Wed, 30 Sep 2026 08:23:21 GMT
	gatewayDate = "Wed, 30 Sep 2026 08:23:21 GMT"

	// x-ratelimit-reset: 1790756603 — 2026-09-30T08:23:23Z, two seconds after
	// the response was served.
	gatewayReset = "1790756603"

	gatewayWindow = 2 * time.Second
)

// gatewayHeaders returns the response headers exactly as the gateway sent
// them, including the ones this client ignores. They are kept so that a reader
// can compare this block against the issue without translating anything, and
// so a future header the client starts reading is visible here if it was
// already on the wire.
func gatewayHeaders() http.Header {
	header := http.Header{}
	header.Set("Access-Control-Allow-Origin", "*")
	header.Set("Alt-Svc", `h3=":443"; ma=2592000`)
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Date", gatewayDate)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-RateLimit-Limit", "50")
	header.Set("X-RateLimit-Remaining", "0")
	header.Set("X-RateLimit-Reset", gatewayReset)

	return header
}

// gatewayServedAt is the instant the captured response was served, taken from
// its own Date header. Parsing the capture against this is what makes the
// two-second window exact rather than approximate.
func gatewayServedAt(t *testing.T) time.Time {
	t.Helper()

	served, err := http.ParseTime(gatewayDate)
	if err != nil {
		t.Fatalf("the captured Date header does not parse: %v", err)
	}

	return served
}

// TestGatewayRateLimitResponse pins the parser to the captured response.
//
// It asserts the window, and separately asserts that Retry-After is absent.
// The second assertion is the one worth having: without it a later change that
// started preferring some other header would still read two seconds out of
// this capture and the test would stay green while the live path moved.
func TestGatewayRateLimitResponse(t *testing.T) {
	header := gatewayHeaders()

	if got := header.Get("Retry-After"); got != "" {
		t.Fatalf("the captured response carries Retry-After = %q; "+
			"if the gateway now sends it, this file and the tests that assume "+
			"the fallback path are out of date", got)
	}

	if got := resetFrom(header, gatewayServedAt(t)); got != gatewayWindow {
		t.Errorf("resetFrom() = %v, want %v — the gateway's bucket refills two "+
			"seconds after the response is served", got, gatewayWindow)
	}
}

// TestGatewayWindowIsClockSkewSensitive measures how much client clock skew
// the live configuration tolerates.
//
// X-RateLimit-Reset is absolute, so the delta is only as good as the agreement
// between this host's clock and the gateway's. Against a two-second window
// that agreement does not have to be off by much: a client running three
// seconds fast sees a deadline already past and floors to minResetIn, one
// running a minute slow is pinned to maxResetIn. Neither is a failure — the
// clamp is doing exactly its job and the circuit still closes — but both mean
// the cooldown no longer tracks the window the server advertised.
//
// This is not a regression guard. It is the evidence behind the request to
// send Retry-After instead: delta-seconds carry no dependency on the client's
// clock at all, which is also why draft-ietf-httpapi-ratelimit-headers
// specifies a delta and lets Retry-After take precedence.
func TestGatewayWindowIsClockSkewSensitive(t *testing.T) {
	served := gatewayServedAt(t)

	// The wants are written as literal durations rather than as minResetIn and
	// maxResetIn. The bounds are what a reader needs to weigh the tradeoff, and
	// spelled symbolically the table would keep passing if someone moved them.
	tests := []struct {
		name string
		skew time.Duration
		want time.Duration
	}{
		{"clocks agree", 0, 2 * time.Second},

		// Modest skew still lands inside the window.
		{"one second slow", -time.Second, 3 * time.Second},
		{"one second fast", time.Second, time.Second},

		// Past the window the floor takes over and the dynamic cooldown is
		// gone: every value below a second reads the same.
		{"two seconds fast, the window is exactly spent", 2 * time.Second, time.Second},
		{"three seconds fast", 3 * time.Second, time.Second},
		{"an hour fast", time.Hour, time.Second},

		// In the other direction the cap takes over, and a two-second bucket
		// holds the circuit open for a minute.
		{"a minute slow", -time.Minute, time.Minute},
		{"a day slow", -24 * time.Hour, time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resetFrom(gatewayHeaders(), served.Add(tc.skew)); got != tc.want {
				t.Errorf("resetFrom() with %v of skew = %v, want %v", tc.skew, got, tc.want)
			}
		})
	}
}

// TestGatewayResponseDrivesTheBreaker takes the captured response the whole
// way: served by a real handler, through the client, into a typed error, into
// the breaker's open state.
//
// The parser being right proves less than it looks here. The value has to
// survive four hand-offs before it changes anything an operator can observe,
// and the one that matters in production is the fallback path, because the
// gateway sends no Retry-After. This is that path end to end.
func TestGatewayResponseDrivesTheBreaker(t *testing.T) {
	var hits atomic.Int64

	// The capture is replayed with its reset rewritten relative to the test's
	// clock. The headers, their absence and the two-second width are the
	// gateway's; only the epoch moves, because a response captured in
	// September cannot open a circuit today.
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)

		header := gatewayHeaders()
		header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		header.Set("X-RateLimit-Reset", formatUnix(time.Now().Add(gatewayWindow)))

		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit should have opened at the threshold", got)
	}

	// Still inside the window the gateway advertised. Nothing may be let
	// through yet.
	now = now.Add(gatewayWindow / 2)
	mustCheck(t, client)
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit reopened before the "+
			"gateway's window had passed", got)
	}

	// Past it, and far short of the configured minute. The probe goes out.
	now = now.Add(gatewayWindow)
	mustCheck(t, client)
	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — the cooldown must come from the "+
			"gateway's reset timestamp, not the configured minute", got)
	}
}

// TestGatewayResponseCarriesItsStatus pins the verdict the captured response
// produces. The window is an optimisation; this is the part callers branch on,
// and it must not move when the header handling does.
func TestGatewayResponseCarriesItsStatus(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		for name, values := range gatewayHeaders() {
			w.Header()[name] = values
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithFailClose())

	_, err := client.CheckPassword(context.Background(), pwPassword)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want it to match ErrRateLimited", err)
	}

	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("err = %v, want a *RateLimitError", err)
	}
	if rle.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want %d", rle.StatusCode, http.StatusTooManyRequests)
	}
}

// gatewayHeadersWithRetryAfter is the same response with the gateway migrated
// to Retry-After, as discussed on #11: the same two-second window, stated as a
// delta instead of as an instant.
//
// X-RateLimit-Reset is kept alongside it. Dropping it would break anyone
// already parsing it, and the two must then be rendered from one value or they
// disagree by rounding — so where both are present the specified header wins,
// which is what this exercises.
func gatewayHeadersWithRetryAfter() http.Header {
	header := gatewayHeaders()
	header.Set("Retry-After", "2")

	return header
}

// TestGatewayWithRetryAfterIsClockIndependent is the other half of the
// migration, written against the target state rather than today's.
//
// It is not waiting for the gateway. The point is the comparison with
// TestGatewayWindowIsClockSkewSensitive directly above: the same gateway, the
// same two-second window, the same resulting cooldown — and no dependency on
// this host's clock at all. The skew column that bends the timestamp from one
// second to a full minute is flat here.
//
// That is the whole argument for sending Retry-After, as a diff rather than as
// prose. It is also why draft-ietf-httpapi-ratelimit-headers specifies a delta
// and lets Retry-After take precedence where both are present.
//
// When the gateway does migrate, the capture at the top of this file is what
// changes; this test stops describing the target and starts describing
// production, and TestGatewayRateLimitResponse fails to say so.
func TestGatewayWithRetryAfterIsClockIndependent(t *testing.T) {
	served := gatewayServedAt(t)

	// The same skews that move the timestamp path across the whole clamp.
	skews := []struct {
		name string
		skew time.Duration
	}{
		{"clocks agree", 0},
		{"one second slow", -time.Second},
		{"one second fast", time.Second},
		{"two seconds fast, the window is exactly spent", 2 * time.Second},
		{"three seconds fast", 3 * time.Second},
		{"an hour fast", time.Hour},
		{"a minute slow", -time.Minute},
		{"a day slow", -24 * time.Hour},
	}

	for _, tc := range skews {
		t.Run(tc.name, func(t *testing.T) {
			got := resetFrom(gatewayHeadersWithRetryAfter(), served.Add(tc.skew))
			if got != gatewayWindow {
				t.Errorf("resetFrom() with %v of skew = %v, want %v — a delta "+
					"must not depend on the client's clock", tc.skew, got, gatewayWindow)
			}
		})
	}
}

// TestGatewayRetryAfterWinsOverItsOwnReset pins the precedence on the one
// response where it is observable: both headers present, describing the same
// window, disagreeing by a second because one of them was rendered from a
// rounded clock.
//
// The reset here is deliberately three seconds out while Retry-After says two.
// A gateway rendering both from a single value would not produce this, but
// rounding at the boundary does, and the specified header is the one to
// believe.
func TestGatewayRetryAfterWinsOverItsOwnReset(t *testing.T) {
	served := gatewayServedAt(t)

	header := gatewayHeadersWithRetryAfter()
	header.Set("X-RateLimit-Reset", formatUnix(served.Add(3*time.Second)))

	if got := resetFrom(header, served); got != gatewayWindow {
		t.Errorf("resetFrom() = %v, want %v — Retry-After is specified and "+
			"self-describing, X-RateLimit-Reset is neither", got, gatewayWindow)
	}
}

// TestGatewayRetryAfterDrivesTheBreaker takes the migrated response the whole
// way, the same journey TestGatewayResponseDrivesTheBreaker makes for the
// timestamp.
//
// Nothing downstream of the parser may notice which header the window came
// from: same trip, same wait, same probe.
func TestGatewayRetryAfterDrivesTheBreaker(t *testing.T) {
	var hits atomic.Int64

	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)

		header := gatewayHeadersWithRetryAfter()
		header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		header.Set("X-RateLimit-Reset", formatUnix(time.Now().Add(gatewayWindow)))

		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithCircuitBreaker(2, time.Minute))

	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range 4 {
		mustCheck(t, client)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit should have opened at the threshold", got)
	}

	now = now.Add(gatewayWindow / 2)
	mustCheck(t, client)
	if got := hits.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2 — the circuit reopened before the "+
			"advertised delta had passed", got)
	}

	now = now.Add(gatewayWindow)
	mustCheck(t, client)
	if got := hits.Load(); got != 3 {
		t.Errorf("requests = %d, want 3 — a delta must shorten the cooldown "+
			"exactly as the timestamp does today", got)
	}
}

// formatUnix renders t as the gateway renders X-RateLimit-Reset: whole seconds
// since the epoch, no units, nothing to say which encoding it is.
func formatUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
