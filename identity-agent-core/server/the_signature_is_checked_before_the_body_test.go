package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
)

// A request that declares its body's digest (X-IA-Body-Digest) has its
// signature checked before any of the body is read.

func digestOf(body string) string { return iacrypto.Blake3QB64Must([]byte(body)) }

func serveThroughTheGate(s *CoreServer, req *http.Request) (reached bool, w *httptest.ResponseRecorder) {
	w = httptest.NewRecorder()
	probe := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	s.authorize(s.buildRouter(""))(probe).ServeHTTP(w, req)
	return
}

// The motivating case: no key, a fresh timestamp, a body declared at 500 MiB on
// a route that allows 512. Refused having read nothing.
func TestAGarbageSignatureOnTheRecoveryRouteIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	sealTestOwner(t, s)

	body := &countingBody{total: 500 << 20}
	req := remote("POST", "/api/recovery/start", "")
	req.Body = body
	req.ContentLength = body.total
	req.Header.Set(headerOwnerSig, "0Bgarbage")
	req.Header.Set(headerOwnerTimestamp, time.Now().UTC().Format(time.RFC3339))
	req.Header.Set(headerBodyDigest, digestOf("anything"))

	w := httptest.NewRecorder()
	s.buildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if body.served != 0 {
		t.Fatalf("the agent read %d bytes of a request whose signature was garbage", body.served)
	}
}

// A well-formed signature by the wrong key, chunked (no declared length), is
// refused unread as well.
func TestAWrongKeyWithADeclaredDigestIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	sealTestOwner(t, s)
	otherSeed := make([]byte, 32)
	otherSeed[0] = 9

	req := signed(t, "POST", "/api/recovery/start", "{}", otherSeed, time.Now())
	body := &countingBody{total: 400 << 20}
	req.Body = body
	req.ContentLength = -1
	req.Header.Set(headerBodyDigest, digestOf("{}"))

	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reached %v, code %d: %s", reached, w.Code, w.Body.String())
	}
	if body.served != 0 {
		t.Fatalf("read %d bytes before the signature was known good", body.served)
	}
}

// A validly signed 20 MiB archive with the header is accepted, and the handler
// reads exactly the bytes that were signed.
func TestAValidlySignedArchiveWithItsDigestIsAcceptedWhole(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	payload := `{"archive_b64":"` + strings.Repeat("A", 20<<20) + `"}`

	req := signed(t, "POST", "/api/recovery/start", payload, seed, time.Now())
	req.Header.Set(headerBodyDigest, digestOf(payload))

	var got string
	w := httptest.NewRecorder()
	probe := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	})
	s.authorize(s.buildRouter(""))(probe).ServeHTTP(w, req)
	if got != payload {
		t.Fatalf("the handler was given %d bytes, want the %d that were signed (code %d: %s)",
			len(got), len(payload), w.Code, w.Body.String())
	}
}

// A body that is not the one the header declares and the signature covers is a
// 400 before any handler sees it.
func TestABodyThatDoesNotMatchItsDigestIsRefusedBeforeTheHandler(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	signedBody := `{"archive_b64":"AAAA"}`

	req := signed(t, "POST", "/api/recovery/start", signedBody, seed, time.Now())
	req.Header.Set(headerBodyDigest, digestOf(signedBody))
	other := `{"archive_b64":"BBBB"}`
	req.Body = io.NopCloser(strings.NewReader(other))
	req.ContentLength = int64(len(other))

	reached, w := serveThroughTheGate(s, req)
	if reached {
		t.Fatal("a body that is not the signed one reached the handler")
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), headerBodyDigest) {
		t.Fatalf("got %d, want a 400 naming %s: %s", w.Code, headerBodyDigest, w.Body.String())
	}
	// The signature was not spent by a request that failed on its body: the same
	// headers with the body that was signed are admitted.
	again := httptest.NewRequest("POST", "/api/recovery/start", strings.NewReader(signedBody))
	again.RemoteAddr = req.RemoteAddr
	again.Header = req.Header.Clone()
	if reached, w := serveThroughTheGate(s, again); !reached {
		t.Fatalf("the signed body was refused after a mismatch: %d %s", w.Code, w.Body.String())
	}
}

// A header that does not match the signed string fails the signature, not the
// body check: the declared digest is what the signature is checked over.
func TestADigestHeaderThatWasNotSignedFailsTheSignature(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	req := signed(t, "POST", "/api/recovery/start", "{}", seed, time.Now())
	req.Header.Set(headerBodyDigest, digestOf("something else"))
	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("reached %v, code %d", reached, w.Code)
	}
}

func TestAMalformedDigestHeaderIsRefusedNotTreatedAsAbsent(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	for _, bad := range []string{"", "not-a-digest", "E" + strings.Repeat("!", 43), digestOf("{}") + "A"} {
		req := signed(t, "POST", "/api/recovery/start", "{}", seed, time.Now())
		req.Header.Set(headerBodyDigest, bad)
		reached, w := serveThroughTheGate(s, req)
		if reached || w.Code == http.StatusOK {
			t.Fatalf("%q: reached %v, code %d", bad, reached, w.Code)
		}
	}
}

// No header: today's behaviour, at the default bound only. The route's larger
// bound is for requests that declare their digest.
func TestWithoutTheHeaderOnlyTheDefaultBoundApplies(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	payload := `{"archive_b64":"` + strings.Repeat("A", 20<<20) + `"}`

	req := signed(t, "POST", "/api/recovery/start", payload, seed, time.Now())
	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("reached %v, code %d, want 413 without the header: %s", reached, w.Code, w.Body.String())
	}

	// And it stops reading at the default bound, not the route's.
	body := &countingBody{total: 400 << 20}
	req = signed(t, "POST", "/api/recovery/start", "{}", seed, time.Now())
	req.Body = body
	req.ContentLength = -1
	serveThroughTheGate(s, req)
	if body.served == 0 || body.served > maxSignedBodyBytes+1 {
		t.Fatalf("read %d bytes, want 1..%d", body.served, maxSignedBodyBytes+1)
	}

	// A small request without the header is still served: older clients work.
	small := signed(t, "POST", "/api/recovery/start", "{}", seed, time.Now())
	if reached, w := serveThroughTheGate(s, small); !reached {
		t.Fatalf("an older client's small request was refused: %d %s", w.Code, w.Body.String())
	}
}

// The header counts only where it was checked: a body larger than the default
// on a route with no bound of its own stays refused, header or not.
func TestTheHeaderDoesNotRaiseTheBoundOfARouteWithoutOne(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	payload := `{"pad":"` + strings.Repeat("A", 20<<20) + `"}`
	req := signed(t, "PUT", "/api/settings/tunnel", payload, seed, time.Now())
	req.Header.Set(headerBodyDigest, digestOf(payload))
	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("reached %v, code %d: %s", reached, w.Code, w.Body.String())
	}
}

func TestTheDigestHeaderIsSentOnceOrNotAtAll(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Add(headerBodyDigest, digestOf("a"))
	r.Header.Add(headerBodyDigest, digestOf("a"))
	if _, _, err := theDigestTheRequestDeclares(r); err == nil {
		t.Fatal("two copies of the header were accepted")
	}
}

// --- the controller path ---

func TestAControllerWithAGarbageSignatureIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	req := asThatMachine(t, aid, "PUT", "/api/profile", "{}", seed, "", time.Time{})
	req.Header.Set(headerControllerSig, "0Bgarbage")
	req.Header.Set(headerBodyDigest, digestOf("{}"))
	body := &countingBody{total: 500 << 20}
	req.Body = body
	req.ContentLength = body.total

	if _, _, err := s.theControllerBehind(req); err == nil {
		t.Fatal("a garbage signature admitted a machine")
	}
	if body.served != 0 {
		t.Fatalf("read %d bytes before the machine's signature was known good", body.served)
	}
}

func TestAControllerWithItsDigestIsAdmittedWithTheBodyIntact(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	payload := `{"pad":"` + strings.Repeat("A", 15<<20) + `"}`

	req := asThatMachine(t, aid, "POST", "/api/recovery/start", payload, seed, "", time.Time{})
	req.Header.Set(headerBodyDigest, digestOf(payload))
	req = withSignedBodyBound(req, "/api/recovery/start") // as the gate does
	if _, _, err := s.theControllerBehind(req); err != nil {
		t.Fatalf("a correctly signed request with its digest was refused: %v", err)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != payload {
		t.Fatalf("the handler would be given %d bytes, want %d", len(got), len(payload))
	}
}

func TestAControllersBodyThatDoesNotMatchItsDigestIsRefusedAs400(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	req := asThatMachine(t, aid, "PUT", "/api/profile", `{"a":1}`, seed, "", time.Time{})
	req.Header.Set(headerBodyDigest, digestOf(`{"a":1}`))
	req.Body = io.NopCloser(strings.NewReader(`{"a":2}`))

	_, _, err := s.theControllerBehind(req)
	var mismatched bodyDoesNotMatchItsDigest
	if !errors.As(err, &mismatched) {
		t.Fatalf("got %v, want the digest mismatch", err)
	}
	if left, rerr := io.ReadAll(req.Body); rerr == nil || len(left) != 0 {
		t.Fatalf("a refused body still yields %d bytes (err %v)", len(left), rerr)
	}

	// Through the gate: a 400, and the handler is never reached.
	req = asThatMachine(t, aid, "PUT", "/api/profile", `{"a":1}`, seed, "", time.Time{})
	req.Header.Set(headerBodyDigest, digestOf(`{"a":1}`))
	req.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code != http.StatusBadRequest {
		t.Fatalf("reached %v, code %d: %s", reached, w.Code, w.Body.String())
	}
}

func TestAControllerWithoutTheHeaderGetsOnlyTheDefaultBound(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	req := asThatMachine(t, aid, "PUT", "/api/profile", "{}", seed, "", time.Time{})
	body := &countingBody{total: 400 << 20}
	req.Body = body
	req.ContentLength = -1
	req = withSignedBodyBound(req, "/api/profile")

	_, _, err := s.theControllerBehind(req)
	var tooLarge requestTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("got %v, want the size refusal", err)
	}
	if body.served > maxSignedBodyBytes+1 {
		t.Fatalf("read %d bytes, want at most %d", body.served, maxSignedBodyBytes+1)
	}
}
