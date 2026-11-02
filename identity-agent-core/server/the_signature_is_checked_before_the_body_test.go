package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	// The signature IS spent by a request that failed on its body, so that a
	// captured request cannot be resent to make the agent read again: the same
	// headers with the body that was signed are refused too.
	again := httptest.NewRequest("POST", "/api/recovery/start", strings.NewReader(signedBody))
	again.RemoteAddr = req.RemoteAddr
	again.Header = req.Header.Clone()
	if reached, w := serveThroughTheGate(s, again); reached {
		t.Fatalf("a signature burned by a mismatched body admitted a resend: %d %s", w.Code, w.Body.String())
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

	// Through the gate: a 400, and the handler is never reached. A different
	// timestamp, so this is a different signature from the one the direct call
	// above spent.
	req = asThatMachineAt(t, aid, "PUT", "/api/profile", `{"a":1}`, seed, time.Now().Add(-5*time.Second))
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

// --- a verified signature is spent before the body is read ---

// A captured signed request resent with a body that does not match is refused as
// already used, and the second time nothing of the body is read.
func TestAVerifiedSignatureResentWithAMismatchedBodyIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	at := time.Now()

	first := signed(t, "POST", "/api/recovery/start", "{}", seed, at)
	first.Header.Set(headerBodyDigest, digestOf("{}"))
	first.Body = io.NopCloser(strings.NewReader(`{"x":1}`))
	if reached, w := serveThroughTheGate(s, first); reached || w.Code != http.StatusBadRequest {
		t.Fatalf("first: reached %v, code %d: %s", reached, w.Code, w.Body.String())
	}

	resent := signed(t, "POST", "/api/recovery/start", "{}", seed, at)
	resent.Header.Set(headerBodyDigest, digestOf("{}"))
	body := &countingBody{total: 400 << 20}
	resent.Body = body
	resent.ContentLength = body.total
	// Directly, for the reason: through the gate an owner refusal reads the same
	// whatever the cause.
	err := s.verifyOwnerSignature(resent)
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("got %v, want refused as already used", err)
	}
	if body.served != 0 {
		t.Fatalf("read %d bytes of a request whose signature was already spent", body.served)
	}
}

// The same, on the controller path.
func TestAControllerSignatureResentWithAMismatchedBodyIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	at := time.Now()

	first := asThatMachine(t, aid, "PUT", "/api/profile", `{"a":1}`, seed, "", at)
	first.Header.Set(headerBodyDigest, digestOf(`{"a":1}`))
	first.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
	var mismatched bodyDoesNotMatchItsDigest
	if _, _, err := s.theControllerBehind(first); !errors.As(err, &mismatched) {
		t.Fatalf("first: got %v, want the digest mismatch", err)
	}

	// The very same headers, not a second signing: the stamp is the clock's.
	resent := asThatMachine(t, aid, "PUT", "/api/profile", `{"a":1}`, seed, "", at)
	resent.Header = first.Header.Clone()
	body := &countingBody{total: 400 << 20}
	resent.Body = body
	resent.ContentLength = body.total
	_, _, err := s.theControllerBehind(resent)
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("got %v, want refused as already used", err)
	}
	if body.served != 0 {
		t.Fatalf("read %d bytes of a request whose signature was already spent", body.served)
	}
}

// Resends of one valid request sent at once: the body is read at most once.
func TestParallelResendsOfOneSignedRequestReadTheBodyAtMostOnce(t *testing.T) {
	const n = 16
	payload := `{"pad":"` + strings.Repeat("A", 1<<20) + `"}`

	check := func(t *testing.T, name string, run func(i int, body io.ReadCloser) bool) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var admitted, readers int
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := &readCounted{r: strings.NewReader(payload)}
				<-start
				ok := run(i, c)
				mu.Lock()
				defer mu.Unlock()
				if ok {
					admitted++
				}
				if atomic.LoadInt64(&c.n) > 0 {
					readers++
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if readers > 1 || admitted > 1 {
			t.Fatalf("%s: %d requests had their body read, %d admitted; want at most one", name, readers, admitted)
		}
	}

	t.Run("owner", func(t *testing.T) {
		s := newAuthTestServer(t)
		seed, _ := sealTestOwner(t, s)
		at := time.Now()
		reqs := make([]*http.Request, n)
		for i := range reqs {
			reqs[i] = signed(t, "POST", "/api/recovery/start", payload, seed, at)
			reqs[i].Header.Set(headerBodyDigest, digestOf(payload))
		}
		check(t, "owner", func(i int, body io.ReadCloser) bool {
			reqs[i].Body = body
			reached, _ := serveThroughTheGate(s, reqs[i])
			return reached
		})
	})
	t.Run("controller", func(t *testing.T) {
		s := newAuthTestServer(t)
		aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
		at := time.Now()
		reqs := make([]*http.Request, n)
		// Signed once and the headers copied: a machine's signature is not
		// deterministic, so signing again would be a different request.
		one := asThatMachine(t, aid, "POST", "/api/recovery/start", payload, seed, "", at)
		one.Header.Set(headerBodyDigest, digestOf(payload))
		for i := range reqs {
			reqs[i] = asThatMachine(t, aid, "POST", "/api/recovery/start", payload, seed, "", at)
			reqs[i].Header = one.Header.Clone()
			reqs[i] = withSignedBodyBound(reqs[i], "/api/recovery/start")
		}
		check(t, "controller", func(i int, body io.ReadCloser) bool {
			reqs[i].Body = body
			_, _, err := s.theControllerBehind(reqs[i])
			return err == nil
		})
	})
}

type readCounted struct {
	r io.Reader
	n int64
}

func (c *readCounted) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	atomic.AddInt64(&c.n, int64(n))
	return n, err
}
func (c *readCounted) Close() error { return nil }

// The controller case through the gate, on a large-bound route, with a
// well-formed signature from a key that is not the machine's: refused having
// read nothing. (The direct test above uses a default-bound route and a
// signature that may not even decode.)
func TestAControllersWrongKeyWithADeclaredDigestIsRefusedHavingReadNothing(t *testing.T) {
	s := newAuthTestServer(t)
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)
	otherSeed := make([]byte, 32)
	otherSeed[0] = 9

	req := asThatMachine(t, aid, "POST", "/api/recovery/start", "{}", otherSeed, "", time.Time{})
	req.Header.Set(headerBodyDigest, digestOf("{}"))
	body := &countingBody{total: 400 << 20}
	req.Body = body
	req.ContentLength = -1

	reached, w := serveThroughTheGate(s, req)
	if reached || w.Code == http.StatusOK {
		t.Fatalf("reached %v, code %d: %s", reached, w.Code, w.Body.String())
	}
	if body.served != 0 {
		t.Fatalf("read %d bytes before the machine's signature was known good", body.served)
	}
}
