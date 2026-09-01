package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

// What a controller's signature is bound to, and that it is spent once.
//
// The file this covers claims three things: the request is signed over its own
// method, path and body; the timestamp bounds a window; and a signature is spent
// once so a captured one cannot be replayed. A reviewer deleted every field of
// the canonical string, the replay guard, and the window — and the suite still
// reported ok for all ten. The code was right; nothing held it there.
//
// These are the checks that stand between a captured request and the identity,
// so each mutation gets a test that fails without it.

// A signature made for one request cannot be pointed at another. This is the
// sharpest of them: capture a harmless GET in flight and re-present its headers
// on something that destroys the identity.
func TestASignatureCannotBeMovedToAnotherRequest(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	// Moved onto ORDINARY routes on purpose. An earlier version of this moved the
	// signature onto RAISED ones, and passed for the wrong reason: the level gate
	// refused them before the signature was ever the deciding thing, so the test
	// went on passing with the method and path deleted from the signed string. It
	// was measuring a different lock than the one it named.
	captured := asThatMachine(t, aid, "POST", "/api/verify", `{"a":1}`, seed, "", time.Time{})

	for _, moved := range []struct{ method, path, body string }{
		{"POST", "/api/cesr/encode", `{"a":1}`}, // a different path
		{"GET", "/api/identity", ""},            // a different method and path
		{"POST", "/api/verify", `{"a":2}`},      // the same request, a different body
	} {
		req := remote(moved.method, moved.path, moved.body)
		for _, h := range []string{
			headerControllerAID, headerControllerSig, headerControllerTimestamp,
		} {
			req.Header.Set(h, captured.Header.Get(h))
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("a signature made for POST /api/verify was accepted on %s %s "+
				"(body %q): %d", moved.method, moved.path, moved.body, w.Code)
		}
	}
}

// The same signature cannot be used twice, so capturing one in flight buys a
// single use at most — and only if it arrives before the original.
func TestASignatureIsSpentOnce(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	req := asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{})
	replay := remote("GET", "/api/profile", "")
	for _, h := range []string{
		headerControllerAID, headerControllerSig, headerControllerTimestamp,
	} {
		replay.Header.Set(h, req.Header.Get(h))
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("the first use was refused, so this proves nothing: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, replay)
	if w.Code != http.StatusForbidden {
		t.Fatalf("the same signature was accepted twice: %d", w.Code)
	}
}

// A signature from outside the window is refused however good it is, so one
// captured today is not usable tomorrow.
func TestASignatureOutsideTheWindowIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	for _, skew := range []time.Duration{
		signedRequestWindow + time.Minute,    // long past
		-(signedRequestWindow + time.Minute), // and the future, which is the same problem
	} {
		req := asThatMachineAt(t, aid, "GET", "/api/profile", "", seed,
			time.Now().UTC().Add(-skew))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("a request signed %s away was accepted: %d", skew, w.Code)
		}
	}
}

// A captured signature cannot be given a fresh timestamp to extend its life.
//
// The window alone does not stop this: it checks the timestamp HEADER, so if the
// timestamp were not inside the signed string, an attacker could take a
// signature made hours ago and simply present it with a current one. What stops
// it is that the moment is part of what was signed, so changing it breaks the
// signature. Without this test, deleting the timestamp from the canonical string
// left the whole suite green.
func TestACapturedSignatureCannotBeGivenAFreshTimestamp(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	// Signed well outside the window, as a captured one would be.
	stale := asThatMachineAt(t, aid, "GET", "/api/identity", "", seed,
		time.Now().UTC().Add(-4*signedRequestWindow))
	// Re-presented as though it were made just now.
	stale.Header.Set(headerControllerTimestamp, time.Now().UTC().Format(time.RFC3339))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, stale)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an old signature was accepted by relabelling when it was made: %d", w.Code)
	}
}

// One machine's signature cannot be presented under another machine's name.
// The identifier is inside the signed string, so swapping it breaks the
// signature rather than naming a different key to check against.
func TestASignatureCannotBePresentedUnderAnotherName(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	// A second authorised machine, so the swap names a key the agent really has.
	other := grantFor(77, GradeEnrolled)
	if _, err := s.controllers().Grant(other, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	r := s.buildRouter("")

	req := asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{})
	req.Header.Set(headerControllerAID, other.ControllerAID)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("one machine's signature was accepted under another's name: %d", w.Code)
	}
}

// Raising the level in flight breaks the REQUEST signature, which is what the
// level being inside the signed string buys.
//
// The existing test for this passed for a different reason — it edited only the
// header, which breaks the voucher binding, so it went on passing with the level
// deleted from the signed string. This presents a genuinely valid voucher for
// the higher level and signs the request over the lower one.
func TestAValidVoucherCannotBeAttachedToASignatureForALowerLevel(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")
	at := time.Now().UTC()

	req := asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelBasic, at)
	req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	req.Header.Set(headerAuthLevelVouchedBy,
		theRootDeviceVouches(t, aid, authprovider.LevelHigh, at, 80))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a valid high voucher was attached to a request signed for a lower "+
			"level and accepted: %d %s", w.Code, w.Body.String())
	}
}

// A measurement dated in the future is not fresh. Without this, a clock ahead of
// the agent's — or a value simply chosen — would satisfy a rule whose entire job
// is keeping the answer current.
func TestAMeasurementFromTheFutureIsNotFresh(t *testing.T) {
	now := time.Now().UTC()
	if freshEnough(authprovider.Result{
		Measured: true, At: now.Add(time.Hour), Level: authprovider.LevelHigh,
	}, now) {
		t.Fatal("a measurement an hour in the future counted as fresh")
	}
}
