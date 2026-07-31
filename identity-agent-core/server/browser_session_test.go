package server

import (
	"testing"
	"time"
)

func newSessionsForTest() *browserSessions { return newBrowserSessions() }

// The flow, start to finish: the browser keeps a secret, the phone grants by
// code, the browser exchanges its secret for the session.
func TestABrowserCanBeSignedInByThePhone(t *testing.T) {
	b := newSessionsForTest()
	const secret = "a-secret-only-the-browser-has"

	id, code, _, err := b.newChallenge(hashSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.grant(code); err != nil {
		t.Fatalf("grant: %v", err)
	}
	token, expires, err := b.claim(id, secret)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !b.valid(token) {
		t.Error("the session was not usable after being claimed")
	}
	if !expires.After(time.Now().UTC()) {
		t.Error("the session expired before it began")
	}
}

// The attack the browser's secret exists to stop. The code is on a screen;
// anybody who sees it knows it. Without the secret, seeing the code would be
// enough to collect the session the owner just granted — the owner would have
// authorised a stranger while watching their own screen.
func TestSeeingTheCodeIsNotEnoughToTakeTheSession(t *testing.T) {
	b := newSessionsForTest()
	id, code, _, _ := b.newChallenge(hashSecret("the-real-browser-secret"))
	b.grant(code)

	if _, _, err := b.claim(id, "a-guess"); err == nil {
		t.Fatal("a session was collected without the browser's secret")
	}
	// And the real browser can still collect it: a failed attempt must not
	// consume the login.
	if _, _, err := b.claim(id, "the-real-browser-secret"); err != nil {
		t.Errorf("the genuine browser was locked out by somebody else's guess: %v", err)
	}
}

// A challenge that can be claimed twice is a session that can be handed to a
// second browser.
func TestASessionCannotBeClaimedTwice(t *testing.T) {
	b := newSessionsForTest()
	const secret = "browser-secret"
	id, code, _, _ := b.newChallenge(hashSecret(secret))
	b.grant(code)

	if _, _, err := b.claim(id, secret); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.claim(id, secret); err == nil {
		t.Error("the same login was collected twice")
	}
}

// A code that has already been used being usable again is how one displayed
// code becomes two sessions.
func TestACodeCannotBeGrantedTwice(t *testing.T) {
	b := newSessionsForTest()
	_, code, _, _ := b.newChallenge(hashSecret("s"))

	if err := b.grant(code); err != nil {
		t.Fatal(err)
	}
	if err := b.grant(code); err == nil {
		t.Error("the same code was granted twice")
	}
}

// "Not yet" is not "no". A browser polling while the owner finds their phone
// must be able to tell the difference.
func TestClaimingBeforeTheGrantSaysNotYet(t *testing.T) {
	b := newSessionsForTest()
	const secret = "browser-secret"
	id, _, _, _ := b.newChallenge(hashSecret(secret))

	_, _, err := b.claim(id, secret)
	if err != errSessionNotGranted {
		t.Errorf("expected a not-yet answer, got %v", err)
	}
}

// A code left on a screen has to stop working.
func TestAnExpiredChallengeCannotBeGranted(t *testing.T) {
	b := newSessionsForTest()
	_, code, _, _ := b.newChallenge(hashSecret("s"))

	for _, c := range b.challenges {
		c.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	}
	if err := b.grant(code); err == nil {
		t.Error("an expired code was still granted")
	}
}

func TestAnExpiredSessionStopsWorking(t *testing.T) {
	b := newSessionsForTest()
	const secret = "browser-secret"
	id, code, _, _ := b.newChallenge(hashSecret(secret))
	b.grant(code)
	token, _, _ := b.claim(id, secret)

	if !b.valid(token) {
		t.Fatal("the session was not valid to begin with")
	}
	for _, s := range b.sessions {
		s.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	}
	if b.valid(token) {
		t.Error("an expired session was still accepted")
	}
}

// Signing out has to actually end it.
func TestEndingASessionRevokesIt(t *testing.T) {
	b := newSessionsForTest()
	const secret = "browser-secret"
	id, code, _, _ := b.newChallenge(hashSecret(secret))
	b.grant(code)
	token, _, _ := b.claim(id, secret)

	if !b.revoke(token) {
		t.Error("revoking a live session reported nothing to revoke")
	}
	if b.valid(token) {
		t.Error("the session survived being ended")
	}
}

// A store holding live credentials in clear is a store worth stealing.
func TestTokensAndSecretsAreStoredHashed(t *testing.T) {
	b := newSessionsForTest()
	const secret = "browser-secret"
	id, code, _, _ := b.newChallenge(hashSecret(secret))
	b.grant(code)
	token, _, _ := b.claim(id, secret)

	for key, s := range b.sessions {
		if key == token || s.TokenHash == token {
			t.Error("a live session token is stored in clear")
		}
	}
}

// The code is read aloud and typed by hand. 0/O and 1/l is a failure that
// reads as "the login is broken".
func TestTheCodeHasNoLookAlikeCharacters(t *testing.T) {
	for i := 0; i < 200; i++ {
		code, err := readableCode()
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range code {
			switch ch {
			case '0', 'O', '1', 'I', 'L', 'A', 'E', 'U':
				t.Fatalf("code %q contains an easily-confused character %q", code, ch)
			}
		}
	}
}

// A garbled or unknown code should say so rather than appearing to work.
func TestAnUnknownCodeIsRefused(t *testing.T) {
	b := newSessionsForTest()
	b.newChallenge(hashSecret("s"))
	if err := b.grant("ZZZZ-ZZZZ"); err == nil {
		t.Error("a code nobody is waiting for was granted")
	}
}

// The list of what a session cannot do is the reason sessions are safe to hand
// out. These are the operations that change who the identity IS.
func TestASessionCannotChangeTheIdentityItself(t *testing.T) {
	for _, route := range []struct{ method, pattern string }{
		{"POST", "/api/keystore/root-seed"},
		{"POST", "/api/identity/rotate"},
		{"POST", "/api/signer/invites"},
		{"POST", "/api/signing-requests/{id}/fulfil"},
		{"POST", "/api/reset"},
	} {
		reason, forbidden := requiresTheKeyItself(route.method, route.pattern)
		if !forbidden {
			t.Errorf("%s %s is reachable from a browser session", route.method, route.pattern)
		}
		if reason == "" {
			t.Errorf("%s %s is forbidden with no reason to tell the person",
				route.method, route.pattern)
		}
	}
}

// Everything else is reachable, or a session would be useless.
func TestASessionCanDoOrdinaryThings(t *testing.T) {
	for _, route := range []struct{ method, pattern string }{
		{"GET", "/api/contacts"},
		{"GET", "/api/credentials"},
		{"GET", "/api/providers"},
	} {
		if _, forbidden := requiresTheKeyItself(route.method, route.pattern); forbidden {
			t.Errorf("%s %s is blocked, which would make a session useless",
				route.method, route.pattern)
		}
	}
}
