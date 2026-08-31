package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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
		{"POST", "/api/recovery/root-aid-rotation"},
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

// Every route a browser session is forbidden must be a route that EXISTS.
//
// This is the test that should have existed from the start. A deny-list keyed
// by route pattern fails silently in the worst possible direction: an entry
// naming a route that was never registered, or was later renamed, protects
// nothing while continuing to look like protection. Nothing errors, no request
// is refused, and the list still reads as though the operation is covered.
//
// It caught three immediately. /api/identity/rotate was never a route at all;
// the real ones are /api/recovery/root-aid-rotation and
// /api/employees/{aid}/approve|revoke. Root-AID rotation was therefore
// reachable from a browser session, which is exactly what the list exists to
// prevent.
//
// Some routes genuinely exist only in some configurations — the signer and
// employee routes mount only where an organisation overlay is present. Those
// are named below rather than silently tolerated, because "absent because it
// is conditional" and "absent because somebody renamed it" look identical from
// here, and only one of them is fine.
var conditionallyMounted = map[string]string{
	"POST /api/signer/invites":                "mounts only with an asset handler, i.e. on an organisation agent",
	"POST /api/signer/invites/{token}/redeem": "mounts only with an asset handler, i.e. on an organisation agent",
	"POST /api/employees/{aid}/approve":       "mounts unless an overlay has taken the employee routes",
	"POST /api/employees/{aid}/revoke":        "mounts unless an overlay has taken the employee routes",
}

func TestEveryForbiddenRouteIsARealRoute(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	registered := map[string]bool{}
	if err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(registered) < 100 {
		t.Fatalf("only %d routes walked — the router did not build", len(registered))
	}

	for key := range sessionForbidden {
		if registered[key] {
			continue
		}
		if _, known := conditionallyMounted[key]; known {
			continue
		}
		t.Errorf("sessionForbidden names %q, which is not a registered route and is not "+
			"listed as conditionally mounted. A browser session is therefore NOT blocked "+
			"from whatever that was meant to cover — the entry looks like protection and "+
			"is none.", key)
	}

	// The other direction: an entry excused as conditional that has since become
	// unconditional is an excuse nobody needs any more, and leaving it means the
	// next genuine rot hides behind it.
	for key := range conditionallyMounted {
		if _, forbidden := sessionForbidden[key]; !forbidden {
			t.Errorf("%q is excused as conditionally mounted but is no longer in "+
				"sessionForbidden — remove the excuse", key)
		}
	}
}

func TestASessionCannotStartStopOrWeakenARecovery(t *testing.T) {
	// A browser session is something the owner grants for a while and that
	// whoever holds the browser then has. A recovery replaces this identity's
	// key material and everything it held, so it belongs behind the same bar as
	// installing a root seed.
	//
	// The duress policy is the sharpest of these: it says what must happen if
	// the owner may be being forced. A session that could turn it off could
	// disable the protection and then use the recovery it was protecting
	// against — which would make the control the third gate exists to provide
	// removable by the very thing it defends against.
	for _, route := range []string{
		"PUT /api/recovery/duress-policy",
		"POST /api/recovery/start",
		"POST /api/recovery/sessions/{id}/activate",
		"POST /api/recovery/sessions/{id}/cancel",
		"POST /api/recovery/sessions/{id}/rotation",
		"POST /api/inception",
		"POST /api/rotation",
	} {
		if _, forbidden := sessionForbidden[route]; !forbidden {
			t.Fatalf("a browser session can reach %s", route)
		}
	}
}
