package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

// anAuthorisedMachine puts a controller on an agent and returns the machine's
// identifier and the seed it signs with.
//
// Both are derived from the test's own name, so every test is a DIFFERENT
// machine. That is how it works in life, and here it also keeps two tests from
// producing byte-identical signed requests within the same second — which the
// replay guard would correctly refuse as a reused signature, failing the second
// test for a reason that has nothing to do with what it was checking.
func anAuthorisedMachine(t *testing.T, s *CoreServer, grade ControllerGrade) (string, []byte) {
	t.Helper()
	// The device holding this identity's root key, because it is the only thing
	// entitled to say how well somebody was authenticated.
	ownerSeedForTest(t, s)
	seed := make([]byte, ed25519.SeedSize)
	for i, c := range []byte(t.Name()) {
		seed[i%ed25519.SeedSize] ^= c + byte(i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid := "EMachineFor" + t.Name()
	if _, err := s.controllers().Grant(ControllerGrant{
		ControllerAID: aid,
		PublicKey:     iacrypto.VerkeyQB64(pub),
		Label:         "the laptop in the study",
		Grade:         grade,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("authorising the machine: %v", err)
	}
	return aid, seed
}

// asThatMachine builds a request signed by a controller, asserting an
// authentication level measured at a given moment.
//
// Passing an empty level means the machine reported nothing, which is different
// from reporting a weak one.
func asThatMachine(t *testing.T, aid, method, path, body string, seed []byte,
	level authprovider.Level, measuredAt time.Time) *http.Request {
	t.Helper()
	req := remote(method, path, body)
	stamp := time.Now().UTC().Format(time.RFC3339)

	asserted := authprovider.Unmeasured("")
	if level != "" {
		asserted = authprovider.Result{
			Level: level, Measured: true, At: measuredAt.UTC(), Score: 80,
		}
		req.Header.Set(headerControllerAuthLevel, string(level))
		req.Header.Set(headerControllerAuthAt, measuredAt.UTC().Format(time.RFC3339))
		req.Header.Set(headerControllerAuthScore, "80")
		// Vouched for by the root-identity device. Without this the level is the
		// machine scoring itself, which the agent refuses.
		if vouch := theRootDeviceVouches(t, aid, level, measuredAt, 80); vouch != "" {
			req.Header.Set(headerAuthLevelVouchedBy, vouch)
		}
	}

	sig, err := login.SignString(
		canonicalControllerRequest(aid, method, path, stamp, asserted, []byte(body)), seed)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	req.Header.Set(headerControllerAID, aid)
	req.Header.Set(headerControllerSig, sig)
	req.Header.Set(headerControllerTimestamp, stamp)
	return req
}

// The ordinary case, and the reason the class exists: a machine the owner
// authorised reaches an everyday route without anybody having granted it that
// route specifically.
func TestAnAuthorisedMachineReachesAnOrdinaryRoute(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}))
	if w.Code == http.StatusForbidden {
		t.Fatalf("an authorised machine was refused an ordinary route: %s", w.Body.String())
	}
}

// A route added tomorrow is reachable without anybody remembering to allow it.
// That is the difference between this and a capability scope, and it is checked
// against the real router rather than asserted.
func TestARouteNobodyNamedIsStillReachable(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	// A route with no entry in controllerNeedsLevel.
	const ordinary = "GET /api/contacts"
	if _, raised := theLevelThisActionNeeds("GET", "/api/contacts"); raised {
		t.Skip("this route has since been raised; the property is covered elsewhere")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/contacts", "", seed, "", time.Time{}))
	if w.Code == http.StatusForbidden {
		t.Fatalf("%s was refused, so the class is a permit-list rather than a deny-list: %s",
			ordinary, w.Body.String())
	}
}

// A raised action is not reachable on the grant alone. Nothing measured means
// nothing measured — it must not fall through as a weak-but-present level.
func TestARaisedActionNeedsThePersonMeasured(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("rotating keys was allowed on the authorisation alone: %d %s",
			w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "authenticated") {
		t.Errorf("the refusal does not say what would let them through: %s", w.Body.String())
	}
}

// The point of Rob's ruling: rotation IS reachable from a controller, at a
// higher level. If it were simply forbidden, an owner whose key-holding device
// was stolen could never rotate, and the thief would keep the identity.
func TestRotationIsReachableWhenThePersonIsStronglyAuthenticated(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelHigh, time.Now()))
	if w.Code == http.StatusForbidden {
		t.Fatalf("a strongly authenticated person could not rotate from their own "+
			"machine, so a stolen key device would mean the identity can never be "+
			"rotated: %s", w.Body.String())
	}
}

// A weak level does not clear a strong requirement.
func TestAWeakLevelDoesNotClearARaisedAction(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelBasic, time.Now()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a self-asserted identity cleared a gate needing the strongest check: %d", w.Code)
	}
}

// An authentication is a statement about a moment. A machine authorised for
// months would otherwise carry one measurement forever.
func TestAStaleMeasurementDoesNotClearARaisedAction(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelHigh, time.Now().Add(-2*controllerAuthenticationFreshness)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a measurement from %s ago cleared a raised action: %d",
			2*controllerAuthenticationFreshness, w.Code)
	}
	if !strings.Contains(w.Body.String(), "too old") {
		t.Errorf("the refusal does not say the check was stale: %s", w.Body.String())
	}
}

// The level is inside what the machine signed, so raising it in flight breaks
// the signature rather than passing. Without this the threshold is a header
// anybody in the middle could edit.
func TestRaisingTheLevelInFlightIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	req := asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelBasic, time.Now())
	req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an authentication level edited in flight was accepted: %d", w.Code)
	}
}

// A level this build does not define is not a level. A newer controller naming
// something unrecognised must not clear a gate on an older agent.
func TestAnUnrecognisedLevelIsTreatedAsNothingMeasured(t *testing.T) {
	s := newAuthTestServer(t)
	got := s.theAuthenticationSomebodyVouchedFor(func() *http.Request {
		req := remote("POST", "/api/rotation", "")
		req.Header.Set(headerControllerAuthLevel, "platinum")
		req.Header.Set(headerControllerAuthAt, time.Now().UTC().Format(time.RFC3339))
		return req
	}(), "EAnyMachine", time.Now().UTC())
	if got.Measured {
		t.Fatalf("an unrecognised level was treated as a measurement: %+v", got)
	}
}

// A machine whose authorisation was removed is nobody, whatever it signs.
func TestARevokedMachineIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	if err := s.controllers().Revoke(aid); err != nil {
		t.Fatal(err)
	}
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a machine whose authorisation was removed still acted: %d", w.Code)
	}
}

// A signature from a key that was never granted is nobody, even if it names a
// machine that was.
func TestASignatureFromAnotherKeyIsNotThatMachine(t *testing.T) {
	s := newAuthTestServer(t)
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)
	imposter := make([]byte, ed25519.SeedSize)
	for i := range imposter {
		imposter[i] = byte(200 - i)
	}
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/profile", "", imposter, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request signed by a key nobody granted was admitted as that machine: %d", w.Code)
	}
}

// A typo in the table must not silently open a gate. An entry naming a level
// this package does not define is treated as the strongest, not as absent.
func TestAnUnknownRequirementBecomesTheStrongest(t *testing.T) {
	req, raised := theLevelThisActionNeeds("POST", "/api/rotation")
	if !raised || req.Level != authprovider.LevelHigh {
		t.Fatalf("rotation is not raised to the strongest level: %+v", req)
	}

	// Simulate the typo directly, since the table itself is correct.
	const typo = "POST /api/some-raised-thing"
	controllerNeedsLevel[typo] = controllerRequirement{Level: "hgih", Why: "a typo"}
	t.Cleanup(func() { delete(controllerNeedsLevel, typo) })

	got, raised := theLevelThisActionNeeds("POST", "/api/some-raised-thing")
	if !raised {
		t.Fatal("a mistyped requirement stopped being a requirement at all")
	}
	if got.Level != authprovider.LevelHigh {
		t.Fatalf("a mistyped requirement became %q, so the gate is weaker than "+
			"intended rather than louder", got.Level)
	}
}

// Every action this identity's shape depends on is raised. Named explicitly so
// that adding a route which replaces keys, hands back an archive, or decides who
// may act, and forgetting to raise it, fails here rather than in the field.
func TestTheActionsThatChangeTheIdentityAreAllRaised(t *testing.T) {
	for _, route := range []string{
		"POST /api/keystore/root-seed",
		"POST /api/rotation",
		"POST /api/reset",
		"POST /api/recovery/root-aid-rotation",
		"POST /api/recovery/retrieve",
		"PUT /api/recovery/duress-policy",
		"POST /api/controllers",
	} {
		parts := strings.SplitN(route, " ", 2)
		req, raised := theLevelThisActionNeeds(parts[0], parts[1])
		if !raised {
			t.Errorf("%s is reachable by any authorised machine", route)
			continue
		}
		if !req.Level.AtLeast(authprovider.LevelHigh) {
			t.Errorf("%s needs only %q", route, req.Level)
		}
		if req.Why == "" {
			t.Errorf("%s is raised without saying why, so somebody stopped by it "+
				"learns nothing", route)
		}
	}
}

// A controller cannot quietly authorise more controllers at its own level —
// that is how a machine makes its own access outlive the revocation of the one
// the owner knows about.
func TestAuthorisingAnotherMachineIsItselfRaised(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/controllers",
		`{"controller_aid":"ESecond","public_key":"DSecond","label":"another","grade":"enrolled"}`,
		seed, authprovider.LevelAuthenticated, time.Now()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an authorised machine authorised another one without the "+
			"strongest check: %d %s", w.Code, w.Body.String())
	}
}

// What a machine did is attributable to it, not to the owner. An audit trail
// that cannot tell them apart cannot answer what a stolen laptop did.
func TestWhatTheMachineDidIsAttributableToIt(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	var sawLabel string
	var sawAny bool

	// The real middleware, in front of a handler that reports what the context
	// carried. Mounted on its own router so the pattern resolves the same way it
	// does in the agent — the middleware reads the matched route, so a request
	// that matched nothing would prove nothing.
	mini := chi.NewRouter()
	mini.Use(s.authorize(mini))
	mini.Get("/api/profile", func(w http.ResponseWriter, req *http.Request) {
		if g, ok := TheControllerThatAsked(req); ok {
			sawAny, sawLabel = true, g.Label
		}
	})

	mini.ServeHTTP(httptest.NewRecorder(),
		asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}))

	if !sawAny {
		t.Fatal("a request from an authorised machine reached the handler with " +
			"nothing saying which machine it was")
	}
	if sawLabel != "the laptop in the study" {
		t.Fatalf("the machine was recorded as %q", sawLabel)
	}
}

// The two lists must not drift apart.
//
// sessionForbidden already names the actions a browser session may not perform.
// A controller is trusted further, so it is not the same list — but an action
// dangerous enough to be closed to a session is one somebody should have made a
// DECISION about here, rather than left reachable by forgetting.
//
// So every entry there is either raised here, or named below as deliberately
// left at the default. Adding a route to sessionForbidden and not to one of
// those two fails this test, which is the only thing that would catch it.
func TestEveryActionClosedToASessionWasDecidedForAControllerToo(t *testing.T) {
	// Reachable by any authorised machine, on purpose. These are the owner's own
	// decisions about their own machine, or things their front end must be able
	// to show them — a controller that could not do them would not be a front
	// end.
	deliberatelyOrdinary := map[string]string{
		"POST /api/recovery/holdings": "agreeing to hold part of somebody else's recovery " +
			"is this owner's decision about their own machine, and changes nothing about this identity",
		"POST /api/recovery/holdings/approve": "approving somebody else's recovery is a decision " +
			"this owner makes for other people, not a change to their own identity",
		"POST /api/recovery/holdings/stop": "giving up a share somebody else relies on is this " +
			"owner's decision about their own machine",
		"GET /api/recovery/sessions": "the owner's own front end must be able to show them that " +
			"a recovery of their identity is running — that is who the warning is for",
		"GET /api/recovery/sessions/{id}": "the same: this is the owner being told about their own identity",
	}

	for route := range sessionForbidden {
		parts := strings.SplitN(route, " ", 2)
		if len(parts) != 2 {
			t.Errorf("%q is not a METHOD /pattern key", route)
			continue
		}
		if _, raised := theLevelThisActionNeeds(parts[0], parts[1]); raised {
			continue
		}
		if _, deliberate := deliberatelyOrdinary[route]; deliberate {
			continue
		}
		t.Errorf("%s is closed to a browser session but reachable by any authorised "+
			"machine with no extra check. Either raise it in controllerNeedsLevel, or "+
			"name it in this test as deliberately ordinary and say why", route)
	}

	// The reverse: an entry here that no longer names a real route is a rule
	// guarding nothing, and it would sit looking like protection.
	for route := range deliberatelyOrdinary {
		if _, ok := sessionForbidden[route]; !ok {
			t.Errorf("%s is named as deliberately ordinary but is no longer closed to "+
				"a session, so this exemption guards nothing", route)
		}
	}
}

// Being admitted is not being granted capability scopes.
//
// A controller reaches capability routes because it acts for the owner, but it
// carries no capability grant and must not appear to. The near-identical mistake
// has been made here before: a caller was admitted for holding a signature and
// picked up an AI agent's ceiling on the way through.
func TestAnAdmittedMachineCarriesNoCapabilityScopes(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	req := asThatMachine(t, aid, "POST", "/api/capabilities/send.email/invoke", `{}`,
		seed, authprovider.LevelHigh, time.Now())
	if got := s.resolveCaller(req).Scopes; len(got) != 0 {
		t.Fatalf("an authorised machine resolved with scopes %v — it holds no capability "+
			"grant, so anything it reaches must still be decided by the handler", got)
	}
}

// A body larger than a signed request may carry is refused, not truncated.
//
// Truncating would check the signature against the same shortened copy the
// handler then reads, so both would agree and the request would succeed while
// doing something other than what was sent.
func TestAnOversizedBodyIsRefusedRatherThanTruncated(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	big := strings.Repeat("x", int(maxSignedBodyBytes)+64)
	req := asThatMachine(t, aid, "POST", "/api/profile", big, seed, "", time.Time{})

	_, _, err := s.theControllerBehind(req)
	if err == nil {
		t.Fatal("an oversized body was accepted, so the handler reads a truncated " +
			"request that the signature appears to cover")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// The routes that hand out or redirect this identity's archives are raised.
//
// Found by walking the router rather than by reading the list: three doors led
// to the same room and only the one with "recovery" in its name had been raised.
func TestEveryDoorToAnArchiveIsRaised(t *testing.T) {
	for _, route := range []string{
		"POST /api/recovery/retrieve",
		"POST /api/backup/export",
		"POST /api/backup/pull/{destID}",
		"POST /api/sign",
	} {
		parts := strings.SplitN(route, " ", 2)
		req, raised := theLevelThisActionNeeds(parts[0], parts[1])
		if !raised || !req.Level.AtLeast(authprovider.LevelHigh) {
			t.Errorf("%s is reachable without the strongest check (raised=%v level=%q)",
				route, raised, req.Level)
		}
	}
	// Where archives are SENT is raised too — redirecting it is a quiet way to
	// be handed every future copy.
	for _, route := range []string{
		"PUT /api/backup/config",
		"POST /api/backup/destinations",
		"POST /api/backup/credentials",
	} {
		parts := strings.SplitN(route, " ", 2)
		if _, raised := theLevelThisActionNeeds(parts[0], parts[1]); !raised {
			t.Errorf("%s is reachable by any authorised machine", route)
		}
	}
}

// ownerSeedForTest gives the agent a root-identity device whose statements about
// authentication it will accept, and returns that device's seed.
//
// Stored in a package-level map keyed by the test, because a controller request
// is built by a helper that does not otherwise know the owner.
func ownerSeedForTest(t *testing.T, s *CoreServer) []byte {
	t.Helper()
	seed, _ := sealTestOwner(t, s)
	rootDeviceSeeds[t.Name()] = seed
	t.Cleanup(func() { delete(rootDeviceSeeds, t.Name()) })
	return seed
}

var rootDeviceSeeds = map[string][]byte{}

// theRootDeviceVouches is the phone signing "this person reached this level, at
// this moment, for this machine".
func theRootDeviceVouches(t *testing.T, controllerAID string, level authprovider.Level,
	at time.Time, score int) string {
	t.Helper()
	seed, ok := rootDeviceSeeds[t.Name()]
	if !ok {
		return ""
	}
	sig, err := login.SignString(
		canonicalAuthLevelStatement(controllerAID, level, at, score), seed)
	if err != nil {
		t.Fatalf("the root device could not vouch: %v", err)
	}
	return sig
}

// A machine may not score itself.
//
// Rob, 2026-08-31: an authentication level is only worth what the software
// producing it can be held to. If the controller measures the person and reports
// the answer, whoever runs modified software there reports whatever they like,
// and every threshold here becomes a number the attacker chooses — because
// nobody is auditing what build is running on that machine.
func TestAMachineMayNotScoreItself(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	req := asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelHigh, time.Now())
	// Strip what the root-identity device said, leaving the machine's own claim.
	req.Header.Del(headerAuthLevelVouchedBy)
	// Re-sign, so this fails on the missing voucher rather than on the signature.
	stamp := req.Header.Get(headerControllerTimestamp)
	sig, err := login.SignString(canonicalControllerRequest(aid, "POST", "/api/rotation", stamp,
		authprovider.Result{Level: authprovider.LevelHigh, Measured: true,
			At: time.Now().UTC(), Score: 80}, []byte(`{}`)), seed)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerControllerSig, sig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a machine scored itself and was believed: %d %s", w.Code, w.Body.String())
	}
}

// A statement the root device made about ONE machine cannot be relayed by
// another, or an authorised laptop could borrow the level granted to a phone.
func TestOneMachinesLevelCannotBeRelayedByAnother(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	req := asThatMachine(t, aid, "POST", "/api/rotation", `{}`, seed,
		authprovider.LevelHigh, time.Now())
	// A perfectly good statement — about a different machine.
	req.Header.Set(headerAuthLevelVouchedBy,
		theRootDeviceVouches(t, "ESomeOtherMachine", authprovider.LevelHigh, time.Now(), 80))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a level vouched for another machine was accepted here: %d", w.Code)
	}
}

// An agent that knows of no root-identity device cannot be told a level by
// anybody, rather than falling back to believing the machine.
func TestWithNoRootDeviceNobodyCanVouch(t *testing.T) {
	s := newAuthTestServer(t)
	got := s.theAuthenticationSomebodyVouchedFor(func() *http.Request {
		req := remote("POST", "/api/rotation", "")
		req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
		req.Header.Set(headerControllerAuthAt, time.Now().UTC().Format(time.RFC3339))
		req.Header.Set(headerAuthLevelVouchedBy, "AAnythingAtAll")
		return req
	}(), "EAnyMachine", time.Now().UTC())
	if got.Measured {
		t.Fatalf("an agent with no root-identity device accepted a level anyway: %+v", got)
	}
}
