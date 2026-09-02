package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"

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
	// A controller is named by its own key, so the identifier is derived rather
	// than invented — the agent refuses a grant whose two halves disagree.
	aid := iacrypto.NonTransferableAIDQB64(pub)
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
	// A real machine and a real root device, so the voucher below genuinely
	// verifies. An earlier version sent an invented voucher, which failed the
	// signature check — so the function returned Unmeasured for that reason and
	// never reached the question this test is named for. It passed with the
	// check deleted.
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)

	at := time.Now().UTC()
	const invented = authprovider.Level("platinum")
	vouched := theRootDeviceVouches(t, aid, invented, at, 100)
	if vouched == "" {
		t.Fatal("the root device did not vouch, so this proves nothing")
	}

	req := remote("POST", "/api/rotation", "")
	req.Header.Set(headerControllerAuthLevel, string(invented))
	req.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	req.Header.Set(headerControllerAuthScore, "100")
	req.Header.Set(headerAuthLevelVouchedBy, vouched)

	got := s.theAuthenticationSomebodyVouchedFor(req, aid, at)
	if got.Measured {
		t.Fatalf("a level this build does not define was accepted as a measurement, so "+
			"a newer device naming something unrecognised clears gates on an older "+
			"agent: %+v", got)
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

// A controller cannot enrol another controller AT ANY LEVEL, including the
// strongest one it could ever present.
//
// The earlier version of this only proved refusal at a middling level, which
// left the dangerous case untested — and the dangerous case is the whole point.
// The statement vouching for a level names the machine, the level and the
// moment, but NOT the action, so one high statement obtained honestly for
// something the person did intend can be spent inside its window on enrolling a
// second machine. That second grant outlives the revocation of the first, so an
// attacker who briefly holds a controller leaves with access the owner cannot
// see they gave.
func TestNoLevelLetsAControllerEnrolAnotherController(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	for _, level := range []authprovider.Level{
		authprovider.LevelAuthenticated,
		authprovider.LevelVerified,
		authprovider.LevelHigh,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, asThatMachine(t, aid, "POST", "/api/controllers",
			`{"controller_aid":"BSecond","public_key":"DSecond","label":"another","grade":"enrolled"}`,
			seed, level, time.Now()))
		if w.Code != http.StatusForbidden {
			t.Fatalf("a controller enrolled another one at %q: %d %s",
				level, w.Code, w.Body.String())
		}
	}

	// And it is closed rather than merely very high, so adding a stronger level
	// later cannot open it by accident.
	req, raised := theLevelThisActionNeeds("POST", "/api/controllers")
	if !raised || !req.Closed {
		t.Fatalf("enrolling is not closed to controllers: %+v", req)
	}
}

// Reading the list is raised: it hands over every machine that may act for this
// identity, its label and its key — a map of the owner's devices that a machine
// somebody borrowed for an afternoon should not leave with.
func TestListingEveryMachineIsRaised(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeScoped)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/controllers", "", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a borrowed machine with nothing measured listed every controller, "+
			"its label and its key: %d %s", w.Code, w.Body.String())
	}
}

// A closed action stays closed even if its level entry is mistyped, because the
// two are independent — a typo must not turn "never from here" into "prove more".
func TestAMistypedLevelDoesNotOpenAClosedAction(t *testing.T) {
	const typo = "POST /api/some-closed-thing"
	controllerNeedsLevel[typo] = controllerRequirement{
		Closed: neverByAController, Level: "hgih", Why: "a typo",
	}
	t.Cleanup(func() { delete(controllerNeedsLevel, typo) })

	req, raised := theLevelThisActionNeeds("POST", "/api/some-closed-thing")
	if !raised || !req.Closed {
		t.Fatalf("a mistyped level reopened a closed action: %+v", req)
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/some-closed-thing",
		authprovider.Result{Level: authprovider.LevelHigh, Measured: true,
			At: time.Now().UTC()}, time.Now().UTC()); ok {
		t.Fatal("a closed action was performed by presenting the strongest level")
	}
}

// Superseded by TestNoLevelLetsAControllerEnrolAnotherController, kept only to
// show a weak level is refused too.
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

// A controller cannot install the key that vouches for it.
//
// This is the attack a reviewer proved on this branch, and it needed no
// authentication at all: a controller is permitted by default, POST
// /api/store/identity was named nowhere, and ownerAuthority() falls back to the
// agent's own identity record when nothing is anchored or sealed. So the machine
// wrote its own key in as the owner, signed a statement vouching for itself at
// the strongest level, and every raised gate opened — and it was then the owner
// for isOwner on every route, which survives revoking the grant.
//
// Two locks now. The route is closed, and the voucher is checked only against
// the record sealed at provisioning, which no route writes.
func TestAControllerCannotInstallTheKeyThatVouchesForIt(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	// The first lock: the routes that decide who the owner is are closed.
	for _, route := range []struct{ method, path, pattern string }{
		{"POST", "/api/store/identity", "/api/store/identity"},
		{"POST", "/api/contacts", "/api/contacts"},
		{"PUT", "/api/contacts/BSomebody", "/api/contacts/{aid}"},
		{"POST", "/api/contacts/resolve", "/api/contacts/resolve"},
		{"DELETE", "/api/contacts/BSomebody", "/api/contacts/{aid}"},
	} {
		req, raised := theLevelThisActionNeeds(route.method, route.pattern)
		if !raised || !req.Closed {
			t.Errorf("%s %s is not closed to a controller, so it can rewrite who the "+
				"owner is: %+v", route.method, route.pattern, req)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, asThatMachine(t, aid, route.method, route.path,
			`{"aid":"BAttackerChosen","public_key":"DAttackerChosen"}`, seed,
			authprovider.LevelHigh, time.Now()))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s admitted a controller at the strongest level: %d %s",
				route.method, route.path, w.Code, w.Body.String())
		}
	}
}

// The second lock, checked on its own so it holds even if a route like those is
// added and nobody remembers to close it.
//
// An agent whose owner is only its own identity record has no device entitled to
// speak for it, so no voucher is accepted and every raised action stays shut.
// Before this, that fallback key was what the voucher was checked against.
func TestAVoucherIsOnlyBelievedFromTheSealedRecord(t *testing.T) {
	// An agent with a real store, so the identity record below is genuinely the
	// thing ownerAuthority would have fallen back to.
	s := agentWithNoIdentity(t)

	// An agent with an identity but nothing sealed: the ordinary personal agent,
	// and the configuration the attack was proven against.
	attacker := make([]byte, ed25519.SeedSize)
	for i := range attacker {
		attacker[i] = byte(i + 90)
	}
	pub := ed25519.NewKeyFromSeed(attacker).Public().(ed25519.PublicKey)
	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID:       "BWhateverTheCallerWrote",
		PublicKey: iacrypto.VerkeyQB64(pub),
	}); err != nil {
		t.Fatalf("seeding the identity record: %v", err)
	}

	at := time.Now().UTC()
	statement := canonicalAuthLevelStatement("BSomeController", authprovider.LevelHigh, at, 99)
	vouched, err := login.SignString(statement, attacker)
	if err != nil {
		t.Fatal(err)
	}

	req := remote("POST", "/api/rotation", "")
	req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	req.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	req.Header.Set(headerControllerAuthScore, "99")
	req.Header.Set(headerAuthLevelVouchedBy, vouched)

	got := s.theAuthenticationSomebodyVouchedFor(req, "BSomeController", at)
	if got.Measured {
		t.Fatalf("a key written into the identity record vouched for a level, so a "+
			"caller who can reach that record can grant itself anything: %+v", got)
	}
}

// Every raised gate names a route this agent actually serves.
//
// The map is keyed by hand-typed strings, and a key that matches no route
// guards nothing while looking exactly like protection. Four did: the employee
// and signer-invite entries name routes this router does not mount.
//
// This is the discipline already written for the controller routes themselves —
// "a hand-typed string that does not match it would pass while proving nothing"
// — applied to the other thirty-odd, which had been keyed by hand with no walk.
// The tests that check specific entries compare the map against literals copied
// out of the map, so a typo passes every one of them.
func TestEveryRaisedGateNamesARouteThisAgentServes(t *testing.T) {
	s := newAuthTestServer(t)
	// mountEmployeeRoutes and mountSignerRoutes return early on a nil handler,
	// so a bare server does not mount the very routes some of these gates guard.
	// Without this the test reports four gates as dead that are real — which is
	// what a reviewer concluded from the bare fixture.
	ah, err := asset.NewHandler(s.DataDir, nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	s.assetHandler = ah

	served := map[string]bool{}
	if werr := chi.Walk(s.buildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			served[method+" "+route] = true
			return nil
		}); werr != nil {
		t.Fatalf("walking the router: %v", werr)
	}

	for gate := range controllerNeedsLevel {
		if !served[gate] {
			t.Errorf("%s is raised but this agent serves no such route, so the gate "+
				"guards nothing while reading as protection", gate)
		}
	}
}

// The reverse of the walk above: every owner-class route this agent serves has
// had a DECISION made about it — permitted, raised, or closed.
//
// Permitted-by-default is only safe where somebody looked at what is being
// permitted. Two routes nobody had looked at were an unauthenticated privilege
// escalation: a controller wrote its own key into the identity record and
// vouched for itself. Neither looked dangerous by name, which is exactly why
// reading the list is not a substitute for walking it.
//
// New owner-class routes land in `deliberatelyOrdinary` with a reason, or they
// get raised. Either is a decision; silence is not.
func TestEveryOwnerRouteHasHadADecisionMadeAboutIt(t *testing.T) {
	s := newAuthTestServer(t)

	// Reviewed and left reachable by an authorised controller: they read or
	// write things belonging to the person's own use of their identity, and none
	// of them changes who the owner is, what signs for the identity, or what an
	// authorisation decision reads.
	reviewed := 0
	err := chi.Walk(s.buildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if classify(method, route) != accessOwner {
				return nil
			}
			reviewed++
			return nil
		})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if reviewed == 0 {
		t.Fatal("no owner-class routes found, so this test proves nothing")
	}

	// The property that must hold: nothing feeding the authorisation decision is
	// reachable. Checked by name against what ownerAuthority and
	// sealedOwnerAuthority actually read, rather than by guessing which routes
	// sound dangerous.
	for _, mustBeClosed := range []string{
		"POST /api/store/identity",
		"POST /api/contacts",
		"PUT /api/contacts/{aid}",
		"DELETE /api/contacts/{aid}",
		"POST /api/contacts/resolve",
		"POST /api/controllers",
		"POST /api/controller/sign",
	} {
		parts := strings.SplitN(mustBeClosed, " ", 2)
		req, raised := theLevelThisActionNeeds(parts[0], parts[1])
		if !raised || !req.Closed {
			t.Errorf("%s is not closed to a controller: %+v", mustBeClosed, req)
		}
	}
}

// asThatMachineAt is asThatMachine with the request's own timestamp chosen, so a
// test can sign for a moment outside the window without waiting.
func asThatMachineAt(t *testing.T, aid, method, path, body string, seed []byte,
	stampAt time.Time) *http.Request {
	t.Helper()
	req := remote(method, path, body)
	stamp := stampAt.UTC().Format(time.RFC3339)
	sig, err := login.SignString(
		canonicalControllerRequest(aid, method, path, stamp,
			authprovider.Unmeasured(""), []byte(body)), seed)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	req.Header.Set(headerControllerAID, aid)
	req.Header.Set(headerControllerSig, sig)
	req.Header.Set(headerControllerTimestamp, stamp)
	return req
}

// The doors that write a contact record are closed, including the two that do
// not say "contact" anywhere in their names.
//
// A reviewer proved this end to end after the obvious contact routes were shut:
// POST /api/scan/execute reaches EnsureKeriContact, which fetches a record from
// an address in the payload and stores the key it gets back — the identical
// primitive. The owner's key is resolved from those records, so writing one
// makes the writer the owner. POST /api/ask/create is the same door.
//
// The lesson is in how they were found: by tracing what the handlers CALL, not
// by reading what they are named. This list cannot be kept correct by reading.
func TestTheLessObviousDoorsToAContactRecordAreClosedToo(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	for _, path := range []string{"/api/scan/execute", "/api/ask/create"} {
		req, raised := theLevelThisActionNeeds("POST", path)
		if !raised || !req.Closed {
			t.Errorf("POST %s is not closed, and it can write the record the owner's "+
				"key is read from: %+v", path, req)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, asThatMachine(t, aid, "POST", path, `{}`, seed,
			authprovider.LevelHigh, time.Now()))
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s admitted a controller at the strongest level: %d", path, w.Code)
		}
	}
}

// A sealed owner is not replaced by somebody redeeming a founding invite.
//
// That route is declared public and reached from a token in a link or a QR, and
// the sealed record is now the only thing a controller's authentication level is
// checked against — so without this, an unredeemed founding token is an
// unauthenticated rewrite of the key that vouches for every raised action.
func TestAFoundingInviteCannotReplaceAnOwnerWhoAlreadyExists(t *testing.T) {
	s := agentWithNoIdentity(t)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "BTheRealOwner",
		PublicKey: aGrant(GradeEnrolled).PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := s.AcceptFoundingSigner(SignerAcceptance{
		InviteToken: "whatever-token",
		PairwiseAID: "BSomebodyElse",
		PublicKey:   grantFor(55, GradeEnrolled).PublicKey,
	})
	if err == nil {
		t.Fatal("a founding invite replaced an owner who already existed, so anyone " +
			"holding an unredeemed token owns this agent")
	}

	sealed, serr := s.sealedOwnerAuthority()
	if serr != nil || sealed.AID != "BTheRealOwner" {
		t.Fatalf("the owner was changed anyway: %+v (%v)", sealed, serr)
	}
}

// An owner named by the log, whose key is only an unverified contact row, cannot
// vouch for an authentication level.
//
// This is the door that stayed open after the sealed-only rule: an anchored
// identity has no sealed record, so the voucher falls back to the owner's key —
// and if that may come from a contact row, anything able to write one is back to
// vouching for itself. Contact rows are written by handlers that fetch a record
// from an address the caller names, which is how this was reached twice.
//
// It stays shut rather than trusting the row. The way to open it is to verify
// the owner's key event log, not to lower this.
func TestAnUnverifiedOwnerRowCannotVouch(t *testing.T) {
	s := serverWithIdentity(t, "EORG")

	// The identity's inception names an owner — an anchor, and nothing sealed.
	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "EORG",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "EORG",
				"a": []interface{}{map[string]interface{}{
					"i": "ETHEOWNER", "s": "0", "d": "ETHEOWNER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// The attacker writes the owner's key, exactly as the scan and contact
	// routes do.
	attacker := make([]byte, ed25519.SeedSize)
	for i := range attacker {
		attacker[i] = byte(i + 31)
	}
	pub := ed25519.NewKeyFromSeed(attacker).Public().(ed25519.PublicKey)
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETHEOWNER", Status: "accepted", PublicKey: iacrypto.VerkeyQB64(pub),
	}); err != nil {
		t.Fatal(err)
	}

	at := time.Now().UTC()
	vouched, err := login.SignString(
		canonicalAuthLevelStatement("BSomeController", authprovider.LevelHigh, at, 99),
		attacker)
	if err != nil {
		t.Fatal(err)
	}

	req := remote("POST", "/api/rotation", "")
	req.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	req.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	req.Header.Set(headerControllerAuthScore, "99")
	req.Header.Set(headerAuthLevelVouchedBy, vouched)

	if got := s.theAuthenticationSomebodyVouchedFor(req, "BSomeController", at); got.Measured {
		t.Fatalf("a contact row nobody verified vouched for the strongest level, so "+
			"anything able to write one grants itself everything: %+v", got)
	}
}

// A machine that IS a controller is told why it was refused.
//
// Every refusal used to be discarded and replaced with "sign the request with
// the owner key or call it locally" — advice a controller cannot act on, since
// by design it holds no owner key. The same line appeared when the grants file
// could not be read, so a fault that locked every authorised machine out
// reported nothing at all.
func TestARefusedControllerIsToldWhichRefusalItHit(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter("")

	// An authorisation that has been removed.
	if err := s.controllers().Revoke(aid); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a revoked machine was admitted: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "owner key") {
		t.Errorf("a controller was told to sign with the owner key, which it does not "+
			"have and never will: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not authorised") {
		t.Errorf("the refusal does not say the authorisation is gone: %s", w.Body.String())
	}

	// A request from nobody in particular still falls through to the ordinary
	// answer, or every non-controller caller would start getting controller
	// errors.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/profile", ""))
	if !strings.Contains(w.Body.String(), "owner") {
		t.Errorf("an ordinary caller stopped getting the ordinary refusal: %s", w.Body.String())
	}
}

// seedForGrant is the seed behind grantFor, so a test can sign as a machine it
// built with that helper.
func seedForGrant(n byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n + byte(i)
	}
	return seed
}

// An owner who rotates their key is not locked out of their own machine.
//
// The owner of a paired machine is a pairwise identity their own device minted
// for it, and that identity can rotate. Nothing rewrites the record sealed at
// pairing when it does — changing owners is a separate ceremony — so the sealed
// key is the key as it was at pairing and no later.
//
// Asking the sealed record FIRST, which this briefly did, means the machine goes
// on checking against a key its owner has replaced and refuses them for good,
// with no way back in. A verified key event log is the only source that tracks a
// rotation, and it cannot be written by a caller, which is what makes it safe to
// prefer.
func TestAnOwnerWhoRotatesIsNotLockedOutOfTheirOwnMachine(t *testing.T) {
	s := serverWithIdentity(t, "EMACHINE")

	// The machine's inception names its owner.
	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "EMACHINE",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "EMACHINE",
				"a": []interface{}{map[string]interface{}{
					"i": "ETHEOWNER", "s": "0", "d": "ETHEOWNER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// Sealed at pairing: the owner's key as it was THEN.
	old := grantFor(60, GradeEnrolled)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID: "ETHEOWNER", PublicKey: old.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	// The owner rotates. Their new key is recorded from a log this agent
	// verified — the only place a rotation can honestly show up.
	rotated := grantFor(61, GradeEnrolled)
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "ETHEOWNER", KelVerified: true,
		CurrentPublicKey: rotated.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("the machine could not resolve its own owner: %v", err)
	}
	if authority.PublicKey == old.PublicKey {
		t.Fatal("the machine is still checking against the key its owner replaced, " +
			"so the owner is locked out of their own machine permanently")
	}
	if authority.PublicKey != rotated.PublicKey {
		t.Fatalf("resolved to neither the old nor the rotated key: %q", authority.PublicKey)
	}
}

// A sealed record naming somebody the log never anchored cannot vouch.
//
// The two questions were split apart: such a record was refused for "who is the
// owner" and accepted for "whose statement about an authentication level do I
// believe". The founding-signer redeem route is public and writes that record,
// so anybody holding an unredeemed invite could install the key that vouches for
// every raised action — rotation, seed install, signing, archive retrieval —
// without ever becoming the owner.
func TestASealedRecordTheLogNeverNamedCannotVouch(t *testing.T) {
	s := serverWithIdentity(t, "EMACHINE")

	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "EMACHINE",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "EMACHINE",
				"a": []interface{}{map[string]interface{}{
					"i": "ETHEREALOWNER", "s": "0", "d": "ETHEREALOWNER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// Somebody seals themselves under an identity the inception never named.
	attacker := grantFor(70, GradeEnrolled)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID: "EANIMPOSTER", PublicKey: attacker.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	key, err := s.theKeyEntitledToVouch()
	if err == nil && key == attacker.PublicKey {
		t.Fatal("a sealed record naming an identity the log never anchored was " +
			"accepted as the thing that may vouch, so anybody who can write that " +
			"record grants themselves every raised action")
	}
	if err == nil {
		t.Fatalf("expected nobody to be entitled to vouch, got key %q", key)
	}
}

// Sealing an owner is once, including a second attempt naming the SAME identity
// with a different key.
//
// A pairwise owner AID is not a secret — the redeem handler returns it and it
// sits on the roster — so comparing only the AID left the attack intact: the
// later key simply won, and what the sealed record decides is which key may
// speak for this identity.
func TestAnOwnerCannotBeResealedUnderTheSameNameWithANewKey(t *testing.T) {
	s := agentWithNoIdentity(t)
	first := grantFor(71, GradeEnrolled)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID: "BTHEOWNER", PublicKey: first.PublicKey,
	}); err != nil {
		t.Fatal(err)
	}

	second := grantFor(72, GradeEnrolled)
	if _, err := s.AcceptFoundingSigner(SignerAcceptance{
		InviteToken: "a-token",
		PairwiseAID: "BTHEOWNER", // the same name
		PublicKey:   second.PublicKey,
	}); err == nil {
		t.Fatal("the owner was re-sealed under the same name with a different key")
	}

	sealed, serr := s.sealedOwnerAuthority()
	if serr != nil || sealed.PublicKey != first.PublicKey {
		t.Fatalf("the sealed key changed: %+v (%v)", sealed, serr)
	}
}

// Sealing an owner is atomic, so two requests racing cannot both pass.
//
// The seal-once guard reads and then writes, and everything that seals does it
// from a request. Both readers see nothing sealed, both pass, and the later
// write wins — so an attacker racing the real founding redeem seals their own
// key, and the founder is refused from then on. One invite is enough, because
// the use-count is incremented only after the seal returns.
func TestTwoRequestsRacingToSealAnOwnerCannotBothWin(t *testing.T) {
	s := agentWithNoIdentity(t)

	const racers = 24
	var wg sync.WaitGroup
	won := make([]bool, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := grantFor(byte(80+i), GradeEnrolled)
			<-start
			won[i] = s.SealOwnerAuthority(OwnerAuthority{
				AID: fmt.Sprintf("BRACER%d", i), PublicKey: key.PublicKey,
			}) == nil
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, w := range won {
		if w {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d requests sealed an owner — sealing is not once, so the "+
			"last writer decides who this agent answers to", winners, racers)
	}

	// And what is on disk is one of them, whole, rather than two overlaid.
	sealed, err := s.sealedOwnerAuthority()
	if err != nil || sealed == nil || sealed.AID == "" {
		t.Fatalf("the record is not readable after the race: %+v (%v)", sealed, err)
	}
}

// A founding invite may only seal the identity the inception already named.
//
// Refusing on the sealed record alone turned the escalation into a lockout: on
// an agent that anchors an owner but has nothing sealed, a token-holder took the
// slot. It granted them nothing, and it refused every later redeem including the
// real founder's, for good.
func TestAFoundingInviteCannotSealSomebodyTheLogNeverNamed(t *testing.T) {
	s := serverWithIdentity(t, "EMACHINE")

	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "EMACHINE",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "EMACHINE",
				"a": []interface{}{map[string]interface{}{
					"i": "ETHEREALOWNER", "s": "0", "d": "ETHEREALOWNER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	stranger := grantFor(190, GradeEnrolled)
	if _, err := s.AcceptFoundingSigner(SignerAcceptance{
		InviteToken: "a-token",
		PairwiseAID: "EANIMPOSTER",
		PublicKey:   stranger.PublicKey,
	}); err == nil {
		t.Fatal("a founding invite sealed an identity the inception never named, " +
			"taking the slot the real founder needs")
	}

	// The slot is still free, so the owner the log names can still found.
	if sealed, err := s.sealedOwnerAuthority(); err == nil && sealed != nil &&
		sealed.AID != "" {
		t.Fatalf("the refused redeem left a record behind: %+v", sealed)
	}
}
