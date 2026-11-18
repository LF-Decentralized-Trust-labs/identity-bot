package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/testkeys"
)

// A computer asks to act for an identity by an Ask like any other: it leaves its signed offer at the
// Identity Agent it asks, shows that Identity Agent's short pointer, and the owner's Identity Agent
// fetches and checks the Ask there. Leaving a request never grants anything.

const anAgentOrigin = "https://agent.example"

// leaveARequest posts an offer to the leave route and returns the status and the answer.
func leaveARequest(t *testing.T, s *CoreServer, offer ControllerOffer, extra map[string]string) (int, map[string]string) {
	t.Helper()
	return leaveARequestFrom(t, s, "192.0.2.1:1234", offer, extra)
}

// leaveARequestFrom is leaveARequest from a given caller address.
func leaveARequestFrom(t *testing.T, s *CoreServer, from string, offer ControllerOffer, extra map[string]string) (int, map[string]string) {
	t.Helper()
	body := map[string]string{
		"aid": offer.AID, "public_key": offer.PublicKey, "protected_by": offer.ProtectedBy,
		"agent_origin": offer.AgentOrigin, "timestamp": offer.Timestamp, "signature": offer.Signature,
	}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/controller/requests", strings.NewReader(string(b)))
	req.RemoteAddr = from
	w := httptest.NewRecorder()
	s.handleLeaveAControllerRequest(w, req)
	out := map[string]string{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// servedAt fetches /i/{token} the way a scanning Identity Agent does.
func servedAt(s *CoreServer, token string) (int, []byte) {
	req := httptest.NewRequest("GET", "/i/"+token, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("token", token)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	s.handleChallengeBundleServe(w, req)
	return w.Code, w.Body.Bytes()
}

// offerSignedBy is an offer signed at a given moment by a given computer's key.
func offerSignedBy(t *testing.T, key *testkeys.Key, agent string, at time.Time) ControllerOffer {
	t.Helper()
	pub := key.Compressed()
	verkey, err := iacrypto.MachineVerkeyForKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := iacrypto.MachineAIDForKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ts := at.UTC().Format(time.RFC3339)
	raw, err := key.Sign([]byte(canonicalControllerOffer(verkey, agent, ts)))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := iacrypto.MachineSignatureQB64(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	return ControllerOffer{AID: aid, PublicKey: verkey, ProtectedBy: "test enclave",
		AgentOrigin: agent, Timestamp: ts, Signature: sig}
}

func freshOffer(t *testing.T, agent string) ControllerOffer {
	t.Helper()
	offer, _ := aSignedOffer(t, agent, time.Now().UTC().Format(time.RFC3339))
	return offer
}

// The whole point of the change: the code a computer shows is a bare pointer, short enough to scan
// easily, where the self-contained offer was about 330 characters.
func TestTheCodeAComputerShowsIsAShortPointer(t *testing.T) {
	s := &CoreServer{}
	code, out := leaveARequest(t, s, freshOffer(t, anAgentOrigin), map[string]string{"label": "Study laptop"})
	if code != http.StatusOK {
		t.Fatalf("a fresh signed offer was not taken: %d %v", code, out)
	}
	ptr := out["url"]
	if !strings.HasPrefix(ptr, anAgentOrigin+"/i/") {
		t.Fatalf("the pointer is not the Identity Agent's own: %q", ptr)
	}
	if len(ptr) >= 60 {
		t.Fatalf("the pointer is %d characters (%q); it must be well under 60", len(ptr), ptr)
	}
	if len(out["token"]) != 22 {
		t.Fatalf("the token is not 128 bits of base64url: %q", out["token"])
	}
	exp, err := time.Parse(time.RFC3339, out["expires_at"])
	if err != nil || time.Until(exp) > controllerOfferWindow || time.Until(exp) <= 0 {
		t.Fatalf("the code does not expire with the offer: %q", out["expires_at"])
	}
}

// The owner's Identity Agent fetches the Ask, and it checks the computer's signature exactly as the
// self-contained offer did.
func TestTheAskAtThePointerIsTheComputersSignedOffer(t *testing.T) {
	s := &CoreServer{}
	offer := freshOffer(t, anAgentOrigin)
	_, out := leaveARequest(t, s, offer, map[string]string{"org_name": "Acme"})
	status, ask := servedAt(s, out["token"])
	if status != http.StatusOK {
		t.Fatalf("the pointer did not resolve: %d", status)
	}
	if typ, _ := askActionType(ask); typ != ActionActForIdentity {
		t.Fatalf("the Ask is not action %d: %d", ActionActForIdentity, typ)
	}
	if err := s.verifyAskSignature(ask); err != nil {
		t.Fatalf("the base layer refused a self-verifying Ask: %v", err)
	}
	if err := askExpiryFresh(ask, time.Now()); err != nil {
		t.Fatalf("a fresh request reads as expired: %v", err)
	}
	p, err := (actForIdentityAsk{}).Preview(s, AskContext{Base: anAgentOrigin, AskBytes: ask, T: ActionActForIdentity})
	if err != nil {
		t.Fatalf("a genuine request was refused: %v", err)
	}
	// The subtitle is the origin the computer signed; the organisation name is its own unsigned word, so
	// it is shown only as what it says.
	if p.Counterparty != offer.AID || p.Subtitle != anAgentOrigin {
		t.Fatalf("the preview does not name the computer and its Identity Agent: %+v", p)
	}
	saysAcme := false
	for _, d := range p.Details {
		if d.Value == "Acme" && strings.HasPrefix(d.Label, "It says") {
			saysAcme = true
		}
	}
	if !saysAcme {
		t.Fatalf("the organisation name is not shown as the computer's own word: %+v", p.Details)
	}
}

// A request cannot become a grant without the owner's signature. Leaving it, fetching it, previewing it
// and approving it on the scan gate record nothing; the grant route refuses anybody but the owner.
func TestARequestNeverBecomesAGrantWithoutTheOwner(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerSeedForTest(t, s)
	r := s.buildRouter()

	offer := freshOffer(t, anAgentOrigin)
	b, _ := json.Marshal(map[string]string{
		"aid": offer.AID, "public_key": offer.PublicKey, "agent_origin": offer.AgentOrigin,
		"timestamp": offer.Timestamp, "signature": offer.Signature,
	})
	// A stranger may leave one: the public route is reachable with no credentials.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("POST", "/api/controller/requests", string(b)))
	if w.Code != http.StatusOK {
		t.Fatalf("a computer with no standing could not ask: %d %s", w.Code, w.Body.String())
	}
	var left map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &left)

	// It is served by token, publicly.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/i/"+left["token"], ""))
	if w.Code != http.StatusOK {
		t.Fatalf("the pointer did not resolve through the router: %d", w.Code)
	}
	ask := w.Body.Bytes()

	// Approved on the scan gate: the answer says nothing was granted, and nothing was.
	res, err := (actForIdentityAsk{}).Execute(s, AskContext{Base: anAgentOrigin, AskBytes: ask, T: ActionActForIdentity},
		ScanDecision{Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	if res["granted"] != false {
		t.Fatalf("approving on the scan gate claimed a grant: %v", res)
	}
	if all, err := s.controllers().All(); err != nil || len(all) != 0 {
		t.Fatalf("a request became a grant without the owner: %v %v", all, err)
	}

	// The stranger who left it cannot grant it either.
	gb, _ := json.Marshal(map[string]string{
		"controller_aid": offer.AID, "public_key": offer.PublicKey, "label": "x", "grade": "enrolled",
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, remote("POST", "/api/controllers", string(gb)))
	if w.Code == http.StatusOK {
		t.Fatalf("a stranger granted a machine: %s", w.Body.String())
	}
	if all, _ := s.controllers().All(); len(all) != 0 {
		t.Fatalf("a stranger's grant was recorded: %v", all)
	}
}

// The owner's grant retires the code, so the token is used once.
func TestTheOwnersGrantRetiresTheCode(t *testing.T) {
	s, _ := grantWorld(t)
	r := s.buildRouter()
	offer := freshOffer(t, anAgentOrigin)
	_, out := leaveARequest(t, s, offer, nil)
	if status, _ := servedAt(s, out["token"]); status != http.StatusOK {
		t.Fatalf("the code did not resolve before the grant: %d", status)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, local("POST", "/api/controllers",
		`{"controller_aid":"`+offer.AID+`","public_key":"`+offer.PublicKey+
			`","label":"the laptop in the study","grade":"enrolled"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("the owner could not grant: %d %s", w.Code, w.Body.String())
	}
	if status, _ := servedAt(s, out["token"]); status != http.StatusNotFound {
		t.Fatalf("a granted machine's code still resolves: %d", status)
	}
}

// A new code from the same computer makes the old one stop working.
func TestANewCodeReplacesTheOld(t *testing.T) {
	s := &CoreServer{}
	key, err := testkeys.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, first := leaveARequest(t, s, offerSignedBy(t, key, anAgentOrigin, now.Add(-time.Second)), nil)
	code, second := leaveARequest(t, s, offerSignedBy(t, key, anAgentOrigin, now), nil)
	if code != http.StatusOK {
		t.Fatalf("a newer offer from the same computer was refused: %d %v", code, second)
	}
	if status, _ := servedAt(s, first["token"]); status != http.StatusNotFound {
		t.Fatalf("the old code still resolves after a new one: %d", status)
	}
	if status, _ := servedAt(s, second["token"]); status != http.StatusOK {
		t.Fatalf("the new code does not resolve: %d", status)
	}
}

// Anybody holding the pointer can fetch the offer behind it. Posting it again must not make the code on
// the computer's screen stop working, nor may an older offer from the same computer.
func TestAReplayedOfferDoesNotKillTheCodeOnScreen(t *testing.T) {
	s := &CoreServer{}
	key, err := testkeys.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	offer := offerSignedBy(t, key, anAgentOrigin, now)
	_, shown := leaveARequest(t, s, offer, nil)
	if code, _ := leaveARequest(t, s, offer, nil); code != http.StatusConflict {
		t.Fatalf("the same offer posted again was not refused: %d", code)
	}
	if code, _ := leaveARequest(t, s, offerSignedBy(t, key, anAgentOrigin, now.Add(-time.Minute)), nil); code != http.StatusConflict {
		t.Fatalf("an older offer from the same computer was not refused: %d", code)
	}
	if status, _ := servedAt(s, shown["token"]); status != http.StatusOK {
		t.Fatalf("a replay made the code on screen stop working: %d", status)
	}
}

// Nothing that does not verify is held, and an expired code is not served.
func TestOnlyAFreshGenuineOfferIsHeld(t *testing.T) {
	s := &CoreServer{}
	stale, _ := aSignedOffer(t, anAgentOrigin, time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339))
	if code, _ := leaveARequest(t, s, stale, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("a stale offer was held: %d", code)
	}
	forged := freshOffer(t, anAgentOrigin)
	forged.AgentOrigin = "https://someone-else.example"
	if code, _ := leaveARequest(t, s, forged, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("an offer repointed after signing was held: %d", code)
	}
	if code, _ := leaveARequest(t, s, freshOffer(t, anAgentOrigin), map[string]string{"label": "a\nb"}); code != http.StatusBadRequest {
		t.Fatalf("a label that cannot be shown was held: %d", code)
	}

	// An expired one is dropped when it is asked for.
	offer := freshOffer(t, anAgentOrigin)
	_, out := leaveARequest(t, s, offer, nil)
	s.controllerRequestMu.Lock()
	s.controllerRequests[out["token"]].expires = time.Now().Add(-time.Second)
	s.controllerRequestMu.Unlock()
	if status, _ := servedAt(s, out["token"]); status != http.StatusNotFound {
		t.Fatalf("an expired code was served: %d", status)
	}
}

// One caller may have only a few waiting, and so many wait in all, so a stranger cannot hold every place.
func TestHowManyMayWaitIsBounded(t *testing.T) {
	s := &CoreServer{controllerRequestLimiter: newIPRateLimiter(100000, time.Minute)}
	for i := 0; i < maxPendingPerCaller; i++ {
		if code, out := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil); code != http.StatusOK {
			t.Fatalf("request %d refused below the caller's limit: %d %v", i, code, out)
		}
	}
	if code, _ := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil); code != http.StatusTooManyRequests {
		t.Fatalf("one caller held more than %d: %d", maxPendingPerCaller, code)
	}

	s = &CoreServer{controllerRequestLimiter: newIPRateLimiter(100000, time.Minute)}
	for i := 0; i < maxPendingControllerRequests; i++ {
		from := fmt.Sprintf("198.51.100.%d:1", i/maxPendingPerCaller)
		if i/maxPendingPerCaller > 255 {
			from = fmt.Sprintf("203.0.113.%d:1", i/maxPendingPerCaller-256)
		}
		if code, out := leaveARequestFrom(t, s, from, freshOffer(t, anAgentOrigin), nil); code != http.StatusOK {
			t.Fatalf("request %d refused below the cap: %d %v", i, code, out)
		}
	}
	if code, _ := leaveARequestFrom(t, s, "203.0.113.250:1", freshOffer(t, anAgentOrigin), nil); code != http.StatusTooManyRequests {
		t.Fatalf("a request over the cap was held: %d", code)
	}
}

// A future-dated offer buys no longer life, and the offer behind a used code cannot be posted again for a
// new one.
func TestAFutureOfferGainsNoLifeAndAUsedOfferIsNotReused(t *testing.T) {
	s := &CoreServer{}
	key, err := testkeys.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ahead := offerSignedBy(t, key, anAgentOrigin, now.Add(4*time.Minute))
	_, out := leaveARequest(t, s, ahead, nil)
	exp, err := time.Parse(time.RFC3339, out["expires_at"])
	if err != nil || exp.After(now.Add(controllerOfferWindow+2*time.Second)) {
		t.Fatalf("a future-dated offer was given longer than the window: %q", out["expires_at"])
	}

	s.retireControllerRequestsFor(ahead.AID)
	if code, _ := leaveARequest(t, s, ahead, nil); code != http.StatusConflict {
		t.Fatalf("the offer behind a used code was taken again: %d", code)
	}
}

// One caller address is rate limited.
func TestOneCallerIsRateLimited(t *testing.T) {
	s := &CoreServer{}
	for i := 0; i < controllerRequestsPerCaller; i++ {
		offer := freshOffer(t, anAgentOrigin)
		if code, _ := leaveARequest(t, s, offer, nil); code != http.StatusOK {
			t.Fatalf("request %d refused under the limit: %d", i, code)
		}
		// Granted at once, so what is counted is the rate and not how many are waiting.
		s.retireControllerRequestsFor(offer.AID)
	}
	if code, _ := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil); code != http.StatusTooManyRequests {
		t.Fatalf("a caller over the limit was not refused: %d", code)
	}
}

// The owner's device refuses a genuine request served from somewhere other than the Identity Agent it
// names, and an unsigned expiry that would lengthen the window.
func TestTheOwnersDeviceRefusesARequestFromTheWrongPlaceOrStretched(t *testing.T) {
	s := &CoreServer{}
	_, out := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil)
	_, ask := servedAt(s, out["token"])
	if _, err := (actForIdentityAsk{}).Preview(s, AskContext{Base: "https://elsewhere.example", AskBytes: ask}); err == nil {
		t.Fatal("a request served by another Identity Agent was shown")
	}

	var m map[string]interface{}
	_ = json.Unmarshal(ask, &m)
	m["expiry"] = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	stretched, _ := json.Marshal(m)
	if _, err := (actForIdentityAsk{}).Preview(s, AskContext{Base: anAgentOrigin, AskBytes: stretched}); err == nil {
		t.Fatal("an expiry past the offer's window was believed")
	}

	m["expiry"] = out["expires_at"]
	m["signature"] = "0B" + strings.Repeat("A", 86)
	forged, _ := json.Marshal(m)
	if _, err := (actForIdentityAsk{}).Preview(s, AskContext{Base: anAgentOrigin, AskBytes: forged}); err == nil {
		t.Fatal("a request whose signature does not verify was shown")
	}
}

// The person chooses keep or borrow on the same screen as the approval, and the choice comes back with
// the machine for the grant to carry. A request with no expiry was not made by an Identity Agent that
// holds one, and is refused.
func TestTheChoiceComesBackWithTheMachineAndAnExpiryIsRequired(t *testing.T) {
	s := &CoreServer{}
	_, out := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil)
	_, ask := servedAt(s, out["token"])
	ctx := AskContext{Base: anAgentOrigin, AskBytes: ask, T: ActionActForIdentity}

	p, err := (actForIdentityAsk{}).Preview(s, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.DefaultTier != string(GradeScoped) || len(p.TierOptions) != 2 {
		t.Fatalf("the preview does not offer keep or borrow, borrow first: %+v", p)
	}
	for tier, want := range map[string]string{"": "scoped", "scoped": "scoped", "enrolled": "enrolled"} {
		res, err := (actForIdentityAsk{}).Execute(s, ctx, ScanDecision{Approved: true, Tier: tier})
		if err != nil {
			t.Fatal(err)
		}
		if got := res["machine"].(map[string]string)["grade"]; got != want {
			t.Fatalf("tier %q came back as %q, want %q", tier, got, want)
		}
	}
	if _, err := (actForIdentityAsk{}).Execute(s, ctx, ScanDecision{Approved: true, Tier: "forever"}); err == nil {
		t.Fatal("a grade that is neither was handed back")
	}

	var m map[string]interface{}
	_ = json.Unmarshal(ask, &m)
	delete(m, "expiry")
	bare, _ := json.Marshal(m)
	if _, err := (actForIdentityAsk{}).Preview(s, AskContext{Base: anAgentOrigin, AskBytes: bare}); err == nil {
		t.Fatal("a request with no expiry was shown")
	}
}
