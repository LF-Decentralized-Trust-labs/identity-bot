package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// A computer asks to act for an identity by an Ask like any other: it leaves its signed offer at the
// Identity Agent it asks, shows that Identity Agent's short pointer, and the owner's Identity Agent
// fetches and checks the Ask there. Leaving a request never grants anything.

const anAgentOrigin = "https://agent.example"

// leaveARequest posts an offer to the leave route and returns the status and the answer.
func leaveARequest(t *testing.T, s *CoreServer, offer ControllerOffer, extra map[string]string) (int, map[string]string) {
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
	if p.Counterparty != offer.AID || p.Subtitle != "Acme" {
		t.Fatalf("the preview does not name the computer and organisation: %+v", p)
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
	offer := freshOffer(t, anAgentOrigin)
	_, first := leaveARequest(t, s, offer, nil)
	_, second := leaveARequest(t, s, offer, nil)
	if status, _ := servedAt(s, first["token"]); status != http.StatusNotFound {
		t.Fatalf("the old code still resolves after a new one: %d", status)
	}
	if status, _ := servedAt(s, second["token"]); status != http.StatusOK {
		t.Fatalf("the new code does not resolve: %d", status)
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

// At most so many wait at once, so a stranger cannot fill memory.
func TestHowManyMayWaitIsBounded(t *testing.T) {
	s := &CoreServer{controllerRequestLimiter: newIPRateLimiter(1000, time.Minute)}
	for i := 0; i < maxPendingControllerRequests; i++ {
		if code, out := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil); code != http.StatusOK {
			t.Fatalf("request %d refused below the cap: %d %v", i, code, out)
		}
	}
	if code, _ := leaveARequest(t, s, freshOffer(t, anAgentOrigin), nil); code != http.StatusTooManyRequests {
		t.Fatalf("a request over the cap was held: %d", code)
	}
}

// One caller address is rate limited.
func TestOneCallerIsRateLimited(t *testing.T) {
	s := &CoreServer{}
	offer := freshOffer(t, anAgentOrigin)
	for i := 0; i < controllerRequestsPerCaller; i++ {
		if code, _ := leaveARequest(t, s, offer, nil); code != http.StatusOK {
			t.Fatalf("request %d refused under the limit: %d", i, code)
		}
	}
	if code, _ := leaveARequest(t, s, offer, nil); code != http.StatusTooManyRequests {
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
