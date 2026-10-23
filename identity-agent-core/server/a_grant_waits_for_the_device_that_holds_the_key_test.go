package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/sandbox"
	"identity-agent-core/store"
)

// keyElsewhere is an Identity Agent whose identity's key is held on another
// device: it publishes the same key, and can no longer derive it. The seed
// returned is that other device's.
func keyElsewhere(t *testing.T) (*CoreServer, []byte, *asset.Asset) {
	t.Helper()
	s, agent := grantWorld(t)
	s.localOwnerSecret = testOwnerSecret
	// A registry made while the key was here, as on a device paired since.
	if _, err := s.issueCapabilityGrant(agent, authority{About: agent.ID}); err != nil {
		t.Fatal(err)
	}
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.identitySigningSeed(); err == nil {
		t.Fatal("the key still reads as held here")
	}
	return s, seed, agent
}

// waiting is the grant signing requests waiting for the device.
func waiting(t *testing.T, s *CoreServer) []store.SigningRequest {
	t.Helper()
	all, err := s.DataStore.GetPendingSigningRequests()
	if err != nil {
		t.Fatal(err)
	}
	var out []store.SigningRequest
	for _, r := range all {
		if r.Kind == signingKindGrant && r.Status == SigningStatusPending {
			out = append(out, r)
		}
	}
	return out
}

func fulfil(t *testing.T, s *CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
	sig, _ := login.SignString(string(payload), seed)
	rec := httptest.NewRecorder()
	s.handleFulfilSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+req.ID+"/fulfil",
		strings.NewReader(`{"signature":"`+sig+`"}`), s), req.ID))
	return rec
}

// A machine granted where the key is elsewhere waits; the device that holds
// the key signs the grant's interaction, and the machine is granted with
// exactly that signature in the key log, which verifies.
func TestAMachineIsGrantedOnceTheDeviceWithTheKeySigns(t *testing.T) {
	s, seed, _ := keyElsewhere(t)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	g := aGrant(GradeEnrolled)
	if got, err := s.grantController(g, time.Now().UTC(), authority{}); err != nil || !got.CredentialPending {
		t.Fatalf("granting where the key is elsewhere: %+v %v", got, err)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written before the device signed")
	}
	reqs := waiting(t, s)
	if len(reqs) != 1 || !strings.Contains(reqs[0].Summary, "machine") || reqs[0].Presentation != PresentationConsent {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	if rec := fulfil(t, s, reqs[0], seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := s.controllers().Get(g.ControllerAID)
	if got.CredentialSAID == "" || got.CredentialPending {
		t.Fatalf("the machine is still waiting: %+v", got)
	}
	after, _ := s.DataStore.GetEvents(owner.AID)
	if len(after) != len(before)+1 || after[len(after)-1].CesrSignature == "" {
		t.Fatal("the grant's interaction was not appended with the device's signature")
	}
	in := drivers.ValidateKELInput{AID: owner.AID}
	for _, ev := range after {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	if res, err := drivers.ValidateKELFromBytes(in); err != nil || !res.KelVerified {
		t.Fatalf("the key log does not verify after the device signed: %v %+v", err, res)
	}
	if m, _ := awaiting(t, s); m[g.ControllerAID] != "" {
		t.Fatal("the granted machine is still listed as waiting")
	}
}

// An AI agent waiting for its grant may do nothing until the device signs,
// and then may do what it was granted.
func TestAnAIAgentIsGrantedOnceTheDeviceWithTheKeySigns(t *testing.T) {
	s, seed, agent := keyElsewhere(t)
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
	toks = append(toks, mcpToken{Name: "waiting", AgentAID: agent.PairwiseAID, DelegatorAID: agent.DelegatorAID, AssetID: agent.ID, Scopes: agent.Capabilities, GrantPending: true})
	s.saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	if _, err := s.issueCapabilityGrant(agent, authority{About: agent.ID}); err == nil {
		t.Fatal("a grant was issued where the key is elsewhere")
	}
	scopes := func() []string {
		for _, tok := range s.loadMCPTokens() {
			if tok.Name == "waiting" {
				cc := sandbox.CallerContext{Scopes: tok.Scopes}
				s.applyGrantScopes(tok, &cc)
				return cc.Scopes
			}
		}
		return nil
	}
	if len(scopes()) != 0 {
		t.Fatal("an AI agent waiting for its grant may do something")
	}
	reqs := waiting(t, s)
	if len(reqs) != 1 || !strings.Contains(reqs[0].Detail, "AI agent") {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	if rec := fulfil(t, s, reqs[0], seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	if len(scopes()) == 0 {
		t.Fatal("the AI agent may still do nothing once its grant is signed")
	}
}

// A signature by another key changes nothing, and the request still waits.
func TestAWronglySignedGrantIsRefused(t *testing.T) {
	s, _, _ := keyElsewhere(t)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	g := aGrant(GradeEnrolled)
	s.grantController(g, time.Now().UTC(), authority{})
	reqs := waiting(t, s)
	other := make([]byte, 32)
	other[0] = 7
	if rec := fulfil(t, s, reqs[0], other); rec.Code != http.StatusBadRequest {
		t.Fatalf("a signature by another key was answered %d", rec.Code)
	}
	if got, _, _ := s.controllers().Get(g.ControllerAID); got.CredentialSAID != "" || !got.CredentialPending {
		t.Fatal("a wrongly signed grant changed the machine")
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("a wrongly signed grant was appended")
	}
	if len(waiting(t, s)) != 1 {
		t.Fatal("the request no longer waits")
	}
}

// A grant built on a key log that has moved on is refused when signed, and
// built again for the device to sign afresh.
func TestAStaleGrantIsBuiltAgain(t *testing.T) {
	s, seed, _ := keyElsewhere(t)
	a, b := aGrant(GradeEnrolled), grantFor(2, GradeEnrolled)
	s.grantController(a, time.Now().UTC(), authority{})
	s.grantController(b, time.Now().UTC(), authority{})
	reqs := waiting(t, s)
	if len(reqs) != 2 {
		t.Fatalf("%d requests wait", len(reqs))
	}
	if rec := fulfil(t, s, reqs[0], seed); rec.Code != http.StatusOK {
		t.Fatalf("the first: %d %s", rec.Code, rec.Body.String())
	}
	if rec := fulfil(t, s, reqs[1], seed); rec.Code != http.StatusConflict {
		t.Fatalf("a stale grant was answered %d %s", rec.Code, rec.Body.String())
	}
	fresh := waiting(t, s)
	if len(fresh) != 1 || fresh[0].ID == reqs[1].ID {
		t.Fatalf("the stale grant was not asked for afresh: %+v", fresh)
	}
	if rec := fulfil(t, s, fresh[0], seed); rec.Code != http.StatusOK {
		t.Fatalf("the grant built again: %d %s", rec.Code, rec.Body.String())
	}
	for _, g := range []ControllerGrant{a, b} {
		if got, _, _ := s.controllers().Get(g.ControllerAID); got.CredentialSAID == "" || got.CredentialPending {
			t.Fatalf("machine %s is still waiting", g.ControllerAID)
		}
	}
}

// Where the key is elsewhere, an earlier AI agent approved by its owner
// waits for the device rather than failing; one already granted is refused
// before anything is asked for, since its grant could not be withdrawn here.
func TestApprovingWhereTheKeyIsElsewhereWaitsOrRefuses(t *testing.T) {
	w := newTalkWorld(t)
	provision := func(name string) string {
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, local("POST", "/api/mcp/agents", `{"name":"`+name+`","capabilities":["`+capabilityMessageAgent+`"]}`))
		var made map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &made)
		id, _ := made["asset_id"].(string)
		if id == "" {
			t.Fatalf("provisioning %s: %d %s", name, rec.Code, rec.Body.String())
		}
		return id
	}
	earlier, granted := provision("Earlier"), provision("Granted")
	mcpTokensMu.Lock()
	toks := w.s.loadMCPTokens()
	for i := range toks {
		if toks[i].AssetID == earlier {
			toks[i].GrantSAID = ""
		}
	}
	w.s.saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	owner, _ := w.s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	w.s.DataStore.SaveIdentity(*owner)
	put := func(id string) int {
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, local("PUT", "/api/mcp/agents/"+id+"/capabilities", `{"capabilities":["`+capabilityMessageAgent+`"]}`))
		return rec.Code
	}
	if code := put(earlier); code != http.StatusOK {
		t.Fatalf("approving an earlier AI agent where the key is elsewhere was answered %d", code)
	}
	if !w.s.agentGrantPendingFor(earlier) {
		t.Fatal("the approved AI agent is not waiting for the device")
	}
	if n := len(waiting(t, w.s)); n != 1 {
		t.Fatalf("%d grants were asked for", n)
	}
	if code := put(granted); code != http.StatusConflict {
		t.Fatalf("re-granting an AI agent already granted, where the key is elsewhere, was answered %d", code)
	}
	if n := len(waiting(t, w.s)); n != 1 {
		t.Fatal("a grant was asked for before re-granting was refused")
	}
}

// A waiting grant whose kept request no longer holds when it is signed is
// not appended.
func TestAWaitingGrantIsCheckedAgainWhenSigned(t *testing.T) {
	w := newTalkWorld(t)
	s := w.s
	resetSeenSignatures(t)
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	s.DataStore.SaveIdentity(*owner)
	g := aGrant(GradeEnrolled)
	body := `{"controller_aid":"` + g.ControllerAID + `","public_key":"` + g.PublicKey + `","label":"` + g.Label + `","grade":"` + string(g.Grade) + `"}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	sig, _ := SignOwnerRequest("POST", "/api/controllers", stamp, []byte(body), testOwnerSeed())
	by := authority{Request: &signedRequest{Kind: "owner", Signer: "EOWNERTESTAID", Body: body, Signature: sig,
		Signed: canonicalRequestString("POST", "/api/controllers", stamp, []byte(body))}}
	if got, err := s.grantController(g, time.Now().UTC(), by); err != nil || !got.CredentialPending {
		t.Fatalf("granting where the key is elsewhere: %+v %v", got, err)
	}
	reqs := waiting(t, s)
	if len(reqs) != 1 {
		t.Fatalf("%d grants were asked for", len(reqs))
	}
	// The request kept with it, altered on disk while it waited.
	kept, _, _ := s.DataStore.GetPendingIssuance(reqs[0].ID)
	altered := strings.Replace(kept, `\"grade\":\"enrolled\"`, `\"grade\":\"scoped\"`, 1)
	if altered == kept {
		t.Fatal("the kept request was not found to alter")
	}
	recordDB(t, s).Exec(`UPDATE pending_issuances SET body = ? WHERE signing_request_id = ?`, altered, reqs[0].ID)
	before, _ := s.DataStore.GetEvents(owner.AID)
	if rec := fulfil(t, s, reqs[0], seed); rec.Code < 400 {
		t.Fatalf("a waiting grant whose request no longer holds was answered %d", rec.Code)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("a waiting grant whose request no longer holds was appended")
	}
}
