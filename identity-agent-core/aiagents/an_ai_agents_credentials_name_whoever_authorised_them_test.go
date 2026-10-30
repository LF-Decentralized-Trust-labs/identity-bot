package aiagents

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/authprovider"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"identity-agent-core/server"
)

// Whoever authorised an AI agent's credentials, or a machine acting on one, is named in them.

// authorisedBy checks a credential names the controller's grant and carries the
// request the controller signed, which verifies against its key.
func authorisedBy(t *testing.T, w *talkWorld, said string) {
	t.Helper()
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	cred := helpers.AcdcOf(t, w.s, said)
	edges, _ := cred["e"].(map[string]interface{})
	by, _ := edges["authorised_by"].(map[string]interface{})
	if by["n"] != ctl.CredentialSAID || by["s"] != schemas.ControllerGrant.Schema.SAID {
		t.Fatalf("the credential does not rest on the grant of the machine that asked: %v", cred["e"])
	}
	attrs, _ := cred["a"].(map[string]interface{})
	req, _ := attrs["request"].(map[string]interface{})
	signed, _ := req["signed"].(string)
	sig, _ := req["signature"].(string)
	if req["signer"] != w.ctlAID {
		t.Fatalf("the credential does not carry the request as that machine signed it: %v", attrs["request"])
	}
	if ok, err := iacrypto.VerifyMachineSignature(ctl.PublicKey, sig, []byte(signed)); err != nil || !ok {
		t.Fatalf("the request kept in the credential does not verify against the machine's key: %v", err)
	}
}

// An AI agent's grant names whoever asked for it: the grant of the machine
// they asked from, and the request as that machine signed it.
func TestAnAIAgentsGrantNamesWhoAskedForIt(t *testing.T) {
	w := newTalkWorld(t)
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("changing the AI agent's grant: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		GrantSAID string `json:"grant_said"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.GrantSAID == "" {
		t.Fatalf("no grant was issued: %s", rec.Body.String())
	}
	authorisedBy(t, w, out.GrantSAID)
}

// A machine's body credential names whoever compared the words and approved it.
func TestABodyCredentialNamesWhoApprovedIt(t *testing.T) {
	w := newTalkWorld(t)
	m := newTestMachine(t)
	host, _, _ := agentbody.Identity(m)
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: m, Hardware: true}
	done := make(chan string, 1)
	go func() {
		for i := 0; i < 200; i++ {
			for _, b := range of(w.s).bodies().ForAgent(w.b.ID) {
				if b.State == agentbody.StatePending && b.Host == host {
					req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "POST", "/api/mcp/agents/"+w.b.ID+"/bodies/"+b.ID+"/approve",
						"", w.ctlSeed, authprovider.LevelVerified, time.Now())
					rec := httptest.NewRecorder()
					hostOf(w.s).Router().ServeHTTP(rec, req)
					done <- rec.Body.String()
					return
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		done <- "never asked"
	}()
	if _, err := h.Enrol(enrolmentVia(t, w.s, w.srv.URL, w.b.ID), "computer", 20*time.Second); err != nil {
		t.Fatalf("enrolling: %v (approval said %s)", err, <-done)
	}
	<-done
	var said string
	for _, b := range of(w.s).bodies().ForAgent(w.b.ID) {
		if b.Host == host {
			said = b.CredentialSAID
		}
	}
	if said == "" {
		t.Fatal("the machine was not bound by a credential")
	}
	authorisedBy(t, w, said)
}

// A conversation's opening names the opener's machine by its anchored grant,
// inside what the Identity Agent countersigned.
func TestAConversationNamesTheGrantItWasOpenedUnder(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	entries := w.read(t, conv)
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	proof := entries[0].Record.ControllerProof
	if proof == nil || ctl.CredentialSAID == "" || proof.ControllerGrant != ctl.CredentialSAID {
		t.Fatalf("the opening does not name the grant it was opened under: %+v", proof)
	}
	if !strings.HasPrefix(entries[0].Record.From, "person:") {
		t.Fatalf("the opening is not a person's: %s", entries[0].Record.From)
	}
}

// A request the identity's own key signed is kept as the authority, and the
// credential rests on it.
func TestAnOwnersSignedRequestIsKeptAsTheAuthority(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	req := helpers.SignedFor(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities", `{"capabilities":["`+capabilityMessageAgent+`"]}`, helpers.TestOwnerSeed(), time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner's change: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		GrantSAID string `json:"grant_said"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	attrs, _ := helpers.AcdcOf(t, w.s, out.GrantSAID)["a"].(map[string]interface{})
	r, _ := attrs["request"].(map[string]interface{})
	if r["kind"] != "owner" || r["body"] == "" {
		t.Fatalf("the owner's request is not kept as the authority: %v", attrs["request"])
	}
}

// A credential that does not rest on the request it carries is not issued.
func TestACredentialThatDoesNotRestOnItsRequestIsNotIssued(t *testing.T) {
	w := newTalkWorld(t)
	before := 0
	for _, c := range helpers.CredentialsOf(t, w.s, w.a.PairwiseAID) {
		if helpers.IsUsableStatus(c.Status) {
			before++
		}
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	bogus := coretypes.Authority{Request: &coretypes.SignedRequest{Kind: "owner", Signer: "EOWNERTESTAID", Body: `{"capabilities":[]}`,
		Signed:    helpers.CanonicalRequestString("PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities", stamp, []byte(`{"capabilities":[]}`)),
		Signature: "0Bnot-a-signature"}, About: w.a.ID}
	if _, err := hostOf(w.s).IssueCapabilityGrant(w.a, bogus); err == nil {
		t.Fatal("a grant resting on a request nobody signed was issued")
	}
	after := 0
	for _, c := range helpers.CredentialsOf(t, w.s, w.a.PairwiseAID) {
		if helpers.IsUsableStatus(c.Status) {
			after++
		}
	}
	if after != before {
		t.Fatalf("usable grants went from %d to %d", before, after)
	}
}

// A grant or body credential issued under the first version after this
// Identity Agent began naming who authorised them is not honoured; one issued
// before is.
func TestAFirstVersionCredentialIssuedAfterwardsIsNotHonoured(t *testing.T) {
	s, agent := helpers.GrantWorld(t)
	early, err := hostOf(s).IssueAssetCredential(schemas.AIAgentGrantV1, agent.PairwiseAID, agent.DelegatorAID,
		map[string]interface{}{"name": "early", "capabilities": []string{}}, "", coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostOf(s).IssueCapabilityGrant(agent, coretypes.Authority{}); err != nil {
		t.Fatal(err)
	}
	late, err := hostOf(s).IssueAssetCredential(schemas.AIAgentGrantV1, agent.PairwiseAID, agent.DelegatorAID,
		map[string]interface{}{"name": "late", "capabilities": []string{}}, "", coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := s.DataStore.GetCredential(early)
	l, _ := s.DataStore.GetCredential(late)
	if hostOf(s).IssuedUnderFirstVersionTooLate(e) {
		t.Fatal("a first-version grant issued before the change was refused")
	}
	if !hostOf(s).IssuedUnderFirstVersionTooLate(l) {
		t.Fatal("a first-version grant issued after the change was honoured")
	}
	if of(s).grantCredentialValid(l, mcpToken{AgentAID: agent.PairwiseAID, DelegatorAID: agent.DelegatorAID}) {
		t.Fatal("the gateway honoured a first-version grant issued after the change")
	}
}

// A machine whose grant has been withdrawn authorises nothing, and nor does
// one paired before machines were given grants, which is not given one by
// asking.
func TestAMachineWithoutAGrantInForceAuthorisesNothing(t *testing.T) {
	w := newTalkWorld(t)
	asked := 0
	put := func() int {
		// Each request its own, so none is refused as one already used.
		asked++
		req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
			`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified,
			time.Now().Add(-time.Duration(asked)*time.Second))
		rec := httptest.NewRecorder()
		hostOf(w.s).Router().ServeHTTP(rec, req)
		return rec.Code
	}
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	unanchored := ctl
	unanchored.CredentialSAID = ""
	helpers.PutControllerRow(w.s, unanchored)
	if code := put(); code != http.StatusForbidden {
		t.Fatalf("a machine paired before grants was answered %d", code)
	}
	if got, _, _ := helpers.ControllerRow(w.s, w.ctlAID); got.CredentialSAID != "" {
		t.Fatal("the machine was given a grant by asking")
	}
	helpers.PutControllerRow(w.s, ctl)
	if err := hostOf(w.s).WithdrawControllerGrant(ctl.CredentialSAID); err != nil {
		t.Fatal(err)
	}
	if code := put(); code != http.StatusForbidden {
		t.Fatalf("a machine whose grant was withdrawn was answered %d", code)
	}
}

// While a credential is being issued on a machine's grant, the grant cannot
// be revoked under it.
func TestAGrantIsHeldWhileACredentialIsIssuedOnIt(t *testing.T) {
	w := newTalkWorld(t)
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":[]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	grant, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	req = helpers.WithController(req, grant)
	_, held, err := hostOf(w.s).AuthorityOf(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { hostOf(w.s).RevokeController(w.ctlAID); close(done) }()
	select {
	case <-done:
		t.Fatal("the grant was revoked while a credential was being issued on it")
	case <-time.After(100 * time.Millisecond):
	}
	held()
	<-done
}

// An AI agent provisioned from a machine is granted on the request, and the
// grant, which anybody can fetch, keeps what was asked for and nothing else
// the request carried: no prompt, no model address, no stored key's name.
func TestAPublishedGrantCarriesNoPrivateConfiguration(t *testing.T) {
	w := newTalkWorld(t)
	body := `{"name":"Ledger clerk","capabilities":["` + capabilityMessageAgent + `"],"system_prompt":"SECRET-PROMPT",` +
		`"brain":{"kind":"local","model":"m","endpoint":"http://10.0.0.9:1234","credential_ref":"ai-agent-brain:vault-key-7"},"nonce":"n-1"}`
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "POST", "/api/mcp/agents", body, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("provisioning: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	said, _ := out["grant_said"].(string)
	if said == "" {
		t.Fatalf("no grant was issued: %s", rec.Body.String())
	}
	pub := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(pub, helpers.Remote("GET", "/public/credential/"+said, ""))
	served := pub.Body.String()
	if c, _ := w.s.DataStore.GetCredential(said); c != nil {
		raw, _ := base64.StdEncoding.DecodeString(c.AcdcJson)
		served += string(raw)
	}
	for _, private := range []string{"SECRET-PROMPT", "10.0.0.9", "vault-key-7", "system_prompt"} {
		if strings.Contains(served, private) {
			t.Fatalf("the grant gives away %q", private)
		}
	}
	attrs, _ := helpers.AcdcOf(t, w.s, said)["a"].(map[string]interface{})
	asked, _ := attrs["request"].(map[string]interface{})["asked"].(map[string]interface{})
	if asked["nonce"] != "n-1" || asked["name"] != "Ledger clerk" {
		t.Fatalf("the grant does not keep what was asked for: %v", asked)
	}
	if kept, ok, _ := w.s.DataStore.GetCredentialRequestBody(said); !ok || kept != body {
		t.Fatal("the full request was not kept with this Identity Agent's record")
	}
}

// One request authorises one credential.
func TestARequestAuthorisesOneCredential(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	body := `{"capabilities":["` + capabilityMessageAgent + `"]}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/mcp/agents/" + w.a.ID + "/capabilities"
	ia := hostOf(w.s).ThisIdentityAgentsIdentifier()
	sig, _ := server.SignOwnerRequest(ia, "PUT", path, stamp, []byte(body), helpers.TestOwnerSeed())
	by := coretypes.Authority{About: w.a.ID, Request: &coretypes.SignedRequest{Kind: "owner", Signer: "EOWNERTESTAID", Body: body,
		Signed: helpers.CanonicalOwnerRequest(ia, "PUT", path, stamp, []byte(body)), Signature: sig}}
	if _, err := hostOf(w.s).IssueCapabilityGrant(w.a, by); err != nil {
		t.Fatalf("the first credential on the request: %v", err)
	}
	held := len(helpers.CredentialsOf(t, w.s, w.a.PairwiseAID))
	if _, err := hostOf(w.s).IssueCapabilityGrant(w.a, by); err == nil {
		t.Fatal("one request authorised a second credential")
	}
	if now := len(helpers.CredentialsOf(t, w.s, w.a.PairwiseAID)); now != held {
		t.Fatal("a second credential was issued on the request before being refused")
	}
}

// Where grants can be issued, an AI agent whose grant cannot be issued is not
// created, and no token is minted for it.
func TestAnAIAgentWhoseGrantCannotBeIssuedIsNotCreated(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	// The owner's request, its digest already spent on another credential, so
	// the grant it asks for is refused while everything before it succeeds.
	body := `{"name":"Ungranted","capabilities":["` + capabilityMessageAgent + `"]}`
	at := time.Now()
	req := helpers.SignedFor(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", body, helpers.TestOwnerSeed(), at)
	spent := helpers.CanonicalOwnerRequest(hostOf(w.s).ThisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", at.UTC().Format(time.RFC3339), []byte(body))
	if err := w.s.DataStore.KeepCredentialRequest("Eanother-credential", iacrypto.Blake3QB64Must([]byte(spent)), body); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("an AI agent with no grant was created: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range hostOf(w.s).AssetHandler().Store.ListAssets() {
		if a.DisplayName == "Ungranted" {
			t.Fatal("the AI agent was left in place")
		}
	}
	if of(w.s).anMCPTokenIsNamed("Ungranted") {
		t.Fatal("a token was minted for it")
	}
}

// A request carrying a signature that does not hold creates no AI agent and
// mints no token.
func TestABadlySignedRequestCreatesNoAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	req := helpers.Local("POST", "/api/mcp/agents", `{"name":"Unwanted","capabilities":[]}`)
	req.Header.Set(helpers.HeaderOwnerSig(), "0Bjunk")
	req.Header.Set(helpers.HeaderOwnerTimestamp(), time.Now().UTC().Format(time.RFC3339))
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("a badly signed request created an AI agent: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range hostOf(w.s).AssetHandler().Store.ListAssets() {
		if a.DisplayName == "Unwanted" {
			t.Fatal("the AI agent was left in place")
		}
	}
	if of(w.s).anMCPTokenIsNamed("Unwanted") {
		t.Fatal("a token was minted for it")
	}
}

// Where grants can be issued, an AI agent's token with no grant may do nothing.
func TestAnAIAgentWithNoGrantMayDoNothing(t *testing.T) {
	s, agent := helpers.GrantWorld(t)
	cc := permission.CallerContext{Scopes: []string{"system.info.read"}}
	of(s).applyGrantScopes(mcpToken{AgentAID: agent.PairwiseAID, DelegatorAID: agent.DelegatorAID}, &cc)
	if len(cc.Scopes) != 0 {
		t.Fatalf("an AI agent with no grant kept %v", cc.Scopes)
	}
}

// A granted machine's row changed since its grant is not acted on, and no
// grant is re-issued from it.
func TestAGrantedMachinesRowEditedSinceIsRefused(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	edited := ctl
	edited.Label = "renamed in the file"
	helpers.PutControllerRow(w.s, edited)
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a machine whose row was changed since its grant was answered %d", rec.Code)
	}
	helpers.PutControllerRow(w.s, ctl)
	edited = ctl
	edited.Grade = server.GradeScoped
	edited.Signer = ""
	helpers.PutControllerRow(w.s, edited)
	if _, err := hostOf(w.s).BindSigner(ctl.ControllerAID, "Esigner"); err == nil {
		t.Fatal("a grant was re-issued from a row changed since")
	}
}

// The owner removes a machine; somebody who can write the data directory puts
// its row back. It is never granted without the owner's signature: not at
// start, not on the tick, not by asking, and it waits for approval.
func TestARestoredMachineRowIsNeverGrantedWithoutTheOwner(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	if err := hostOf(w.s).RevokeController(w.ctlAID); err != nil {
		t.Fatal(err)
	}
	restored := ctl
	restored.CredentialSAID = ""
	helpers.PutControllerRow(w.s, restored)
	helpers.EverythingRuns(w.s)
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a restored machine row was answered %d", rec.Code)
	}
	helpers.EverythingRuns(w.s)
	if got, _, _ := helpers.ControllerRow(w.s, w.ctlAID); got.CredentialSAID != "" || got.CredentialPending {
		t.Fatal("a restored machine row was given a grant")
	}
	if m, _ := helpers.Awaiting(t, w.s); m[w.ctlAID] != "the owner's approval" {
		t.Fatalf("the restored machine is not listed as awaiting the owner: %v", m)
	}
}

// An AI agent with no grant, widened in the files, is never granted from them:
// it may do nothing and waits for the owner.
func TestAnAIAgentWithNoGrantIsNeverGrantedFromItsFiles(t *testing.T) {
	w := newTalkWorld(t)
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.Local("POST", "/api/mcp/agents", `{"name":"Earlier","capabilities":["`+capabilityMessageAgent+`"]}`))
	var made map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &made)
	id, _ := made["asset_id"].(string)
	a, _ := hostOf(w.s).AssetHandler().Store.GetAsset(id)
	a.Capabilities = append(a.Capabilities, "infra.dns_record.create")
	hostOf(w.s).AssetHandler().Store.UpsertAsset(a)
	mcpTokensMu.Lock()
	toks := of(w.s).loadMCPTokens()
	for i := range toks {
		if toks[i].AssetID == id {
			toks[i].GrantSAID = ""
			toks[i].Scopes = append(toks[i].Scopes, "infra.dns_record.create")
		}
	}
	of(w.s).saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	held := len(helpers.CredentialsOf(t, w.s, a.PairwiseAID))
	helpers.EverythingRuns(w.s)
	if now := len(helpers.CredentialsOf(t, w.s, a.PairwiseAID)); now != held {
		t.Fatal("a grant was issued from what the files say")
	}
	for _, tok := range of(w.s).loadMCPTokens() {
		if tok.AssetID != id {
			continue
		}
		cc := permission.CallerContext{Scopes: tok.Scopes}
		of(w.s).applyGrantScopes(tok, &cc)
		if len(cc.Scopes) != 0 {
			t.Fatalf("the AI agent may do %v without a grant", cc.Scopes)
		}
	}
	if _, ag := helpers.Awaiting(t, w.s); ag[id] != "the owner's approval" {
		t.Fatalf("the AI agent is not listed as awaiting the owner: %v", ag)
	}
}

// The owner approves an earlier AI agent by setting its capabilities, signed.
func TestTheOwnerApprovesAnEarlierAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.Local("POST", "/api/mcp/agents", `{"name":"Earlier","capabilities":["`+capabilityMessageAgent+`"]}`))
	var made map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &made)
	id, _ := made["asset_id"].(string)
	mcpTokensMu.Lock()
	toks := of(w.s).loadMCPTokens()
	for i := range toks {
		if toks[i].AssetID == id {
			toks[i].GrantSAID = ""
		}
	}
	of(w.s).saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	body := `{"capabilities":["` + capabilityMessageAgent + `"]}`
	rec = httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.SignedFor(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), "PUT", "/api/mcp/agents/"+id+"/capabilities", body, helpers.TestOwnerSeed(), time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner's approval: %d %s", rec.Code, rec.Body.String())
	}
	for _, tok := range of(w.s).loadMCPTokens() {
		if tok.AssetID != id {
			continue
		}
		cc := permission.CallerContext{Scopes: tok.Scopes}
		of(w.s).applyGrantScopes(tok, &cc)
		if tok.GrantSAID == "" || len(cc.Scopes) == 0 {
			t.Fatal("the approved AI agent may still do nothing")
		}
	}
	if _, ag := helpers.Awaiting(t, w.s); ag[id] != "" {
		t.Fatal("the approved AI agent is still listed as awaiting")
	}
}

// An AI agent that authenticates by its own signature, with no token and no
// grant, is told it awaits the owner's approval, and is listed as waiting.
func TestAnAIAgentWithNoTokenAndNoGrantAwaitsTheOwner(t *testing.T) {
	w := newTalkWorld(t)
	// An AI agent from before grants has none at all.
	helpers.RecordDB(t, w.s).Exec(`DELETE FROM credentials WHERE holder_aid = ?`, w.a.PairwiseAID)
	cc, ok := of(w.s).ResolveAgentCaller(w.a.PairwiseAID)
	if !ok || len(cc.Scopes) != 0 || !strings.Contains(cc.NoScopesBecause, "awaiting the owner's approval") {
		t.Fatalf("an AI agent with no grant resolves as %+v", cc)
	}
	if _, ag := helpers.Awaiting(t, w.s); ag[w.a.ID] != "the owner's approval" {
		t.Fatalf("the AI agent is not listed as waiting: %v", ag)
	}
	tok := mcpToken{AgentAID: w.a.PairwiseAID, AssetID: w.a.ID}
	cc = permission.CallerContext{Scopes: []string{capabilityMessageAgent}}
	of(w.s).applyGrantScopes(tok, &cc)
	if !strings.Contains(cc.NoScopesBecause, "awaiting the owner's approval") {
		t.Fatalf("a token with no grant is denied without saying why: %q", cc.NoScopesBecause)
	}
}

// A granted machine whose signer or end was written into its file is refused,
// for what it asks for and for who is speaking from it.
func TestAMachinesFileEditedSignerOrEndIsRefused(t *testing.T) {
	for _, edit := range []string{"signer", "end"} {
		t.Run(edit, func(t *testing.T) {
			w := newTalkWorld(t)
			helpers.ResetSeenSignatures(t)
			ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
			edited := ctl
			if edit == "signer" {
				edited.Signer = "EImpostorSigner"
			} else {
				edited.ExpiresAt = time.Now().UTC().Add(24 * 365 * time.Hour)
			}
			helpers.PutControllerRow(w.s, edited)
			if err := hostOf(w.s).RowIsItsGrant(edited); err == nil {
				t.Fatal("the edited row was taken for its grant")
			}
			req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
				`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
			if _, _, err := hostOf(w.s).ThePersonAsking(helpers.WithController(req, edited)); err == nil || !strings.Contains(err.Error(), "no longer says") {
				t.Fatalf("a person was attributed from an edited row: %v", err)
			}
		})
	}
}

// A mark that a machine's grant waits for another device is not believed
// where the key is here.
func TestAPendingMarkIsNotBelievedWhereTheKeyIsHere(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	ctl, _, _ := helpers.ControllerRow(w.s, w.ctlAID)
	marked := ctl
	marked.CredentialSAID, marked.CredentialPending = "", true
	helpers.PutControllerRow(w.s, marked)
	req := helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a machine marked as waiting, where the key is here, was answered %d", rec.Code)
	}
	if m, _ := helpers.Awaiting(t, w.s); m[w.ctlAID] != "the owner's approval" {
		t.Fatalf("a machine marked as waiting, where the key is here, is listed as %q", m[w.ctlAID])
	}
}

// A credential that does not rest on its request never reaches the key log:
// it is checked when built, not issued and then withdrawn.
func TestACredentialThatFailsItsCheckWritesNothing(t *testing.T) {
	w := newTalkWorld(t)
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.Local("POST", "/api/mcp/agents", `{"name":"First","capabilities":["`+capabilityMessageAgent+`"]}`))
	if rec.Code >= 400 {
		t.Fatalf("provisioning: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := w.s.DataStore.GetCredentials()
	req := helpers.Local("POST", "/api/mcp/agents", `{"name":"Unwanted","capabilities":["`+capabilityMessageAgent+`"]}`)
	req.Header.Set(helpers.HeaderOwnerSig(), "0Bjunk")
	req.Header.Set(helpers.HeaderOwnerTimestamp(), time.Now().UTC().Format(time.RFC3339))
	rec = httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("a badly signed request was answered %d", rec.Code)
	}
	// Issued and withdrawn, it would be on record, revoked.
	if after, _ := w.s.DataStore.GetCredentials(); len(after) != len(before) {
		t.Fatalf("a credential that failed its check was issued (%d more on record)", len(after)-len(before))
	}
}

// An AI agent whose grant has lapsed is told it has expired, not that it
// awaits approval.
func TestAnAIAgentWithALapsedGrantIsToldItExpired(t *testing.T) {
	w := newTalkWorld(t)
	held := helpers.CredentialsOf(t, w.s, w.a.PairwiseAID)
	if len(held) == 0 {
		t.Fatal("the AI agent holds no grant")
	}
	for _, c := range held {
		w.s.DataStore.UpdateCredentialStatus(c.SAID, "expired")
	}
	cc, _ := of(w.s).ResolveAgentCaller(w.a.PairwiseAID)
	if !strings.Contains(cc.NoScopesBecause, "expired") {
		t.Fatalf("an AI agent with a lapsed grant is told %q", cc.NoScopesBecause)
	}
	tok := mcpToken{AgentAID: w.a.PairwiseAID, AssetID: w.a.ID, GrantSAID: held[0].SAID}
	cc = permission.CallerContext{Scopes: []string{capabilityMessageAgent}}
	of(w.s).applyGrantScopes(tok, &cc)
	if !strings.Contains(cc.NoScopesBecause, "expired") {
		t.Fatalf("a token whose grant lapsed is told %q", cc.NoScopesBecause)
	}
}

// A browser session can issue no authority over an AI agent.
func TestASessionIssuesNoAuthority(t *testing.T) {
	for _, route := range []string{"POST /api/mcp/agents", "PUT /api/mcp/agents/{id}/capabilities", "POST /api/mcp/agents/{id}/bodies/{bid}/approve"} {
		if _, refused := helpers.EverySessionForbidden()[route]; !refused {
			t.Fatalf("a browser session may reach %s", route)
		}
	}
}
