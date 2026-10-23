package server

import (
	"context"
	"crypto/ed25519"
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
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// acdcOf is a stored credential's body.
func acdcOf(t *testing.T, s *CoreServer, said string) map[string]interface{} {
	t.Helper()
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		t.Fatalf("credential %s is not on record: %v", said, err)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func statusOf(t *testing.T, s *CoreServer, said string) string {
	t.Helper()
	rec, _ := s.DataStore.GetCredential(said)
	if rec == nil {
		t.Fatalf("credential %s is not on record", said)
	}
	_, status, err := s.credentialLog(rec.RegistrySAID, said)
	if err != nil {
		t.Fatalf("credential %s has no log that holds together: %v", said, err)
	}
	return status
}

// Granting a machine issues its Controller Grant into the identity's registry,
// anchored in its key log; removing the machine withdraws it.
func TestAMachinesGrantIsAnchoredAndWithdrawnWithIt(t *testing.T) {
	s, _ := grantWorld(t)
	r := s.buildRouter("")
	g := aGrant(GradeEnrolled)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, local("POST", "/api/controllers",
		`{"controller_aid":"`+g.ControllerAID+`","public_key":"`+g.PublicKey+`","label":"the laptop","grade":"enrolled"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("granting: %d %s", w.Code, w.Body.String())
	}
	kept, _, _ := s.controllers().Get(g.ControllerAID)
	if kept.CredentialSAID == "" {
		t.Fatal("the machine was granted without a credential to show for it")
	}
	cred := acdcOf(t, s, kept.CredentialSAID)
	attrs, _ := cred["a"].(map[string]interface{})
	if cred["s"] != schemas.ControllerGrant.Schema.SAID || attrs["i"] != g.ControllerAID || attrs["public_key"] != g.PublicKey {
		t.Fatalf("the credential is not this machine's grant: %v", cred)
	}
	if got := statusOf(t, s, kept.CredentialSAID); got != keri.StatusIssued {
		t.Fatalf("the grant's log ends %q", got)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, local("DELETE", "/api/controllers/"+g.ControllerAID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("removing: %d %s", w.Code, w.Body.String())
	}
	if got := statusOf(t, s, kept.CredentialSAID); got != keri.StatusRevoked {
		t.Fatalf("a removed machine's grant still stands in the registry: %q", got)
	}
}

// A machine whose grant cannot be anchored is not granted.
func TestAMachineIsNotGrantedWhenItsGrantCannotBeAnchored(t *testing.T) {
	s, _ := grantWorld(t)
	r := s.buildRouter("")
	s.KeriDriver = nil
	g := aGrant(GradeEnrolled)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, local("POST", "/api/controllers",
		`{"controller_aid":"`+g.ControllerAID+`","public_key":"`+g.PublicKey+`","label":"the laptop","grade":"enrolled"}`))
	if w.Code == http.StatusOK {
		t.Fatal("a machine was granted with nothing anchored to show for it")
	}
	if _, had, _ := s.controllers().Get(g.ControllerAID); had {
		t.Fatal("the unanchored grant was left in place")
	}
}

// authorisedBy checks a credential names the controller's grant and carries the
// request the controller signed, which verifies against its key.
func authorisedBy(t *testing.T, w *talkWorld, said string) {
	t.Helper()
	ctl, _, _ := w.s.controllers().Get(w.ctlAID)
	cred := acdcOf(t, w.s, said)
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
	req := asThatMachine(t, w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
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
			for _, b := range w.s.bodies().ForAgent(w.b.ID) {
				if b.State == agentbody.StatePending && b.Host == host {
					req := asThatMachine(t, w.ctlAID, "POST", "/api/mcp/agents/"+w.b.ID+"/bodies/"+b.ID+"/approve",
						"", w.ctlSeed, authprovider.LevelVerified, time.Now())
					rec := httptest.NewRecorder()
					w.s.router.ServeHTTP(rec, req)
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
	for _, b := range w.s.bodies().ForAgent(w.b.ID) {
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
	ctl, _, _ := w.s.controllers().Get(w.ctlAID)
	proof := entries[0].Record.ControllerProof
	if proof == nil || ctl.CredentialSAID == "" || proof.ControllerGrant != ctl.CredentialSAID {
		t.Fatalf("the opening does not name the grant it was opened under: %+v", proof)
	}
	if !strings.HasPrefix(entries[0].Record.From, "person:") {
		t.Fatalf("the opening is not a person's: %s", entries[0].Record.From)
	}
}

// When a machine is tied to its signer after it was granted, its grant is
// re-issued to say so and the one that named nobody is withdrawn.
func TestTyingAMachineToItsSignerReissuesItsGrant(t *testing.T) {
	w := newTalkWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := w.s.bindSigner(g.ControllerAID, talkSigner)
	if err != nil {
		t.Fatal(err)
	}
	if bound.CredentialSAID == "" || bound.CredentialSAID == granted.CredentialSAID {
		t.Fatal("the machine's grant was not re-issued when its signer was settled")
	}
	attrs, _ := acdcOf(t, w.s, bound.CredentialSAID)["a"].(map[string]interface{})
	if attrs["signer"] != talkSigner {
		t.Fatalf("the re-issued grant does not name the signer: %v", attrs["signer"])
	}
	if got := statusOf(t, w.s, granted.CredentialSAID); got != keri.StatusRevoked {
		t.Fatalf("the grant that named nobody still stands: %q", got)
	}
}

func credentialsOf(t *testing.T, s *CoreServer, holder string) []store.CredentialRecord {
	t.Helper()
	all, _ := s.DataStore.GetCredentials()
	var out []store.CredentialRecord
	for _, c := range all {
		if c.HolderAID == holder {
			out = append(out, c)
		}
	}
	return out
}

func testOwnerSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// A request the identity's own key signed is kept as the authority, and the
// credential rests on it.
func TestAnOwnersSignedRequestIsKeptAsTheAuthority(t *testing.T) {
	w := newTalkWorld(t)
	resetSeenSignatures(t)
	req := signed(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities", `{"capabilities":["`+capabilityMessageAgent+`"]}`, testOwnerSeed(), time.Now())
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner's change: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		GrantSAID string `json:"grant_said"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	attrs, _ := acdcOf(t, w.s, out.GrantSAID)["a"].(map[string]interface{})
	r, _ := attrs["request"].(map[string]interface{})
	if r["kind"] != "owner" || r["body"] == "" {
		t.Fatalf("the owner's request is not kept as the authority: %v", attrs["request"])
	}
}

// A credential that does not rest on the request it carries is not issued.
func TestACredentialThatDoesNotRestOnItsRequestIsNotIssued(t *testing.T) {
	w := newTalkWorld(t)
	before := 0
	for _, c := range credentialsOf(t, w.s, w.a.PairwiseAID) {
		if isUsableStatus(c.Status) {
			before++
		}
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	bogus := authority{Request: &signedRequest{Kind: "owner", Signer: "EOWNERTESTAID", Body: `{"capabilities":[]}`,
		Signed:    canonicalRequestString("PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities", stamp, []byte(`{"capabilities":[]}`)),
		Signature: "0Bnot-a-signature"}, About: w.a.ID}
	if _, err := w.s.issueCapabilityGrant(w.a, bogus); err == nil {
		t.Fatal("a grant resting on a request nobody signed was issued")
	}
	after := 0
	for _, c := range credentialsOf(t, w.s, w.a.PairwiseAID) {
		if isUsableStatus(c.Status) {
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
	s, agent := grantWorld(t)
	early, err := s.issueAssetCredential(schemas.AIAgentGrantV1, agent.PairwiseAID, agent.DelegatorAID,
		map[string]interface{}{"name": "early", "capabilities": []string{}}, "", authority{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueCapabilityGrant(agent, authority{}); err != nil {
		t.Fatal(err)
	}
	late, err := s.issueAssetCredential(schemas.AIAgentGrantV1, agent.PairwiseAID, agent.DelegatorAID,
		map[string]interface{}{"name": "late", "capabilities": []string{}}, "", authority{})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := s.DataStore.GetCredential(early)
	l, _ := s.DataStore.GetCredential(late)
	if s.issuedUnderFirstVersionTooLate(e) {
		t.Fatal("a first-version grant issued before the change was refused")
	}
	if !s.issuedUnderFirstVersionTooLate(l) {
		t.Fatal("a first-version grant issued after the change was honoured")
	}
	if s.grantCredentialValid(l, mcpToken{AgentAID: agent.PairwiseAID, DelegatorAID: agent.DelegatorAID}) {
		t.Fatal("the gateway honoured a first-version grant issued after the change")
	}
}

// Machines paired before machines were given grants are given one at start.
func TestMachinesPairedEarlierAreGivenGrants(t *testing.T) {
	s, _ := grantWorld(t)
	s.DeclaredEntityType = "organization"
	g := aGrant(GradeEnrolled)
	if _, err := s.controllers().Grant(g, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.prepareKeyLogs()
	got, _, _ := s.controllers().Get(g.ControllerAID)
	if got.CredentialSAID == "" {
		t.Fatal("a machine paired earlier was not given a grant")
	}
	if statusOf(t, s, got.CredentialSAID) != keri.StatusIssued {
		t.Fatal("the grant given is not in force")
	}
}

// Settling a machine's signer, when its grant cannot be re-issued, changes
// nothing and is tried again next time.
func TestSettlingASignerIsTriedAgainWhenItsGrantCannotBeReissued(t *testing.T) {
	w := newTalkWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	engine := w.s.KeriDriver
	w.s.KeriDriver = nil
	if _, err := w.s.bindSigner(g.ControllerAID, talkSigner); err == nil {
		t.Fatal("a signer was settled with no grant to say so")
	}
	if now, _, _ := w.s.controllers().Get(g.ControllerAID); now.Signer != "" || now.CredentialSAID != granted.CredentialSAID {
		t.Fatalf("a failed settling changed the grant: %+v", now)
	}
	w.s.KeriDriver = engine
	bound, err := w.s.bindSigner(g.ControllerAID, talkSigner)
	if err != nil || bound.Signer != talkSigner || bound.CredentialSAID == granted.CredentialSAID {
		t.Fatalf("settling the signer again: %+v %v", bound, err)
	}
}

// Granting a machine again replaces its grant and withdraws the earlier one;
// a re-grant that fails leaves the earlier one in force.
func TestReGrantingAMachine(t *testing.T) {
	s, _ := grantWorld(t)
	g := aGrant(GradeEnrolled)
	first, err := s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if second.CredentialSAID == first.CredentialSAID || statusOf(t, s, first.CredentialSAID) != keri.StatusRevoked {
		t.Fatal("a re-grant left the earlier grant in force")
	}
	engine := s.KeriDriver
	s.KeriDriver = nil
	if _, err := s.grantController(g, time.Now().UTC()); err == nil {
		t.Fatal("a re-grant with nothing to anchor it in succeeded")
	}
	s.KeriDriver = engine
	if now, _, _ := s.controllers().Get(g.ControllerAID); now.CredentialSAID != second.CredentialSAID {
		t.Fatal("a failed re-grant replaced the grant in force")
	}
	if statusOf(t, s, second.CredentialSAID) != keri.StatusIssued {
		t.Fatal("a failed re-grant withdrew the grant in force")
	}
}

// A re-grant whose earlier grant cannot be withdrawn changes nothing, so a
// machine never has two grants in force.
func TestAMachineNeverHasTwoGrantsInForce(t *testing.T) {
	s, _ := grantWorld(t)
	g := aGrant(GradeEnrolled)
	first, err := s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.DeleteCredential(first.CredentialSAID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.grantController(g, time.Now().UTC()); err == nil {
		t.Fatal("a machine was re-granted while its earlier grant could not be withdrawn")
	}
	for _, c := range credentialsOf(t, s, g.ControllerAID) {
		if isUsableStatus(c.Status) {
			t.Fatalf("the new grant %s was left in force beside the earlier one", c.SAID)
		}
	}
	if now, _, _ := s.controllers().Get(g.ControllerAID); now.CredentialSAID != first.CredentialSAID {
		t.Fatal("the grant on record changed")
	}
}

// Where the identity's key is held elsewhere, a machine is recorded with its
// grant pending on that device, and nothing is written into the key log.
func TestAMachineIsGrantedWithItsCredentialPendingWhereTheKeyIsElsewhere(t *testing.T) {
	s, _ := grantWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	elsewhere, _ := keri.GenerateSigner(true)
	owner.PublicKey, _ = elsewhere.PublicKey()
	s.DataStore.SaveIdentity(*owner)
	g, err := s.grantController(aGrant(GradeEnrolled), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !g.CredentialPending || g.CredentialSAID != "" {
		t.Fatalf("the grant is not marked pending: %+v", g)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written into a key log whose key is elsewhere")
	}
}

// A machine whose grant has been withdrawn, or is not yet anchored,
// authorises nothing.
func TestAMachineWithoutAGrantInForceAuthorisesNothing(t *testing.T) {
	w := newTalkWorld(t)
	asked := 0
	put := func() int {
		// Each request its own, so none is refused as one already used.
		asked++
		req := asThatMachine(t, w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
			`{"capabilities":["`+capabilityMessageAgent+`"]}`, w.ctlSeed, authprovider.LevelVerified,
			time.Now().Add(-time.Duration(asked)*time.Second))
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, req)
		return rec.Code
	}
	ctl, _, _ := w.s.controllers().Get(w.ctlAID)
	unanchored := ctl
	unanchored.CredentialSAID = ""
	w.s.controllers().Put(unanchored)
	if code := put(); code != http.StatusForbidden {
		t.Fatalf("a machine whose grant is not anchored was answered %d", code)
	}
	w.s.controllers().Put(ctl)
	if err := w.s.withdrawControllerGrant(ctl.CredentialSAID); err != nil {
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
	req := asThatMachine(t, w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/capabilities",
		`{"capabilities":[]}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	grant, _, _ := w.s.controllers().Get(w.ctlAID)
	req = req.WithContext(context.WithValue(req.Context(), controllerContextKey{}, grant))
	_, held, err := w.s.authorityOf(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { w.s.revokeController(w.ctlAID); close(done) }()
	select {
	case <-done:
		t.Fatal("the grant was revoked while a credential was being issued on it")
	case <-time.After(100 * time.Millisecond):
	}
	held()
	<-done
}

// A browser session can issue no authority over an AI agent.
func TestASessionIssuesNoAuthority(t *testing.T) {
	for _, route := range []string{"POST /api/mcp/agents", "PUT /api/mcp/agents/{id}/capabilities", "POST /api/mcp/agents/{id}/bodies/{bid}/approve"} {
		if _, refused := sessionForbidden[route]; !refused {
			t.Fatalf("a browser session may reach %s", route)
		}
	}
}

// Settling a signer when the machine's earlier grant cannot be withdrawn
// changes nothing and leaves no second grant in force.
func TestSettlingASignerNeverLeavesTwoGrantsInForce(t *testing.T) {
	w := newTalkWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.s.DataStore.DeleteCredential(granted.CredentialSAID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.bindSigner(g.ControllerAID, talkSigner); err == nil {
		t.Fatal("a signer was settled while the earlier grant could not be withdrawn")
	}
	for _, c := range credentialsOf(t, w.s, g.ControllerAID) {
		if isUsableStatus(c.Status) {
			t.Fatalf("the re-issued grant %s was left in force", c.SAID)
		}
	}
	if now, _, _ := w.s.controllers().Get(g.ControllerAID); now.Signer != "" || now.CredentialSAID != granted.CredentialSAID {
		t.Fatalf("the grant on record changed: %+v", now)
	}
}

// An AI agent provisioned from a machine is granted on the request, and the
// grant, which anybody can fetch, keeps what was asked for and nothing else
// the request carried: no prompt, no model address, no stored key's name.
func TestAPublishedGrantCarriesNoPrivateConfiguration(t *testing.T) {
	w := newTalkWorld(t)
	body := `{"name":"Ledger clerk","capabilities":["` + capabilityMessageAgent + `"],"system_prompt":"SECRET-PROMPT",` +
		`"brain":{"kind":"local","model":"m","endpoint":"http://10.0.0.9:1234","credential_ref":"vault-key-7"},"nonce":"n-1"}`
	req := asThatMachine(t, w.ctlAID, "POST", "/api/mcp/agents", body, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
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
	w.s.router.ServeHTTP(pub, remote("GET", "/public/credential/"+said, ""))
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
	attrs, _ := acdcOf(t, w.s, said)["a"].(map[string]interface{})
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
	resetSeenSignatures(t)
	body := `{"capabilities":["` + capabilityMessageAgent + `"]}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/mcp/agents/" + w.a.ID + "/capabilities"
	sig, _ := SignOwnerRequest("PUT", path, stamp, []byte(body), testOwnerSeed())
	by := authority{About: w.a.ID, Request: &signedRequest{Kind: "owner", Signer: "EOWNERTESTAID", Body: body,
		Signed: canonicalRequestString("PUT", path, stamp, []byte(body)), Signature: sig}}
	if _, err := w.s.issueCapabilityGrant(w.a, by); err != nil {
		t.Fatalf("the first credential on the request: %v", err)
	}
	held := len(credentialsOf(t, w.s, w.a.PairwiseAID))
	if _, err := w.s.issueCapabilityGrant(w.a, by); err == nil {
		t.Fatal("one request authorised a second credential")
	}
	if now := len(credentialsOf(t, w.s, w.a.PairwiseAID)); now != held {
		t.Fatal("a second credential was issued on the request before being refused")
	}
}

// Where grants can be issued, an AI agent whose grant cannot be issued is not
// created, and no token is minted for it.
func TestAnAIAgentWhoseGrantCannotBeIssuedIsNotCreated(t *testing.T) {
	w := newTalkWorld(t)
	resetSeenSignatures(t)
	// The owner's request, its digest already spent on another credential, so
	// the grant it asks for is refused while everything before it succeeds.
	body := `{"name":"Ungranted","capabilities":["` + capabilityMessageAgent + `"]}`
	at := time.Now()
	req := signed(t, "POST", "/api/mcp/agents", body, testOwnerSeed(), at)
	spent := canonicalRequestString("POST", "/api/mcp/agents", at.UTC().Format(time.RFC3339), []byte(body))
	if err := w.s.DataStore.KeepCredentialRequest("Eanother-credential", iacrypto.Blake3QB64Must([]byte(spent)), body); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("an AI agent with no grant was created: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range w.s.assetHandler.Store.ListAssets() {
		if a.DisplayName == "Ungranted" {
			t.Fatal("the AI agent was left in place")
		}
	}
	if w.s.anMCPTokenIsNamed("Ungranted") {
		t.Fatal("a token was minted for it")
	}
}

// A request carrying a signature that does not hold creates no AI agent and
// mints no token.
func TestABadlySignedRequestCreatesNoAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	req := local("POST", "/api/mcp/agents", `{"name":"Unwanted","capabilities":[]}`)
	req.Header.Set(headerOwnerSig, "0Bjunk")
	req.Header.Set(headerOwnerTimestamp, time.Now().UTC().Format(time.RFC3339))
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("a badly signed request created an AI agent: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range w.s.assetHandler.Store.ListAssets() {
		if a.DisplayName == "Unwanted" {
			t.Fatal("the AI agent was left in place")
		}
	}
	if w.s.anMCPTokenIsNamed("Unwanted") {
		t.Fatal("a token was minted for it")
	}
}

// Where grants can be issued, an AI agent's token with no grant may do nothing.
func TestAnAIAgentWithNoGrantMayDoNothing(t *testing.T) {
	s, agent := grantWorld(t)
	cc := sandbox.CallerContext{Scopes: []string{"system.info.read"}}
	s.applyGrantScopes(mcpToken{AgentAID: agent.PairwiseAID, DelegatorAID: agent.DelegatorAID}, &cc)
	if len(cc.Scopes) != 0 {
		t.Fatalf("an AI agent with no grant kept %v", cc.Scopes)
	}
}

// An individual's Identity Agent holding no AI agent gives earlier machines no
// grants, so writes nothing into its key log at start.
func TestAnIndividualWithNoAIAgentIsNotBackFilled(t *testing.T) {
	s, _ := grantWorld(t)
	s.DeclaredEntityType = "individual"
	g := aGrant(GradeEnrolled)
	s.controllers().Grant(g, time.Now().UTC())
	s.prepareKeyLogs()
	if got, _, _ := s.controllers().Get(g.ControllerAID); got.CredentialSAID != "" {
		t.Fatal("an individual with no AI agent was given a grant credential at start")
	}
}

// A back-fill that failed is tried again on the next anchoring tick.
func TestABackFillIsTriedAgain(t *testing.T) {
	s, _ := grantWorld(t)
	s.DeclaredEntityType = "organization"
	g := aGrant(GradeEnrolled)
	s.controllers().Grant(g, time.Now().UTC())
	was := anchorInterval
	anchorInterval = 20 * time.Millisecond
	t.Cleanup(func() { anchorInterval = was })
	stop := make(chan struct{})
	go s.keepAnchoring(stop)
	defer close(stop)
	for i := 0; i < 100; i++ {
		if got, _, _ := s.controllers().Get(g.ControllerAID); got.CredentialSAID != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a machine with no grant was not given one on a later tick")
}
