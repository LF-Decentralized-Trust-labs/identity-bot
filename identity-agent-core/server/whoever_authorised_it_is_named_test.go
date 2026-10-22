package server

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
	"identity-agent-core/schemas"

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
