package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

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

// When a machine is tied to its signer after it was granted, its grant is
// re-issued to say so and the one that named nobody is withdrawn.
func TestTyingAMachineToItsSignerReissuesItsGrant(t *testing.T) {
	w := newControllerWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{})
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

// Settling a machine's signer, when its grant cannot be re-issued, changes
// nothing and is tried again next time.
func TestSettlingASignerIsTriedAgainWhenItsGrantCannotBeReissued(t *testing.T) {
	w := newControllerWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{})
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
	first, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	if second.CredentialSAID == first.CredentialSAID || statusOf(t, s, first.CredentialSAID) != keri.StatusRevoked {
		t.Fatal("a re-grant left the earlier grant in force")
	}
	engine := s.KeriDriver
	s.KeriDriver = nil
	if _, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err == nil {
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
	first, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.DeleteCredential(first.CredentialSAID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err == nil {
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

// Settling a signer when the machine's earlier grant cannot be withdrawn
// changes nothing and leaves no second grant in force.
func TestSettlingASignerNeverLeavesTwoGrantsInForce(t *testing.T) {
	w := newControllerWorld(t)
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{})
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

func asJSON(v interface{}) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// Where the identity's key is another device's, issuing a grant writes nothing
// into its key log and says why, rather than appending an event nobody signed.
func TestAGrantIsNotIssuedUnsignedWhereTheKeyIsElsewhere(t *testing.T) {
	s, agent := grantWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	elsewhere, _ := keri.GenerateSigner(true)
	owner.PublicKey, _ = elsewhere.PublicKey()
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	before, _ := s.DataStore.GetEvents(owner.AID)
	if _, err := s.issueCapabilityGrant(agent, coretypes.Authority{About: agent.ID}); !errors.Is(err, errKeyElsewhere) && !errors.Is(err, errNeedsSignedRequest) {
		t.Fatalf("issuing where the key is elsewhere: %v", err)
	}
	// Asked for without a signed request, there is nothing to show the
	// device that holds the key as the authority for it: refused.
	if _, err := s.grantController(aGrant(GradeEnrolled), time.Now().UTC(), coretypes.Authority{}); err == nil {
		t.Fatal("a machine was granted, where the key is elsewhere, with no request behind it")
	}
	after, _ := s.DataStore.GetEvents(owner.AID)
	if len(after) != len(before) {
		t.Fatal("an event was written into a key log whose key is elsewhere")
	}
	for _, ev := range after {
		if ev.CesrSignature == "" {
			t.Fatalf("event %d of the identity's key log is unsigned", ev.SequenceNumber)
		}
	}
}

// A machine row added to the file is never granted without the owner either.
func TestAnAddedMachineRowIsNeverGrantedWithoutTheOwner(t *testing.T) {
	s, _ := grantWorld(t)
	s.DeclaredEntityType = "organization"
	g := aGrant(GradeEnrolled)
	s.controllers().Grant(g, time.Now().UTC())
	everythingRuns(s)
	if got, _, _ := s.controllers().Get(g.ControllerAID); got.CredentialSAID != "" || got.CredentialPending {
		t.Fatal("a machine row added to the file was given a grant")
	}
	if m, _ := awaiting(t, s); m[g.ControllerAID] != "the owner's approval" {
		t.Fatalf("the added machine is not listed as awaiting the owner: %v", m)
	}
}

// The owner approves an earlier machine by granting it again, signed: the
// grant names the owner's request and rests on it.
func TestTheOwnerApprovesAnEarlierMachine(t *testing.T) {
	w := newControllerWorld(t)
	resetSeenSignatures(t)
	ctl, _, _ := w.s.controllers().Get(w.ctlAID)
	earlier := ctl
	earlier.CredentialSAID = ""
	w.s.controllers().Put(earlier)
	body := `{"controller_aid":"` + ctl.ControllerAID + `","public_key":"` + ctl.PublicKey + `","label":"` + ctl.Label + `","grade":"` + string(ctl.Grade) + `"}`
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, signedFor(t, w.s.thisIdentityAgentsIdentifier(), "POST", "/api/controllers", body, testOwnerSeed(), time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner's approval: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := w.s.controllers().Get(w.ctlAID)
	if got.CredentialSAID == "" {
		t.Fatal("the approved machine has no grant")
	}
	req, _ := acdcOf(t, w.s, got.CredentialSAID)["a"].(map[string]interface{})["request"].(map[string]interface{})
	if req["kind"] != "owner" {
		t.Fatalf("the grant does not name the owner's request: %v", req)
	}
	if m, _ := awaiting(t, w.s); m[w.ctlAID] != "" {
		t.Fatal("the approved machine is still listed as awaiting")
	}
}

// The list of what awaits approval is served where the apps ask for it.
func TestTheApprovalListIsServed(t *testing.T) {
	w := newControllerWorld(t)
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, local("GET", "/api/grants/awaiting-approval", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"machines"`) {
		t.Fatalf("the approval list: %d %s", rec.Code, rec.Body.String())
	}
}

// A machine is granted as speaking for an active signer of the identity, or
// for none: never for somebody who is not one.
func TestAMachineSpeaksOnlyForAnActiveSigner(t *testing.T) {
	w := newControllerWorld(t)
	g := grantFor(7, GradeEnrolled)
	g.Signer = "ENotASigner0000000000000000000000000000000000"
	if _, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err == nil {
		t.Fatal("a machine was granted as speaking for somebody who is not a signer")
	}
	signers := w.s.signers()
	if len(signers) == 0 {
		t.Fatal("the world has no signer")
	}
	g.Signer = signers[0].AID
	if _, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err != nil {
		t.Fatalf("a machine speaking for an active signer: %v", err)
	}
}
