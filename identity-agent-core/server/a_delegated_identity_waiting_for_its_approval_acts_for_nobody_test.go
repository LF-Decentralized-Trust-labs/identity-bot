package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// expireTheApprovalRequest makes the request for the agent's approval one that
// is no longer open, as it is once its time has passed.
func expireTheApprovalRequest(t *testing.T, e *elsewhere) {
	t.Helper()
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindDelegation {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	reqs[0].Status = SigningStatusExpired
	if err := e.s.DataStore.SaveSigningRequest(reqs[0]); err != nil {
		t.Fatal(err)
	}
}

// An agent whose approval has not been signed is in no key log. Once nothing
// asks for that approval, nothing is issued to it, signed for it, or
// published of it.
func TestAnAgentWaitingForItsApprovalActsForNobody(t *testing.T) {
	e, a, by := delegationWorld(t)
	s := e.s
	owner, _ := s.DataStore.GetIdentity()
	expireTheApprovalRequest(t, e)

	if _, err := s.issueCapabilityGrant(a, by); !errors.Is(err, errApprovalPending) {
		t.Fatalf("a grant to an agent whose approval is not asked for: %v", err)
	}
	claims := map[string]interface{}{"name": a.DisplayName, "capabilities": []string{"agent.message.send"}}
	if _, err := s.issueAssetCredential(schemas.AIAgentGrant, a.PairwiseAID, owner.AID, claims, "", by); !errors.Is(err, errApprovalPending) {
		t.Fatalf("a credential to an agent whose approval is not asked for: %v", err)
	}
	if len(waiting(t, s)) != 0 || len(s.waitingRows()) != 1 {
		t.Fatal("something was asked of the device for an agent that is not approved")
	}
	if _, _, code, _ := s.createSignedAssetChallenge(a.ID, "https://site.example", nil, "", "https://agent.example"); code != 409 {
		t.Fatalf("a login challenge signed as an agent that is not approved: %d", code)
	}
	if key := s.publicDidWebsPubKey(a.PairwiseAID); key != "" {
		t.Fatalf("the key of an agent that is not in any key log is published: %q", key)
	}
	if _, err := s.heldKeySet(a.PairwiseAID); err == nil || !strings.Contains(err.Error(), "does not speak for") {
		t.Fatalf("the messaging keys of an agent that is not approved: %v", err)
	}
	if err := s.reviveAssetIdentity(*a); err == nil || !strings.Contains(err.Error(), "not revived") {
		t.Fatalf("an agent that is not approved was revived: %v", err)
	}
	if err := s.assetHandler.Store.UpsertAsset(*a); err != nil {
		t.Fatal(err)
	}

	// Asked for again, a grant is kept behind the approval, as it was.
	if err := s.askApprovalAgain(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueCapabilityGrant(a, by); errors.Is(err, errApprovalPending) {
		t.Fatalf("a grant asked for beside an approval that is asked for was refused: %v", err)
	}
}

// What an app is told of an agent still waiting names no identifier or address
// it could be reached at, and says it is waiting.
func TestWhatAnAppIsToldOfAnAgentThatWaitsSaysSo(t *testing.T) {
	e, a, _ := delegationWorld(t)
	got, _, _ := e.s.assetHandler.Store.GetAsset(a.ID)
	cfg := asset.SDKConfigOf(got)
	if cfg["APPROVAL_PENDING"] != "true" || cfg["SITE_PAIRWISE_AID"] != "" || cfg["SITE_OOBI"] != "" {
		t.Fatalf("what an agent that waits is configured with: %v", cfg)
	}
}

// An approval is let act only for the identity it approves, and is checked
// again against what the device was shown before anything is appended.
func TestAnApprovalKeptForAnotherIdentityReleasesNothing(t *testing.T) {
	e, a, _ := delegationWorld(t)
	s := e.s
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	body, _, _ := s.DataStore.GetPendingIssuance(waiting(t, s)[0].ID)
	reqID := waiting(t, s)[0].ID
	var kept pendingIssuance
	if err := json.Unmarshal([]byte(body), &kept); err != nil || kept.Delegation == nil {
		t.Fatalf("the approval kept: %v", err)
	}
	unchanged := func(why string) {
		t.Helper()
		if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(events) {
			t.Fatalf("%s: an event was appended", why)
		}
		if got, _, _ := s.assetHandler.Store.GetAsset(a.ID); !got.ApprovalPending {
			t.Fatalf("%s: the agent was let act", why)
		}
	}

	// Kept for an identifier that is not this agent's.
	other := kept
	d := *kept.Delegation
	d.AID = "EAnotherIdentity00000000000000000000000000000"
	other.Delegation = &d
	if err := s.completeDelegation(reqID, other, "sig"); err == nil || !strings.Contains(err.Error(), "not the identity") {
		t.Fatalf("an approval kept for another identifier: %v", err)
	}
	unchanged("another identifier")

	// An interaction that does not approve the inception it is kept with.
	wrong := kept
	d2 := *kept.Delegation
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: d2.Prior, SN: d2.SN,
		Data: []json.RawMessage{json.RawMessage(`{"d":"` + d2.DipSAID + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	d2.IxnRaw = ixn
	wrong.Delegation = &d2
	// Signed by the key, so nothing but the check of what it approves stops it.
	signed, _ := login.SignString(string(ixn), e.seed)
	if err := s.completeDelegation(reqID, wrong, signed); err == nil || !strings.Contains(err.Error(), "does not anchor what is shown") {
		t.Fatalf("an interaction that does not approve the inception: %v", err)
	}
	unchanged("an interaction that approves something else")
}

// The device is shown the name and kind this Identity Agent gave the identity,
// marked as its own words, and that approving it lets it do nothing yet.
func TestTheDeviceIsShownWhoIsBeingApproved(t *testing.T) {
	e, a, _ := delegationWorld(t)
	reqs := waiting(t, e.s)
	if len(reqs) != 1 {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	line := reqs[0].Summary
	for _, want := range []string{`"` + a.DisplayName + `"`, "AI agent", "this Identity Agent names", "can do nothing until its grant is signed"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the device is shown %q, which lacks %q", line, want)
		}
	}
	if strings.Contains(line, "act for you") {
		t.Fatalf("approving an identity is shown as letting it act: %q", line)
	}
}
