package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"
)

// delegationWorld is an organisation whose key is held on another device, with
// an AI agent created by another AI agent, as the device is asked for the
// agent's approval and then for its grant, which rests on a signed request.
func delegationWorld(t *testing.T) (*elsewhere, *asset.Asset, coretypes.Authority) {
	t.Helper()
	c := newCreator(t, []string{"agent.create", "agent.message.send"})
	anAddonIssuingAIAgentGrants(t)
	e := moveTheKeyElsewhere(t, c.s)
	a, by := c.asks(t, "Researcher", []string{"agent.message.send"})
	return e, a, by
}

// The AI agent exists and cannot act while its approval waits for the device
// that holds the key; nothing is written into the key log; the device is shown
// the identity it approves, read from the inception; and once it signs, the
// agent is let act, its approval is in a key log that verifies, and the grant
// asked for after it is asked of the device in its turn.
func TestAnAIAgentIsApprovedByTheDeviceThatHoldsTheKey(t *testing.T) {
	e, a, by := delegationWorld(t)
	owner, _ := e.s.DataStore.GetIdentity()
	before, _ := e.s.DataStore.GetEvents(owner.AID)
	if !a.ApprovalPending || a.PairwiseAID == "" || a.DelegatorAID != owner.AID {
		t.Fatalf("the agent is not waiting for its approval: %+v", a)
	}
	if ref, _ := e.s.lookupAgentAssetByAID(a.PairwiseAID); ref != nil {
		t.Fatal("an agent still waiting for its approval is found as one that acts")
	}
	if _, err := e.s.assetSigner(a.PairwiseAID); err == nil {
		t.Fatal("an agent still waiting for its approval is signed for")
	}
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindDelegation {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	shown, err := checkAsTheDevice(t, e.s, reqs[0])
	if err != nil {
		t.Fatalf("the device's check: %v", err)
	}
	if shown["kind"] != "delegation" || shown["holder"] != a.PairwiseAID || shown["issuer"] != owner.AID ||
		shown["key_fingerprint"] == "" || !strings.Contains(reqs[0].Summary, a.PairwiseAID) {
		t.Fatalf("the device is shown %v under %q", shown, reqs[0].Summary)
	}
	// The grant asked for now is kept behind the approval, not before it.
	if _, err := e.s.issueCapabilityGrant(a, by); err == nil || len(waiting(t, e.s)) != 1 {
		t.Fatalf("the grant asked for beside the approval: %v, %d waiting", err, len(waiting(t, e.s)))
	}
	if after, _ := e.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written before the device signed")
	}

	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := e.s.assetHandler.Store.GetAsset(a.ID)
	if got.ApprovalPending {
		t.Fatal("the agent still waits after the device signed")
	}
	if ref, _ := e.s.lookupAgentAssetByAID(a.PairwiseAID); ref == nil {
		t.Fatal("an approved agent does not act")
	}
	keyLogVerifies(t, e.s)
	// The grant that waited behind the approval is now asked for, and is issued
	// when signed.
	next := waiting(t, e.s)
	if len(next) != 1 || (next[0].Kind != signingKindGrant && next[0].Kind != signingKindRegistry) {
		t.Fatalf("what is asked after the approval: %+v", next)
	}
	for len(next) == 1 {
		if rec := fulfil(t, e.s, next[0], e.seed); rec.Code != http.StatusOK {
			t.Fatalf("signing %s: %d %s", next[0].Kind, rec.Code, rec.Body.String())
		}
		next = waiting(t, e.s)
	}
	if held := e.s.credentialsHeldBy(a.PairwiseAID, schemas.AIAgentGrant.Schema.SAID, e.s.OwnerRootAID(), true); len(held) != 1 {
		t.Fatalf("%d grants are in force for the approved agent", len(held))
	}
	keyLogVerifies(t, e.s)
}

// A signature by another key approves nothing, and the agent still waits.
func TestAnApprovalSignedByAnotherKeyApprovesNothing(t *testing.T) {
	e, a, _ := delegationWorld(t)
	reqs := waiting(t, e.s)
	other := make([]byte, 32)
	other[0] = 9
	if rec := fulfil(t, e.s, reqs[0], other); rec.Code != http.StatusBadRequest {
		t.Fatalf("a signature by another key was answered %d", rec.Code)
	}
	if got, _, _ := e.s.assetHandler.Store.GetAsset(a.ID); !got.ApprovalPending {
		t.Fatal("an agent was let act on a wrong signature")
	}
	if len(waiting(t, e.s)) != 1 {
		t.Fatal("the request no longer waits")
	}
}

// An approval the device refuses removes the agent, and the grant kept behind
// it, without anything having been written to the key log.
func TestAnApprovalTheDeviceRefusesRemovesTheAgent(t *testing.T) {
	e, a, by := delegationWorld(t)
	_, _ = e.s.issueCapabilityGrant(a, by)
	req := waiting(t, e.s)[0]
	rec := refuseRequest(t, e.s, req.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("refusing: %d %s", rec.Code, rec.Body.String())
	}
	if _, held, _ := e.s.assetHandler.Store.GetAsset(a.ID); held {
		t.Fatal("an agent refused its approval is still held")
	}
	if len(e.s.waitingRows()) != 0 || len(waiting(t, e.s)) != 0 {
		t.Fatalf("something still waits for an agent that was refused: %d rows", len(e.s.waitingRows()))
	}
}

// An approval built on a key log that has moved on is built again and asked
// afresh, for the same agent.
func TestAStaleApprovalIsBuiltAgain(t *testing.T) {
	e, a, _ := delegationWorld(t)
	stale := waiting(t, e.s)[0]
	body, _, _ := e.s.DataStore.GetPendingIssuance(stale.ID)
	var p pendingIssuance
	if err := jsonUnmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	p.Delegation.Prior = "Ethe-key-log-moved-on"
	nb := jsonMarshal(p)
	recordDB(t, e.s).Exec(`UPDATE pending_issuances SET body=? WHERE signing_request_id=?`, nb, stale.ID)
	if rec := fulfil(t, e.s, stale, e.seed); rec.Code != http.StatusConflict {
		t.Fatalf("a stale approval was answered %d %s", rec.Code, rec.Body.String())
	}
	fresh := waiting(t, e.s)
	if len(fresh) != 1 || fresh[0].ID == stale.ID || fresh[0].Kind != signingKindDelegation {
		t.Fatalf("the stale approval was not asked for afresh: %+v", fresh)
	}
	if rec := fulfil(t, e.s, fresh[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the approval built again: %d %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := e.s.assetHandler.Store.GetAsset(a.ID); got.ApprovalPending || got.PairwiseAID != a.PairwiseAID {
		t.Fatalf("the agent after the second approval: %+v", got)
	}
	keyLogVerifies(t, e.s)
}

// Where the engine cannot build an approval to be signed elsewhere, making the
// agent is refused as it was, and nothing is stored.
func TestAnAgentIsRefusedWhereTheApprovalCannotBeAsked(t *testing.T) {
	s := appWorld(t)
	moveTheKeyElsewhere(t, s)
	s.assetHandler.KeriDriver = onlyTheBasicEngine{s.assetHandler.KeriDriver}
	if _, err := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil); !errors.Is(err, asset.ErrKeyElsewhere) {
		t.Fatalf("an agent where its approval cannot be asked: %v", err)
	}
	if _, err := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil); err == nil {
		t.Fatal("an agent was made where its approval cannot be asked")
	}
	if all, _ := s.assetHandler.Store.ListAssets(); len(all) != 0 {
		t.Fatalf("a refused agent was stored: %+v", all)
	}
}

// onlyTheBasicEngine hides what an engine can prepare, leaving the rest.
type onlyTheBasicEngine struct{ drivers.KeriEngine }

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
func jsonMarshal(v any) string            { b, _ := json.Marshal(v); return string(b) }

func refuseRequest(t *testing.T, s *CoreServer, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRefuseSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+id+"/refuse", strings.NewReader(`{}`), s), id))
	return rec
}

// Events an earlier version wrote without the key (an agent's approval, its
// grant) are set aside, not signed: the key log here is rewound to what the
// device holds, the grant is no longer in force, the agent waits for the
// approval it never had and the device is asked for it, and then nothing
// stands in the way of the device signing.
func TestUnsignedEventsAreDiscardedAndTheAgentIsAskedAfresh(t *testing.T) {
	anAddonIssuingAIAgentGrants(t)
	s := appWorld(t)
	a, err := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.issueCapabilityGrant(a, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	approval := -1
	for _, ev := range events {
		if strings.Contains(ev.EventJSON, a.PairwiseAID) {
			approval = ev.SequenceNumber
		}
	}
	if approval < 1 {
		t.Fatal("the agent's approval is not in the key log")
	}
	// What an earlier version left: from the approval on, no signatures.
	recordDB(t, s).Exec(`UPDATE kel SET cesr_signature = '', signatures = '' WHERE aid = ? AND seq_num >= ?`, owner.AID, approval)
	e := moveTheKeyElsewhere(t, s)
	if len(s.unsignedOwnEvents()) == 0 {
		t.Fatal("the fixture left nothing unsigned")
	}

	rec := httptest.NewRecorder()
	s.router = s.buildRouter()
	s.router.ServeHTTP(rec, local("POST", "/api/key-log/unsigned-events/discard", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("discarding: %d %s", rec.Code, rec.Body.String())
	}
	if left := s.unsignedOwnEvents(); len(left) != 0 {
		t.Fatalf("still unsigned: %v", left)
	}
	kept, _ := s.DataStore.GetEvents(owner.AID)
	if kept[len(kept)-1].SequenceNumber != approval-1 {
		t.Fatalf("the key log was rewound to place %d, want %d", kept[len(kept)-1].SequenceNumber, approval-1)
	}
	if aside, _ := s.DataStore.SupersededEvents(owner.AID); len(aside) == 0 {
		t.Fatal("what was discarded was deleted, not set aside")
	}
	keyLogVerifies(t, s)
	if c, _ := s.DataStore.GetCredential(grant); c == nil || c.Status != credentialStatusDiscarded {
		t.Fatalf("the grant the discarded events anchored is %+v", c)
	}
	if held := s.credentialsHeldBy(a.PairwiseAID, schemas.AIAgentGrant.Schema.SAID, s.OwnerRootAID(), true); len(held) != 0 {
		t.Fatal("a grant the key log no longer names is in force")
	}
	got, _, _ := s.assetHandler.Store.GetAsset(a.ID)
	if !got.ApprovalPending {
		t.Fatal("the agent whose approval was discarded can still act")
	}
	reqs := waiting(t, s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindDelegation {
		t.Fatalf("what the device is asked after the discard: %+v", reqs)
	}
	if rec := fulfil(t, s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := s.assetHandler.Store.GetAsset(a.ID); got.ApprovalPending {
		t.Fatal("the agent still waits after the device approved it")
	}
	keyLogVerifies(t, s)

	// Nothing to discard once none is unsigned; and where the key is held
	// here there is never anything to rewind.
	rec = httptest.NewRecorder()
	s.router.ServeHTTP(rec, local("POST", "/api/key-log/unsigned-events/discard", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"discarded":[]`) {
		t.Fatalf("discarding again: %d %s", rec.Code, rec.Body.String())
	}
}

// A key log whose unsigned event is followed by a signed one is not rewound by
// forgetting the events after it.
func TestASignedEventAfterAnUnsignedOneIsNotDiscarded(t *testing.T) {
	anAddonIssuingAIAgentGrants(t)
	s := appWorld(t)
	a, _ := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil)
	if _, err := s.issueCapabilityGrant(a, coretypes.Authority{}); err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	first := events[1].SequenceNumber
	recordDB(t, s).Exec(`UPDATE kel SET cesr_signature = '', signatures = '' WHERE aid = ? AND seq_num = ?`, owner.AID, first)
	moveTheKeyElsewhere(t, s)
	if _, err := s.discardUnsignedOwnEvents(); err == nil {
		t.Fatal("a log with a signed event after an unsigned one was rewound")
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(events) {
		t.Fatal("a refused discard changed the key log")
	}
}
