package server

import (
	"encoding/json"
	"testing"
	"time"

	"identity-agent-core/didcomm"
)

// The rate bound is global on purpose: a sender identity is free to invent, so
// counting per-sender counts nothing.
func TestStrangersAreBoundedByRate(t *testing.T) {
	firstContact.Lock()
	firstContact.seen = nil
	firstContact.Unlock()

	now := time.Now()
	allowed := 0
	for i := 0; i < firstContactBurst+3; i++ {
		if allowFirstContactAttempt(now) {
			allowed++
		}
	}
	if allowed != firstContactBurst {
		t.Fatalf("allowed %d introductions in one window, want %d", allowed, firstContactBurst)
	}

	// The window moves on, and so does the allowance.
	if !allowFirstContactAttempt(now.Add(firstContactWindow + time.Second)) {
		t.Fatal("the bound never releases, so an agent could be locked out permanently by a flood")
	}
}

// A history that does not check out establishes nothing, so nothing may be read
// out of it.
func TestAnUnsoundKeyHistoryIdentifiesNobody(t *testing.T) {
	s := witnessWithSeed(t, 1)
	s.KeriDriver = nil // cannot check a history at all
	if _, err := s.identifyStranger("EStranger", []map[string]interface{}{{"t": "icp"}}); err == nil {
		t.Fatal("a stranger was identified without their history being checked")
	}
}

func TestNoKeyHistoryIdentifiesNobody(t *testing.T) {
	s := witnessWithSeed(t, 1)
	if _, err := s.identifyStranger("EStranger", nil); err == nil {
		t.Fatal("a stranger was identified having presented nothing")
	}
}

// An envelope with nothing presented is left to the ordinary refusal. This
// matters: the first-contact path must not become a second way in for senders
// who are simply unknown.
func TestAnEnvelopeWithNoProofIsNotHandledHere(t *testing.T) {
	s := witnessWithSeed(t, 1)
	if s.tryFirstContact(nil, nil, "EStranger", &didcomm.Envelope{}) {
		t.Fatal("an envelope carrying no key history was handled as a first contact")
	}
}

// A repeat request must not reset a contact the owner has already judged —
// including one they turned down.
func TestARepeatRequestDoesNotDisturbAJudgedContact(t *testing.T) {
	s := witnessWithSeed(t, 1)
	const aid = "EPersistentStranger"

	if err := s.recordConnectionRequest(aid, &didcomm.JWM{
		Type: didcomm.TypeContactRequest,
		Body: json.RawMessage(`{"alias":"first try"}`),
	}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetContact(aid)
	if rec == nil || rec.Status != "pending_inbound" {
		t.Fatalf("a proven stranger was not recorded as awaiting a decision: %+v", rec)
	}

	// The owner turns them down.
	rec.Status = "rejected"
	if err := s.DataStore.SaveContact(*rec); err != nil {
		t.Fatal(err)
	}

	// They ask again.
	if err := s.recordConnectionRequest(aid, &didcomm.JWM{
		Type: didcomm.TypeContactRequest,
		Body: json.RawMessage(`{"alias":"second try"}`),
	}); err != nil {
		t.Fatal(err)
	}
	again, _ := s.DataStore.GetContact(aid)
	if again == nil || again.Status != "rejected" {
		t.Fatalf("asking again undid the owner's decision: %+v", again)
	}
}

// Identifying yourself is not being agreed to. A request must never land in a
// state anything downstream treats as a relationship.
func TestAProvenStrangerIsNotAccepted(t *testing.T) {
	s := witnessWithSeed(t, 1)
	const aid = "EProvenButUnwelcome"
	if err := s.recordConnectionRequest(aid, &didcomm.JWM{
		Type: didcomm.TypeContactRequest,
		Body: json.RawMessage(`{"alias":"hello"}`),
	}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetContact(aid)
	if rec == nil {
		t.Fatal("no request was recorded")
	}
	if rec.Status == "accepted" || rec.Status == "verified" {
		t.Fatalf("a stranger who proved their name was treated as agreed to: %q", rec.Status)
	}
	// And no peer was registered, so nothing can be sent to them yet.
	if _, known := s.loadPeers()[aid]; known {
		t.Fatal("a stranger was registered as a peer before the owner agreed to anything")
	}
}
