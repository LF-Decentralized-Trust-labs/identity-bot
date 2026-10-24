package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"identity-agent-core/store"
)

const (
	askerAID   = "EAsker000000000000000000000000000000000000001"
	witnessAID = "EWitness0000000000000000000000000000000000002"
)

// asked is an Identity Agent that has sent a witness request to a contact
// whose published witness key it holds, and that key and its seed.
func asked(t *testing.T) (*Service, *memContacts, string, []byte) {
	t.Helper()
	key, seed := witnessKey()
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{
			witnessAID: {AID: witnessAID, Status: "accepted", ContactCategory: "trusted"},
		},
		identity: &store.IdentityState{AID: askerAID},
		tasks: []store.TaskRecord{{
			ID: "sent", Type: "witness_request_sent", Status: "pending", ContactAID: witnessAID,
			CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
		}},
	}
	s := agentService(t, askerAID, mc)
	s.RecordContactCapability(witnessAID, BackendDesktop, key, "")
	return s, mc, key, seed
}

// nothingChanged fails if aid became a witness, gained witness state, or the
// request to the witness stopped waiting.
func nothingChanged(t *testing.T, s *Service, mc *memContacts, aid string) {
	t.Helper()
	if c, _ := mc.GetContact(aid); c != nil && c.IsWitness {
		t.Fatalf("%s was enrolled as a witness", aid)
	}
	if meta, _ := s.Store.GetContactMeta(aid); meta != nil && meta.EnrolledAt != "" {
		t.Fatalf("%s was enrolled: %+v", aid, meta)
	}
	if task, _ := s.pendingSentTask(witnessAID); task == nil {
		t.Fatal("the request to the witness is no longer waiting for its real answer")
	}
}

func TestAnUnsignedAnswerChangesNothing(t *testing.T) {
	s, mc, key, _ := asked(t)
	cb := AcceptCallback{RequesterAID: askerAID, ResponderAID: witnessAID, Decision: "accepted", BackendType: BackendDesktop, WitnessKey: key}
	if err := s.ApplyAcceptCallback(cb); err == nil {
		t.Fatal("an unsigned answer was acted on")
	}
	cb.Stamp = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.ApplyAcceptCallback(cb); err == nil {
		t.Fatal("a stamped but unsigned answer was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

func TestAnAnswerSignedByAnotherKeyChangesNothing(t *testing.T) {
	s, mc, key, _ := asked(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "accepted", other.Seed(), time.Now())); err == nil {
		t.Fatal("an answer signed by another key was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// The attack as it was: a stranger answers a request nobody sent it, naming
// the victim as the requester, and became a trusted contact and a witness.
func TestAnAnswerFromAStrangerCreatesNoContact(t *testing.T) {
	s, mc, _, _ := asked(t)
	stranger := "EStranger00000000000000000000000000000000003"
	skey, sseed := witnessKey()
	// Even with its witness key known, as if its OOBI had been resolved.
	s.RecordContactCapability(stranger, BackendDesktop, skey, "")
	if err := s.ApplyAcceptCallback(answerFrom(stranger, askerAID, skey, "accepted", sseed, time.Now())); err == nil {
		t.Fatal("an answer from somebody who was never asked was acted on")
	}
	if c, _ := mc.GetContact(stranger); c != nil {
		t.Fatalf("the stranger was added as a contact: %+v", c)
	}
	nothingChanged(t, s, mc, stranger)
}

func TestAnAnswerNobodyAskedForChangesNothing(t *testing.T) {
	s, mc, key, seed := asked(t)
	mc.tasks = nil
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "accepted", seed, time.Now())); err == nil {
		t.Fatal("an answer to a request that was never sent was acted on")
	}
	if c, _ := mc.GetContact(witnessAID); c != nil && c.IsWitness {
		t.Fatal("an unsolicited answer enrolled a witness")
	}
}

func TestAStaleAnswerChangesNothing(t *testing.T) {
	s, mc, key, seed := asked(t)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "accepted", seed, time.Now().Add(-time.Hour))); err == nil {
		t.Fatal("an hour-old answer was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// The witness's own answer is acted on once. Sent again, it is refused, even
// after the Identity Agent has asked the same witness again.
func TestAGenuineAnswerIsActedOnOnce(t *testing.T) {
	s, mc, key, seed := asked(t)
	cb := answerFrom(witnessAID, askerAID, key, "accepted", seed, time.Now())
	if err := s.ApplyAcceptCallback(cb); err != nil {
		t.Fatalf("the witness's own answer was refused: %v", err)
	}
	if c, _ := mc.GetContact(witnessAID); c == nil || !c.IsWitness {
		t.Fatal("the witness's own answer did not enrol it")
	}
	_ = mc.SaveTask(store.TaskRecord{
		ID: "again", Type: "witness_request_sent", Status: "pending", ContactAID: witnessAID,
		CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
	})
	if err := s.ApplyAcceptCallback(cb); err == nil {
		t.Fatal("a replayed answer was acted on")
	}
}

// A decline is the witness's to give too: an unsigned one does not close the
// request.
func TestAnUnsignedDeclineDoesNotCloseTheRequest(t *testing.T) {
	s, mc, key, seed := asked(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "declined", other.Seed(), time.Now())); err == nil {
		t.Fatal("a decline signed by another key was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "declined", seed, time.Now())); err != nil {
		t.Fatalf("the witness's own decline was refused: %v", err)
	}
	if task, _ := s.pendingSentTask(witnessAID); task != nil {
		t.Fatal("the witness's own decline did not close the request")
	}
}

// An answer under a witness key the responder never published is refused,
// even when that key really signed it.
func TestAnAnswerUnderAnUnpublishedWitnessKeyChangesNothing(t *testing.T) {
	s, mc, _, _ := asked(t)
	other, otherSeed := witnessKey()
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, other, "accepted", otherSeed, time.Now())); err == nil {
		t.Fatal("an answer under a witness key the responder never published was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// The witness answers on its own connection, so its answer can arrive before
// the request it answers has returned. It is still the answer to a request
// that was asked.
func TestAnAnswerArrivingBeforeTheRequestReturnsIsActedOn(t *testing.T) {
	key, seed := witnessKey()
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{
			witnessAID: {AID: witnessAID, Status: "accepted", ContactCategory: "trusted",
				OobiURL: "http://witness.example/public/oobi/" + witnessAID},
		},
		identity: &store.IdentityState{AID: askerAID},
	}
	s := agentService(t, askerAID, mc)
	s.RecordContactCapability(witnessAID, BackendDesktop, key, "")
	var answered error
	s.PostEvent = func(ctx context.Context, url string, body []byte) (map[string]interface{}, error) {
		answered = s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, key, "accepted", seed, time.Now()))
		return map[string]interface{}{"status": "accepted"}, nil
	}
	if err := s.SendWitnessRequest(context.Background(), witnessAID); err != nil {
		t.Fatal(err)
	}
	if answered != nil {
		t.Fatalf("an answer that arrived before the request returned was refused: %v", answered)
	}
	if c, _ := mc.GetContact(witnessAID); c == nil || !c.IsWitness {
		t.Fatal("the witness was not enrolled")
	}
}
