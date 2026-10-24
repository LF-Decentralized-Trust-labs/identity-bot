package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

const (
	askerAID   = "EAsker000000000000000000000000000000000000001"
	witnessAID = "EWitness0000000000000000000000000000000000002"
)

// asked is an agent that has sent a witness request to a contact whose key it
// resolved, and that contact's signing seed.
func asked(t *testing.T) (*Service, *memContacts, []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{
			witnessAID: {AID: witnessAID, Status: "accepted", ContactCategory: "trusted", PublicKey: iacrypto.VerkeyQB64(pub)},
		},
		identity: &store.IdentityState{AID: askerAID},
		tasks: []store.TaskRecord{{
			ID: "sent", Type: "witness_request_sent", Status: "pending", ContactAID: witnessAID,
			CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
		}},
	}
	return agentService(t, askerAID, mc), mc, priv.Seed()
}

// nothingChanged fails if aid became a witness, gained witness state, or the
// request to the witness stopped waiting.
func nothingChanged(t *testing.T, s *Service, mc *memContacts, aid string) {
	t.Helper()
	if c, _ := mc.GetContact(aid); c != nil && c.IsWitness {
		t.Fatalf("%s was enrolled as a witness", aid)
	}
	if meta, _ := s.Store.GetContactMeta(aid); meta != nil {
		t.Fatalf("witness state was written for %s: %+v", aid, meta)
	}
	if task, _ := s.pendingSentTask(witnessAID); task == nil {
		t.Fatal("the request to the witness is no longer waiting for its real answer")
	}
}

func TestAnUnsignedAnswerChangesNothing(t *testing.T) {
	s, mc, _ := asked(t)
	cb := AcceptCallback{RequesterAID: askerAID, ResponderAID: witnessAID, Decision: "accepted", BackendType: BackendDesktop}
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
	s, mc, _ := asked(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, "accepted", other.Seed(), time.Now())); err == nil {
		t.Fatal("an answer signed by another key was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// The attack as it was: a stranger answers a request nobody sent it, naming
// the victim as the requester, and became a trusted contact and a witness.
func TestAnAnswerFromAStrangerCreatesNoContact(t *testing.T) {
	s, mc, _ := asked(t)
	stranger := "EStranger00000000000000000000000000000000003"
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ApplyAcceptCallback(answerFrom(stranger, askerAID, "accepted", priv.Seed(), time.Now())); err == nil {
		t.Fatal("an answer from somebody who was never asked was acted on")
	}
	if c, _ := mc.GetContact(stranger); c != nil {
		t.Fatalf("the stranger was added as a contact: %+v", c)
	}
	nothingChanged(t, s, mc, stranger)
}

func TestAnAnswerNobodyAskedForChangesNothing(t *testing.T) {
	s, mc, seed := asked(t)
	mc.tasks = nil
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, "accepted", seed, time.Now())); err == nil {
		t.Fatal("an answer to a request that was never sent was acted on")
	}
	if c, _ := mc.GetContact(witnessAID); c != nil && c.IsWitness {
		t.Fatal("an unsolicited answer enrolled a witness")
	}
}

func TestAStaleAnswerChangesNothing(t *testing.T) {
	s, mc, seed := asked(t)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, "accepted", seed, time.Now().Add(-time.Hour))); err == nil {
		t.Fatal("an hour-old answer was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// The witness's own answer is acted on once. Sent again, it is refused, even
// after the agent has asked the same witness again.
func TestAGenuineAnswerIsActedOnOnce(t *testing.T) {
	s, mc, seed := asked(t)
	cb := answerFrom(witnessAID, askerAID, "accepted", seed, time.Now())
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
	s, mc, seed := asked(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, "declined", other.Seed(), time.Now())); err == nil {
		t.Fatal("a decline signed by another key was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
	if err := s.ApplyAcceptCallback(answerFrom(witnessAID, askerAID, "declined", seed, time.Now())); err != nil {
		t.Fatalf("the witness's own decline was refused: %v", err)
	}
	if task, _ := s.pendingSentTask(witnessAID); task != nil {
		t.Fatal("the witness's own decline did not close the request")
	}
}
