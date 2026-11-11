package witness

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"identity-agent-core/store"
)

// broadcastFrom is a service with one enrolled witness that receipts whatever
// it is sent, the rotation that is sent, and the means to see what was kept.
// The key log it reads is the one given: the inception that named the witness,
// and, when the rotation is in it, the rotation too.
func broadcastFrom(t *testing.T, log func(inception, rotation []byte) func(string) ([][]byte, error)) (*Service, *keepingContacts, []byte, string) {
	t.Helper()
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	w := witnessesOf(1)
	key := w.keys[0]
	// The witness is known by its own key, so the one that answers is the one asked.
	mc.contacts[key] = store.ContactRecord{AID: key, OobiURL: "http://w.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: key, WitnessKey: key, IsCommercial: true})
	icp := inceptionOf(theAID, []string{key}, 1)
	rot := rotationOf(theAID, 1, []string{key}, nil, 0)
	said := saidOf(rot)
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		if !strings.HasPrefix(url, "http://w.test/") {
			// The bootstrap witness a root is topped up with is not the one under test.
			return nil, errors.New("not answering")
		}
		return map[string]interface{}{"witness_aid": key, "cesr_signature": w.receipt(key, said)}, nil
	}
	s.KeyLogOf = log(icp, rot)
	t.Cleanup(func() { s.Stop() })
	return s, kc, rot, said
}

func inceptionOnly(icp, _ []byte) func(string) ([][]byte, error) { return keyLog(theAID, icp) }

func unreadable(_, _ []byte) func(string) ([][]byte, error) {
	return func(string) ([][]byte, error) { return nil, errors.New("damaged") }
}

func settled(kc *keepingContacts, wantKept int) {
	for i := 0; i < 100; i++ {
		kc.mu.Lock()
		n := len(kc.kept)
		kc.mu.Unlock()
		if n >= wantKept {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
}

// After a rotation that cuts every witness, the log's threshold is its own (0)
// and a cut witness's receipt is not in the list in force, so it is neither
// kept nor counted: not the floor, not an unchecked list.
func TestAfterACutAllRotationTheCutWitnessesReceiptsDoNotCount(t *testing.T) {
	s, kc, rot, said := broadcastFrom(t, inceptionOnly)
	if err := s.BroadcastEvent(context.Background(), theAID, rot, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	settled(kc, 1)
	f, _ := s.Store.GetFinalization(said)
	if f == nil || f.Threshold != 0 {
		t.Fatalf("finalization %+v, want the log's own threshold 0", f)
	}
	if f.ReceiptCount != 0 || len(kc.kept) != 0 {
		t.Fatalf("a cut witness's receipt was kept (%d) or counted (%d)", len(kc.kept), f.ReceiptCount)
	}
}

// A log that cannot be read: the receipt is kept and nothing is counted.
func TestAReceiptIsKeptButNotCountedWhenTheLogCannotBeRead(t *testing.T) {
	s, kc, rot, said := broadcastFrom(t, unreadable)
	if err := s.BroadcastEvent(context.Background(), theAID, rot, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	settled(kc, 1)
	kc.mu.Lock()
	kept := len(kc.kept)
	kc.mu.Unlock()
	f, _ := s.Store.GetFinalization(said)
	if kept != 1 {
		t.Fatalf("kept %d receipts, want 1", kept)
	}
	if f == nil || f.ReceiptCount != 0 || f.State == FinalizeFinalized {
		t.Fatalf("a receipt was counted against a list nobody could read: %+v", f)
	}
}

// The same for the one witness a caller submits to.
func TestSubmittingToAWitnessCountsNothingWhenTheLogCannotBeRead(t *testing.T) {
	s, kc, rot, said := broadcastFrom(t, unreadable)
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: theAID, State: FinalizePending, Threshold: 1, StartedAt: now, UpdatedAt: now})
	if _, err := s.SubmitToWitness(context.Background(), "http://w.test/witness/event", theAID, rot, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	if len(kc.kept) != 1 {
		t.Fatalf("kept %d receipts, want 1", len(kc.kept))
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 0 || f.State == FinalizeFinalized {
		t.Fatalf("counted against a list nobody could read: %+v", f)
	}
}

// And after a cut-all rotation a submitted receipt is refused outright: the
// list in force at the rotation is empty.
func TestSubmittingAfterACutAllRotationRefusesTheCutWitnessesReceipt(t *testing.T) {
	s, kc, rot, said := broadcastFrom(t, inceptionOnly)
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: theAID, State: FinalizePending, StartedAt: now, UpdatedAt: now})
	if _, err := s.SubmitToWitness(context.Background(), "http://w.test/witness/event", theAID, rot, "0Bsig"); err == nil {
		t.Fatal("the receipt of a witness the rotation cut was accepted")
	}
	if len(kc.kept) != 0 {
		t.Fatal("it was kept")
	}
}

// A receipt kept while the log could not be read is counted only as the log
// says once it can be read: when it has cut that witness, neither a recount nor
// the next broadcast of the event counts it.
func TestAReceiptKeptUnreadableIsNotCountedOnceTheLogHasCutItsWitness(t *testing.T) {
	s, kc, rot, said := broadcastFrom(t, unreadable)
	if err := s.BroadcastEvent(context.Background(), theAID, rot, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	settled(kc, 1)
	icp := inceptionOf(theAID, []string{kc.kept[0].WitnessAID}, 1)
	s.KeyLogOf = keyLog(theAID, icp, rot) // read now: every witness cut

	s.RecountReceipts(said)
	if f, _ := s.Store.GetFinalization(said); f == nil || f.ReceiptCount != 0 {
		t.Fatalf("a recount counted a cut witness: %+v", f)
	}
	// A broadcast again must not either. The log now asks no receipt (its own
	// threshold is 0), so the event is finalized on that, not on a count.
	s.begin(said, theAID, 1, 1, rot)
	if f, _ := s.Store.GetFinalization(said); f == nil || f.ReceiptCount != 0 || f.Threshold != 0 || f.State != FinalizeFinalized {
		t.Fatalf("a new broadcast counted a cut witness, or did not finalize on a log that asks for none: %+v", f)
	}
}
