package witness

import (
	"testing"

	"identity-agent-core/store"
)

// One witness is one receipt per event, however often it arrives: a repeat
// must not move the count, or a single witness could reach the threshold alone.
func TestOneWitnessCannotReachTheThresholdAlone(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EOnceEvent0123456789ABCDEFGHIJKLMNOPQRSTUVWX"
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: "ERoot", State: FinalizePending, Threshold: 2, StartedAt: now, UpdatedAt: now})

	for i := 0; i < 5; i++ {
		s.onReceipt(said, "EWitnessOne", "", nil, nil)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("one witness counted %d times, state %s", f.ReceiptCount, f.State)
	}
	s.onReceipt(said, "EWitnessTwo", "", nil, nil)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 2 || f.State != FinalizeFinalized {
		t.Fatalf("a second witness was not counted: %d, %s", f.ReceiptCount, f.State)
	}
}

// Each of the two safeguards is enough on its own. The first: a receipt from a
// witness already held is not kept a second time, whatever counts the receipts.
func TestAWitnessAlreadyHeldIsNotKeptAgain(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EKeptOnce0123456789ABCDEFGHIJKLMNOPQRSTUVWXY"
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: "ERoot", State: FinalizePending, Threshold: 2, StartedAt: now, UpdatedAt: now})
	for i := 0; i < 3; i++ {
		s.onReceipt(said, "EWitnessOne", "", nil, nil)
	}
	if held, _ := kc.GetWitnessReceipts(said); len(held) != 1 {
		t.Fatalf("one witness's receipt was kept %d times", len(held))
	}
}

// The second: the count is of distinct witnesses among the receipts kept, so a
// witness kept twice (by a store that does not refuse it) is still one.
func TestTheCountIsOfDistinctWitnessesAmongTheReceiptsKept(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "ECountedOnce0123456789ABCDEFGHIJKLMNOPQRSTUV"
	for i := 0; i < 3; i++ {
		_ = kc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: "EWitnessOne", CesrSignature: "s"})
	}
	if n := s.storedReceiptCount(said); n != 1 {
		t.Fatalf("one witness kept three times counted %d", n)
	}
	f := &FinalizationState{EventSAID: said, Threshold: 2}
	s.settle(f)
	if f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("settled at %d, %s", f.ReceiptCount, f.State)
	}
}
