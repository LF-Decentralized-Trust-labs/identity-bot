package witness

import "testing"

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
