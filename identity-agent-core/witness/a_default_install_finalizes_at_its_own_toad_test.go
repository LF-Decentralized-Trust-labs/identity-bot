package witness

import (
	"testing"
	"time"
)

// A default install designates three witnesses and records a toad of 2. Two
// receipts finalize the event: it is not timed out against the cap's majority.
func TestADefaultThreeWitnessInstallFinalizesWithTwoReceipts(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	// Stored as the cap's majority, as a send made against the config would.
	s.begin(said, theAID, 0, s.Threshold(), icp)
	if s.Threshold() != 5 {
		t.Fatalf("test needs the default install's threshold of 5, got %d", s.Threshold())
	}
	for _, i := range []int{0, 1} {
		if err := s.receive(said, w.keys[i], w.receipt(w.keys[i], said), icp); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := s.Store.GetFinalization(said)
	if f == nil || f.State != FinalizeFinalized || f.Threshold != 2 {
		t.Fatalf("finalization %+v, want finalized at the log's toad of 2", f)
	}

	old := finalizeWait
	finalizeWait = time.Millisecond
	defer func() { finalizeWait = old }()
	s.finalizeLoop(said)
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizeFinalized {
		t.Fatalf("state %s after the wait, want finalized", f.State)
	}
}

// One receipt of three is short of the toad of 2 and does time out.
func TestOneReceiptOfTwoRequiredStillTimesOut(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 5, icp)
	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
		t.Fatal(err)
	}
	old := finalizeWait
	finalizeWait = time.Millisecond
	defer func() { finalizeWait = old }()
	s.finalizeLoop(said)
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizeTimeout {
		t.Fatalf("state %s, want timeout", f.State)
	}
}

// A configured threshold raises the toad only as far as witnesses are designated.
func TestAConfiguredThresholdOnlyRaisesWhereTheLogAllows(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	s.KeyLogOf = keyLog(theAID, icp)
	row, err := s.witnessing(theAID, saidOf(icp), nil)
	if err != nil {
		t.Fatal(err)
	}
	for cfg, want := range map[string]int{"5": 2, "3": 3, "9": 3, "1": 2} {
		_ = s.Store.SetConfig("threshold", cfg)
		if got := s.thresholdFor(row); got != want {
			t.Errorf("configured %s: threshold %d, want %d", cfg, got, want)
		}
	}
}
