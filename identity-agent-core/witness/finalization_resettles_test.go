package witness

import (
	"errors"
	"testing"
	"time"
)

func quickFinalizeWait(t *testing.T) {
	old := finalizeWait
	finalizeWait = time.Millisecond
	t.Cleanup(func() { finalizeWait = old })
}

func unreadableLog(string) ([][]byte, error) { return nil, errors.New("damaged") }

// An event broadcast while its log could not be read (threshold 1 stored) has
// its kept receipts recounted against the log's toad when the wait ends, not
// timed out on the stale count.
func TestTheDeadlineRecountsReceiptsKeptWhileTheLogWasUnreadable(t *testing.T) {
	quickFinalizeWait(t)
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = unreadableLog
	s.begin(said, theAID, 0, 1, icp)
	for _, i := range []int{0, 1} {
		if err := s.receive(said, w.keys[i], w.receipt(w.keys[i], said), icp); err != nil {
			t.Fatal(err)
		}
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 0 {
		t.Fatalf("counted while the log could not be read: %+v", f)
	}
	s.KeyLogOf = keyLog(theAID, icp) // readable now, toad 2
	s.finalizeLoop(said)
	f, _ := s.Store.GetFinalization(said)
	if f.State != FinalizeFinalized || f.Threshold != 2 || f.ReceiptCount != 2 {
		t.Fatalf("receipts kept while unreadable were not recounted at the deadline: %+v", f)
	}
}

// A receipt kept from a witness the log has since cut does not finalize an
// event whose log still asks for a receipt from the witnesses that remain.
func TestACutWitnessesHeldReceiptDoesNotFinalizeWhenAnotherWitnessIsAsked(t *testing.T) {
	quickFinalizeWait(t)
	s, _ := testService(t)
	w := witnessesOf(2)
	icp := inceptionOf(theAID, w.keys, 1)
	rot := rotationOf(theAID, 1, []string{w.keys[0]}, nil, 1) // cuts w0, leaves w1, toad 1
	said := saidOf(rot)
	s.KeyLogOf = unreadableLog
	s.begin(said, theAID, 1, 1, rot)
	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), rot); err != nil {
		t.Fatal(err)
	}
	s.KeyLogOf = keyLog(theAID, icp, rot)
	s.finalizeLoop(said)
	f, _ := s.Store.GetFinalization(said)
	if f.State == FinalizeFinalized || f.ReceiptCount != 0 || f.Threshold != 1 {
		t.Fatalf("a cut witness's receipt finalized the event: %+v", f)
	}
	if f.State != FinalizeTimeout {
		t.Fatalf("state %s, want timeout", f.State)
	}
}

// A row stored before the threshold came from the log holds the cap's majority
// (5); the startup sweep settles it against the log's own toad.
func TestTheStartupSweepSettlesAnOldRowStoredAtThresholdFive(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	// Two valid receipts kept, then a row as the old code left it.
	s.begin(said, theAID, 0, 2, icp)
	for _, i := range []int{0, 1} {
		if err := s.receive(said, w.keys[i], w.receipt(w.keys[i], said), icp); err != nil {
			t.Fatal(err)
		}
	}
	old := FinalizationState{EventSAID: said, SignerAID: theAID, State: FinalizeTimeout, ReceiptCount: 2,
		Threshold: 5, StartedAt: NowRFC3339(), UpdatedAt: NowRFC3339()}
	if err := s.Store.SaveFinalization(old); err != nil {
		t.Fatal(err)
	}
	done := FinalizationState{EventSAID: "Edone", SignerAID: theAID, State: FinalizeFinalized, Threshold: 5, StartedAt: NowRFC3339(), UpdatedAt: NowRFC3339()}
	_ = s.Store.SaveFinalization(done)

	if n := s.SettleUnfinalized(); n != 1 {
		t.Fatalf("settled %d rows, want 1", n)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.State != FinalizeFinalized || f.Threshold != 2 {
		t.Fatalf("the old row was not settled against the log: %+v", f)
	}
	if d, _ := s.Store.GetFinalization("Edone"); d.Threshold != 5 {
		t.Fatalf("a finalized row was touched: %+v", d)
	}
}

// The status route reports the identity's own threshold from its log, not the
// configured 5 against three witnesses.
func TestStatusReportsTheIdentitysOwnThreshold(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(3)
	s.KeyLogOf = keyLog(mc.identity.AID, inceptionOf(mc.identity.AID, w.keys, 2))
	st, err := s.BuildStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.Threshold != 2 {
		t.Fatalf("status threshold %d, want the log's 2", st.Threshold)
	}
}

// What the configuration reports and what an event is finalized against agree
// on a value below the shipped one.
func TestAConfiguredValueBelowTheDefaultIsReportedAndHonoured(t *testing.T) {
	s, _ := testService(t)
	icp := inceptionOf(theAID, witnessesOf(3).keys, 1)
	s.KeyLogOf = keyLog(theAID, icp)
	row, _ := s.witnessing(theAID, saidOf(icp), nil)
	_ = s.Store.SetConfig("threshold", "3")
	if s.Threshold() != 3 || s.thresholdFor(row) != 3 {
		t.Fatalf("reported %d, applied %d, want both 3", s.Threshold(), s.thresholdFor(row))
	}
}
