package witness

import (
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/store"
)

// A Contacts store that runs a hook once, just after the first read of kept
// receipts: the moment between the sweep reading them and taking its lock.
type hookedContacts struct {
	ContactStore
	fired atomic.Bool
	hook  func()
}

func (h *hookedContacts) GetWitnessReceipts(said string) ([]store.WitnessReceiptRecord, error) {
	out, err := h.ContactStore.GetWitnessReceipts(said)
	// Set before the hook runs: the hook reads receipts itself.
	if h.fired.CompareAndSwap(false, true) && h.hook != nil {
		h.hook()
	}
	return out, err
}

// A receipt that lands between the sweep's read of the receipts and its lock is
// not overwritten with the lower count.
func TestASweepDoesNotOverwriteAReceiptThatLandedMeanwhile(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	_ = s.Store.SaveFinalization(rowOf(said, theAID, FinalizePending, 0, 2))
	h := &hookedContacts{ContactStore: s.Contacts}
	h.hook = func() {
		if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
			t.Error(err)
		}
	}
	s.Contacts = h
	s.SettleUnfinalized()
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State != FinalizePartial {
		t.Fatalf("the receipt that landed during the sweep was overwritten: %+v", f)
	}
}

// StartSettlingUnfinalized returns while the key log is still being read: the
// sweep is never in the start path.
func TestStartingTheSweepDoesNotWaitForTheKeyLog(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	_ = s.Store.SaveFinalization(rowOf(saidOf(icp), theAID, FinalizeTimeout, 0, 5))
	entered, release := make(chan struct{}), make(chan struct{})
	s.KeyLogOf = func(string) ([][]byte, error) {
		close(entered)
		<-release
		return [][]byte{icp}, nil
	}
	returned := make(chan struct{})
	go func() { s.StartSettlingUnfinalized(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("StartSettlingUnfinalized waited for the key log")
	}
	<-entered
	close(release)
	s.Wait()
}

// 2,000 timed-out rows brought up to date are re-armed from one read of the
// log under one shared wait, not one read and one wait each.
func TestTwoThousandTimedOutRowsAreRearmedFromOneRead(t *testing.T) {
	quickFinalizeWait(t)
	s, _ := testService(t)
	w := witnessesOf(3)
	log := [][]byte{inceptionOf(theAID, w.keys, 2)}
	for i := 1; i < 2000; i++ {
		log = append(log, interactionOf(theAID, i))
	}
	var mu sync.Mutex
	reads, timeouts := 0, 0
	s.KeyLogOf = func(string) ([][]byte, error) { mu.Lock(); reads++; mu.Unlock(); return log, nil }
	s.OnEvent = func(kind string, _ map[string]interface{}) {
		if kind == "witness_finalize_timeout" {
			mu.Lock()
			timeouts++
			mu.Unlock()
		}
	}
	var events []SignedEvent
	for _, ev := range log {
		events = append(events, SignedEvent{RawBytesB64: base64.StdEncoding.EncodeToString(ev)})
		if err := s.Store.SaveFinalization(rowOf(saidOf(ev), theAID, FinalizeTimeout, 0, 5)); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	// A designated witness this agent has no address for: nothing is sent, and
	// only the re-arming is measured.
	s.BringUpToDate(t.Context(), theAID, events, []string{w.keys[0]}, 5)
	s.Wait()
	if took := time.Since(start); took > time.Minute {
		t.Fatalf("re-arming 2000 rows took %v", took)
	}
	mu.Lock()
	defer mu.Unlock()
	if reads != 1 {
		t.Fatalf("the key log was read %d times, want once", reads)
	}
	if timeouts != 2000 {
		t.Fatalf("%d rows reported their new timeout, want 2000", timeouts)
	}
	if f, _ := s.Store.GetFinalization(saidOf(log[1234])); f.State != FinalizeTimeout || f.Threshold != 2 {
		t.Fatalf("a re-armed row was not settled against the log: %+v", f)
	}
}
