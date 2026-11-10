package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// someWitnesses are n witnesses with keys of their own, who can receipt an
// event.
type someWitnesses struct {
	keys  []string
	seeds map[string][]byte
}

func witnessesOf(n int) someWitnesses {
	w := someWitnesses{seeds: map[string][]byte{}}
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		key := iacrypto.NonTransferableAIDQB64(pub)
		w.keys = append(w.keys, key)
		w.seeds[key] = priv.Seed()
	}
	return w
}

// receipt is the witness's receipt of the event with this identifier.
func (w someWitnesses) receipt(key, said string) string {
	sig, _ := login.SignString(said, w.seeds[key])
	return sig
}

const theAID = "ERoot"

// A late receipt for an event that a rotation has since passed is counted
// against the witnesses in force at that event, not those in force now: the
// witness the rotation cut still receipted it, and it is finalized.
func TestALateReceiptCountsAgainstTheListInForceAtItsOwnEvent(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(2)
	icp := inceptionOf(theAID, []string{w.keys[0]}, 1)
	rot := rotationOf(theAID, 1, []string{w.keys[0]}, []string{w.keys[1]}, 1)
	said := saidOf(icp)

	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 1, icp)
	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizeFinalized || f.ReceiptCount != 1 {
		t.Fatalf("not finalized before the rotation: %+v", f)
	}

	// The rotation cuts the witness that finalized event 0. A receipt is then
	// submitted late, through the route that keeps a receipt without the
	// service, and the event is recounted.
	s.KeyLogOf = keyLog(theAID, icp, rot)
	_ = mc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[0], CesrSignature: w.receipt(w.keys[0], said)})
	s.RecountReceipts(said)
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizeFinalized || f.ReceiptCount != 1 {
		t.Fatalf("a rotation after the event took it back from finalized: %+v", f)
	}
}

// A receipt from a witness that was added after an event does not count for it,
// however it got to be kept: the event did not name that witness.
func TestALaterWitnessesReceiptDoesNotCountForAnEarlierEvent(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, []string{w.keys[0], w.keys[2]}, 2)
	rot := rotationOf(theAID, 1, []string{w.keys[2]}, []string{w.keys[1]}, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp, rot)

	s.begin(said, theAID, 0, 2, icp)
	_ = mc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[0], CesrSignature: w.receipt(w.keys[0], said)})
	// The list now is [0, 1], and 1 signed this very event, but event 0 named [0, 2].
	_ = mc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[1], CesrSignature: w.receipt(w.keys[1], said)})
	s.RecountReceipts(said)
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State != FinalizePartial {
		t.Fatalf("a witness the event did not name was counted for it: %+v", f)
	}
}

// What a log says of an event it does not hold yet is answered only when the
// event could be next in it: an inception to a log with nothing in it, or the
// event that follows the last.
func TestAnEventThatCannotBeNextInTheLogHasNoWitnessing(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(2)
	icp := inceptionOf(theAID, []string{w.keys[0]}, 1)
	rot := rotationOf(theAID, 1, []string{w.keys[0]}, []string{w.keys[1]}, 1)
	gap := rotationOf(theAID, 7, []string{w.keys[0]}, []string{w.keys[1]}, 1)

	s.KeyLogOf = keyLog(theAID)
	if row, err := s.witnessing(theAID, saidOf(rot), rot); err == nil {
		t.Fatalf("a rotation to a log with nothing in it answered %v", row.Designated)
	}
	if _, err := s.witnessing(theAID, saidOf(icp), icp); err != nil {
		t.Fatalf("an inception to a log with nothing in it was refused: %v", err)
	}

	s.KeyLogOf = keyLog(theAID, icp)
	if row, err := s.witnessing(theAID, saidOf(gap), gap); err == nil {
		t.Fatalf("a rotation at sequence 7 after sequence 0 answered %v", row.Designated)
	}
	row, err := s.witnessing(theAID, saidOf(rot), rot)
	if err != nil || len(row.Designated) != 1 || row.Designated[0] != w.keys[1] {
		t.Fatalf("the next event answered %v, %v", row.Designated, err)
	}
	// And the same once it is in the log.
	s.KeyLogOf = keyLog(theAID, icp, rot)
	if row, err = s.witnessing(theAID, saidOf(rot), rot); err != nil || len(row.Designated) != 1 || row.Designated[0] != w.keys[1] {
		t.Fatalf("the event in the log answered %v, %v", row.Designated, err)
	}
}

// A receipt kept that does not count (here one that does not verify, as one
// kept while the log could not be read may not) does not lock its witness out:
// the witness's receipt that does is kept in its place.
func TestAHeldReceiptThatDoesNotCountIsReplaced(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(1)
	icp := inceptionOf(theAID, w.keys, 1)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 1, icp)
	_ = mc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[0], CesrSignature: "0Bnotasignature"})

	good := w.receipt(w.keys[0], said)
	if err := s.receive(said, w.keys[0], good, icp); err != nil {
		t.Fatal(err)
	}
	held, _ := mc.GetWitnessReceipts(said)
	if len(held) != 1 || held[0].CesrSignature != good {
		t.Fatalf("the receipt that counts did not replace the one that does not: %+v", held)
	}
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizeFinalized || f.ReceiptCount != 1 {
		t.Fatalf("not counted: %+v", f)
	}
}

// And one that does count is kept as it is: a witness sending again changes
// nothing.
func TestAHeldReceiptThatCountsIsNotReplaced(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(1)
	icp := inceptionOf(theAID, w.keys, 1)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 1, icp)
	good := w.receipt(w.keys[0], said)
	_ = s.receive(said, w.keys[0], good, icp)
	_ = mc.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[0], CesrSignature: good})
	for i := 0; i < 3; i++ {
		_ = s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp)
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 1 {
		t.Fatalf("one witness counted %d times", f.ReceiptCount)
	}
}

// When the key log cannot be read now, nothing is counted, even for receipts
// that counted before: the receipts stay kept for when it can be read. Counting
// them as they stood, without a list, would call a cut witness's receipt good.
func TestWhenTheLogCannotBeReadNowNothingIsCounted(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(1)
	icp := inceptionOf(theAID, w.keys, 1)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 1, icp)
	_ = s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp)
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 1 {
		t.Fatalf("not counted while it could be read: %+v", f)
	}

	s.KeyLogOf = func(string) ([][]byte, error) { return nil, errors.New("damaged") }
	s.RecountReceipts(said)
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 0 || f.State != FinalizePending {
		t.Fatalf("receipts were counted against a log nobody could read: %+v", f)
	}
	// Nor with no log to ask at all.
	s.KeyLogOf = nil
	s.RecountReceipts(said)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 0 {
		t.Fatalf("receipts were counted with no log: %+v", f)
	}
	// Read again, they count again.
	s.KeyLogOf = keyLog(theAID, icp)
	s.RecountReceipts(said)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 1 || f.State != FinalizeFinalized {
		t.Fatalf("not counted once the log read again: %+v", f)
	}
}

// One witness is one receipt per event, however often it arrives: a repeat
// must not move the count, or a single witness could reach the threshold alone.
func TestOneWitnessCannotReachTheThresholdAlone(t *testing.T) {
	s, mc := testService(t)
	w := witnessesOf(2)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 2, icp)
	for i := 0; i < 5; i++ {
		_ = s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("one witness counted %d times, state %s", f.ReceiptCount, f.State)
	}
	if held, _ := mc.GetWitnessReceipts(said); len(held) != 1 {
		t.Fatalf("one witness's receipt was kept %d times", len(held))
	}
	// And a store that kept it three times (one that does not refuse it) still counts one.
	for i := 0; i < 3; i++ {
		mc.mu.Lock()
		mc.receipts[said] = append(mc.receipts[said], store.WitnessReceiptRecord{EventSAID: said, WitnessAID: w.keys[0], CesrSignature: w.receipt(w.keys[0], said)})
		mc.mu.Unlock()
	}
	s.RecountReceipts(said)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 1 {
		t.Fatalf("a witness kept four times counted %d", f.ReceiptCount)
	}
	_ = s.receive(said, w.keys[1], w.receipt(w.keys[1], said), icp)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 2 || f.State != FinalizeFinalized {
		t.Fatalf("a second witness was not counted: %d, %s", f.ReceiptCount, f.State)
	}
}

// With bt 0 nothing is waited for: zero receipts of zero asked is finalized,
// and a log that designates nobody asks for nobody.
func TestAThresholdOfZeroIsFinalizedNotPendingForEver(t *testing.T) {
	s, _ := testService(t)
	icp := inceptionOf(theAID, nil, 0)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(saidOf(icp), theAID, 0, 0, icp)
	if f, _ := s.Store.GetFinalization(saidOf(icp)); f.State != FinalizeFinalized || f.ReceiptCount != 0 {
		t.Fatalf("zero of zero settled as %s with %d", f.State, f.ReceiptCount)
	}
}

// onReceipt does not count a witness it already holds, so a broadcast that
// restarted the count at 0 would leave an event that is sent again with one
// receipt too few for good. The count is the receipts kept, whatever restarts it.
func TestAnEventBroadcastAgainKeepsTheReceiptsItHas(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	w := witnessesOf(2)
	const aid = "ERecord"
	icp := inceptionOf(aid, w.keys, 2)
	ixn := interactionOf(aid, 1)
	said := saidOf(ixn)
	s.KeyLogOf = keyLog(aid, icp, ixn)
	for i, key := range w.keys {
		c := "EContactw" + string(rune('1'+i))
		mc.contacts[c] = store.ContactRecord{AID: c, OobiURL: "http://w" + string(rune('1'+i)) + ".test", IsWitness: true}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: c, WitnessKey: key})
	}
	var mu sync.Mutex
	secondUp := false
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		i := 0
		if url != witnessEventURL(witnessTarget{URL: "http://w1.test"}) {
			i = 1
			mu.Lock()
			up := secondUp
			mu.Unlock()
			if !up {
				return nil, errors.New("down")
			}
		}
		return map[string]interface{}{"witness_aid": w.keys[i], "cesr_signature": w.receipt(w.keys[i], said)}, nil
	}
	send := func() {
		t.Helper()
		if err := s.BroadcastToDesignated(context.Background(), aid, ixn, []string{"0Bsig"}, w.keys, 2); err != nil {
			t.Fatal(err)
		}
	}
	// The sends are in the background, so the count is waited for.
	settled := func(count int, state string) {
		t.Helper()
		var f *FinalizationState
		for i := 0; i < 200; i++ {
			if f, _ = s.Store.GetFinalization(said); f != nil && f.ReceiptCount == count && f.State == state {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("expected %d receipts, %s; it is %+v", count, state, f)
	}
	defer s.Stop()
	send()
	settled(1, FinalizePartial)
	mu.Lock()
	secondUp = true
	mu.Unlock()
	send()
	settled(2, FinalizeFinalized)
	// Sent a third time, with both receipts held, it stays finalized at 2.
	send()
	time.Sleep(200 * time.Millisecond)
	settled(2, FinalizeFinalized)
}
