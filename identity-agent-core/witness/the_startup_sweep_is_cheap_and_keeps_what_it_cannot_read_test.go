package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

func rowOf(said, signer, state string, count, threshold int) FinalizationState {
	return FinalizationState{EventSAID: said, SignerAID: signer, State: state, ReceiptCount: count,
		Threshold: threshold, StartedAt: NowRFC3339(), UpdatedAt: NowRFC3339()}
}

// A log of 2000 events, every one with an old row at threshold 5, is settled in
// one pass over the log, well inside a time budget (the pass that re-read the
// log per row took seconds).
func TestTheSweepOfTwoThousandRowsReadsTheLogOnce(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	log := [][]byte{inceptionOf(theAID, w.keys, 2)}
	for i := 1; i < 2000; i++ {
		log = append(log, interactionOf(theAID, i))
	}
	reads := 0
	s.KeyLogOf = func(aid string) ([][]byte, error) { reads++; return log, nil }
	for _, ev := range log {
		if err := s.Store.SaveFinalization(rowOf(saidOf(ev), theAID, FinalizeTimeout, 0, 5)); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	n := s.SettleUnfinalized()
	took := time.Since(start)
	if n != 2000 {
		t.Fatalf("settled %d rows, want 2000", n)
	}
	if reads != 1 {
		t.Fatalf("the key log was read %d times, want once", reads)
	}
	if took > 5*time.Second {
		t.Fatalf("settling 2000 rows took %v", took)
	}
	f, _ := s.Store.GetFinalization(saidOf(log[1234]))
	if f.Threshold != 2 {
		t.Fatalf("a row was not settled against the log's toad: %+v", f)
	}
}

// Once settled, later starts look only at pending and partial rows.
func TestLaterSweepsLeaveTimedOutRowsAlone(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	s.KeyLogOf = keyLog(theAID, icp, interactionOf(theAID, 1))
	timedOut, pending := saidOf(icp), saidOf(interactionOf(theAID, 1))
	_ = s.Store.SaveFinalization(rowOf(timedOut, theAID, FinalizeTimeout, 0, 5))
	_ = s.Store.SaveFinalization(rowOf(pending, theAID, FinalizePending, 0, 5))
	if n := s.SettleUnfinalized(); n != 2 {
		t.Fatalf("first run settled %d, want 2", n)
	}
	// A timed-out row stored later (as one is, when a wait ends) at threshold 5.
	_ = s.Store.SaveFinalization(rowOf(timedOut, theAID, FinalizeTimeout, 0, 5))
	_ = s.Store.SaveFinalization(rowOf(pending, theAID, FinalizePending, 0, 5))
	if n := s.SettleUnfinalized(); n != 1 {
		t.Fatalf("a later run settled %d rows, want only the pending one", n)
	}
	if f, _ := s.Store.GetFinalization(timedOut); f.Threshold != 5 {
		t.Fatalf("a later run touched a timed-out row: %+v", f)
	}
}

// A partial row with a real receipt, whose log cannot be read, times out
// reporting that receipt and the threshold it had, not 0.
func TestAnUnreadableLogKeepsAPartialRowsCountAtTheDeadline(t *testing.T) {
	quickFinalizeWait(t)
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	said := saidOf(icp)
	s.KeyLogOf = keyLog(theAID, icp)
	s.begin(said, theAID, 0, 2, icp)
	if err := s.receive(said, w.keys[0], w.receipt(w.keys[0], said), icp); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Store.GetFinalization(said); f.State != FinalizePartial || f.ReceiptCount != 1 {
		t.Fatalf("setup: %+v", f)
	}
	s.KeyLogOf = unreadableLog
	s.finalizeLoop(said)
	f, _ := s.Store.GetFinalization(said)
	if f.State != FinalizeTimeout || f.ReceiptCount != 1 || f.Threshold != 2 {
		t.Fatalf("the count or threshold was lost with the log: %+v", f)
	}
}

// An event that is not in the log the store holds (nil raw event) keeps its row
// through the sweep; a timeout row is not turned into pending.
func TestAnEventMissingFromItsLogKeepsItsStoredState(t *testing.T) {
	s, _ := testService(t)
	w := witnessesOf(3)
	icp := inceptionOf(theAID, w.keys, 2)
	s.KeyLogOf = keyLog(theAID, icp)
	_ = s.Store.SaveFinalization(rowOf("Egone", theAID, FinalizeTimeout, 1, 2))
	_ = s.Store.SaveFinalization(rowOf("Epartial", theAID, FinalizePartial, 1, 2))
	s.SettleUnfinalized()
	for said, want := range map[string]string{"Egone": FinalizeTimeout, "Epartial": FinalizePartial} {
		f, _ := s.Store.GetFinalization(said)
		if f.State != want || f.ReceiptCount != 1 || f.Threshold != 2 {
			t.Fatalf("%s lost what it knew: %+v", said, f)
		}
	}
}

// An old install's event that no designated witness holds (row timeout, 0
// receipts, stored at 5) is sent again when the log is brought up to date, and
// finalizes on the receipt that comes back.
func TestAnEventNoWitnessHoldsIsSentAgainAndFinalizes(t *testing.T) {
	d := newDelegation(t)
	d.approved(t)
	sender, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	posts := 0
	sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		posts++
		var req struct {
			AID   string `json:"aid"`
			Event string `json:"event_b64"`
			Sig   string `json:"cesr_signature"`
		}
		_ = json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req.Event)
		return d.w.ReceiveEvent(req.AID, raw, req.Sig)
	}
	sender.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		_, nonce, _ := strings.Cut(url, "?nonce=")
		return d.w.KelTip(d.delegate, nonce, true)
	}
	dip, _ := base64.StdEncoding.DecodeString(d.dipB64)
	said := saidOf(dip)
	sig, _ := login.SignString(string(dip), d.delegateSeed)
	sender.KeyLogOf = keyLog(d.delegate, dip)
	old := rowOf(said, d.delegate, FinalizeTimeout, 0, 5)
	if err := sender.Store.SaveFinalization(old); err != nil {
		t.Fatal(err)
	}
	// On an existing install the background sweep runs before the first
	// BringUpToDate: it must leave the timed-out row timed out, or nothing
	// re-arms it.
	sender.SettleUnfinalized()
	if g, _ := sender.Store.GetFinalization(said); g.State != FinalizeTimeout {
		t.Fatalf("the sweep turned a timed-out row into %s: %+v", g.State, g)
	}
	sender.BringUpToDate(context.Background(), d.delegate, []SignedEvent{{RawBytesB64: d.dipB64, CesrSignature: sig}}, []string{d.wkey}, 5)
	if posts != 1 {
		t.Fatalf("the event was sent %d times, want once", posts)
	}
	f, _ := sender.Store.GetFinalization(said)
	if f.State != FinalizeFinalized || f.ReceiptCount != 1 || f.Threshold != 1 {
		t.Fatalf("the event was not receipted and finalized: %+v", f)
	}
	// Once per boot: a row that times out with nothing again is not re-armed
	// by the next pass.
	_ = sender.Store.SaveFinalization(old)
	sender.rearm(d.delegate, []rearmRow{{said: said}})
	if g, _ := sender.Store.GetFinalization(said); g.State != FinalizeTimeout {
		t.Fatalf("an event was re-armed twice in one run: %+v", g)
	}
	sender.Stop()
	sender.Wait()
}

// A timed-out event with no receipts gets another wait when it is sent again,
// even if the witness does not answer this time, so it can time out honestly
// again rather than sit as a row nothing will ever look at.
func TestAnEventSentAgainGetsAnotherWait(t *testing.T) {
	d := newDelegation(t)
	d.approved(t)
	sender, mc := testService(t)
	mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
	_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: d.wkey})
	sender.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		return nil, fmt.Errorf("unreachable")
	}
	sender.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
		_, nonce, _ := strings.Cut(url, "?nonce=")
		return d.w.KelTip(d.delegate, nonce, true)
	}
	dip, _ := base64.StdEncoding.DecodeString(d.dipB64)
	said := saidOf(dip)
	sig, _ := login.SignString(string(dip), d.delegateSeed)
	sender.KeyLogOf = keyLog(d.delegate, dip)
	_ = sender.Store.SaveFinalization(rowOf(said, d.delegate, FinalizeTimeout, 0, 5))
	sender.BringUpToDate(context.Background(), d.delegate, []SignedEvent{{RawBytesB64: d.dipB64, CesrSignature: sig}}, []string{d.wkey}, 5)
	f, _ := sender.Store.GetFinalization(said)
	if f.State != FinalizePending || f.Threshold != 1 {
		t.Fatalf("the event was not given another wait: %+v", f)
	}
	sender.Stop()
	sender.Wait()
}
