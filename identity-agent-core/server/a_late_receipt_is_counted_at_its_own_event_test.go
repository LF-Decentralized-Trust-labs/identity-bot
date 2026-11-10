package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A key log of an inception naming the first witness (threshold 1), then a
// rotation that cuts it and adds the second. Event 0 is finalized: the first
// witness receipted it.
func cutByARotation(t *testing.T) (s *CoreServer, aid string, saids []string, witnesses []string, sign func(i int, said string) string) {
	t.Helper()
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ds.Close() })
	s = &CoreServer{DataStore: ds, localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	var privs []ed25519.PrivateKey
	for i := 0; i < 2; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privs = append(privs, priv)
		witnesses = append(witnesses, iacrypto.NonTransferableAIDQB64(pub))
	}
	k0, _ := keri.GenerateSigner(true)
	k1, _ := keri.GenerateSigner(true)
	k2, _ := keri.GenerateSigner(true)
	pub0, _ := k0.PublicKey()
	pub1, _ := k1.PublicKey()
	pub2, _ := k2.PublicKey()
	d1, _ := keri.NextDigest(pub1)
	d2, _ := keri.NextDigest(pub2)
	one := 1
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub0}, NextDigests: []string{d1}, Witnesses: witnesses[:1], Toad: &one,
		Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, _ := keri.ParseEvent(icp)
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{pub1}, PriorSAID: icpEv.SAID, SN: 1, NextDigests: []string{d2},
		PriorWitnesses: witnesses[:1], Cuts: witnesses[:1], Adds: witnesses[1:], Toad: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotEv, _ := keri.ParseEvent(rot)
	if err := ds.SaveIdentity(store.IdentityState{AID: icpEv.Identifier, PublicKey: pub0}); err != nil {
		t.Fatal(err)
	}
	for i, raw := range [][]byte{icp, rot} {
		if err := ds.SaveEvent(store.EventRecord{
			AID: icpEv.Identifier, SequenceNumber: i, EventType: []string{"icp", "rot"}[i], EventJSON: string(raw),
			RawBytesB64: base64.StdEncoding.EncodeToString(raw),
		}); err != nil {
			t.Fatal(err)
		}
	}
	wsvc := witness.NewService(witness.NewSQLiteStore(ds.DB()), ds, nil, witness.BackendDesktop)
	wsvc.KeyLogOf = s.keyLogOf
	s.WitnessService = wsvc
	now := time.Now().UTC().Format(time.RFC3339)
	if err := wsvc.Store.SaveFinalization(witness.FinalizationState{
		EventSAID: icpEv.SAID, SignerAID: icpEv.Identifier, State: witness.FinalizePending,
		Threshold: 1, StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return s, icpEv.Identifier, []string{icpEv.SAID, rotEv.SAID}, witnesses, func(i int, said string) string {
		sig, _ := login.SignString(said, privs[i].Seed())
		return sig
	}
}

func submitReceipt(t *testing.T, s *CoreServer, said, witness, sig string) int {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{"event_said": said, "witness_aid": witness, "cesr_signature": sig})
	rec := httptest.NewRecorder()
	s.handleSubmitReceipt(rec, local("POST", "/api/receipt/submit", string(b)))
	return rec.Code
}

// A receipt that arrives after a rotation has cut its witness is counted for
// the event it receipts at that event's own place in the log. Counted against
// the list as it stands now, the witness the rotation cut would not count, and
// an event that was finalized would drop back to pending with nothing.
func TestALateReceiptDoesNotUndoAnEventARotationHasPassed(t *testing.T) {
	s, _, saids, witnesses, sign := cutByARotation(t)
	if code := submitReceipt(t, s, saids[0], witnesses[0], sign(0, saids[0])); code != 200 {
		t.Fatalf("the receipt of the witness event 0 named was refused: %d", code)
	}
	f, _ := s.WitnessService.Store.GetFinalization(saids[0])
	if f == nil || f.State != witness.FinalizeFinalized || f.ReceiptCount != 1 {
		t.Fatalf("event 0 after a late receipt: %+v", f)
	}
	// Sent again, it stays finalized.
	_ = submitReceipt(t, s, saids[0], witnesses[0], sign(0, saids[0]))
	if f, _ = s.WitnessService.Store.GetFinalization(saids[0]); f.State != witness.FinalizeFinalized || f.ReceiptCount != 1 {
		t.Fatalf("event 0 after the receipt again: %+v", f)
	}
}

// A witness the rotation added signs event 0 as well. Its receipt is not one
// event 0 asked for, and does not count for it.
func TestALaterWitnessesOldReceiptDoesNotCountForAnEarlierEvent(t *testing.T) {
	s, _, saids, witnesses, sign := cutByARotation(t)
	_ = submitReceipt(t, s, saids[0], witnesses[1], sign(1, saids[0]))
	f, _ := s.WitnessService.Store.GetFinalization(saids[0])
	if f.ReceiptCount != 0 || f.State == witness.FinalizeFinalized {
		t.Fatalf("a witness added after event 0 finalized it: %+v", f)
	}
}

// The list in force at an event is read from its log as far as that event. When
// an event before it cannot be read, the list is not known, and a receipt is
// not kept against it: the unreadable event could be the rotation that cut the
// witness.
func TestAReceiptPastAnUnreadableEventIsNotKeptAgainstAnUnknownList(t *testing.T) {
	s, aid, saids, witnesses, sign := cutByARotation(t)
	db := s.DataStore.(*store.SQLiteStore).DB()
	// The rotation moves to place 2, and a damaged event takes place 1.
	if _, err := db.Exec(`UPDATE kel SET seq_num = 2 WHERE aid = ? AND seq_num = 1`, aid); err != nil {
		t.Fatal(err)
	}
	damaged := `{"t":"rot", this is damaged`
	if err := s.DataStore.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: 1, EventType: "rot",
		EventJSON: damaged, RawBytesB64: base64.StdEncoding.EncodeToString([]byte(damaged))}); err != nil {
		t.Fatal(err)
	}
	if code := submitReceipt(t, s, saids[1], witnesses[1], sign(1, saids[1])); code != 422 {
		t.Fatalf("a receipt for an event past an unreadable one answered %d, want 422", code)
	}
	if held, _ := s.DataStore.GetWitnessReceipts(saids[1]); len(held) != 0 {
		t.Fatalf("it was kept against a list nobody could read: %+v", held)
	}
	// The event before the damage is read as far as it, and is still judged.
	if code := submitReceipt(t, s, saids[0], witnesses[0], sign(0, saids[0])); code != 200 {
		t.Fatalf("a receipt for an event before the damage answered %d", code)
	}
}

// A receipt submitted here is counted on the event's finalization, as one that
// came back in a witness's answer is: the count is the receipts kept, so a
// repeat does not move it and a second witness completes it.
func TestASubmittedReceiptIsCountedOnTheEventsFinalization(t *testing.T) {
	w := witnessedIdentity(t)
	sq := w.s.DataStore.(*store.SQLiteStore)
	w.s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, nil, witness.BackendDesktop)
	w.s.WitnessService.KeyLogOf = w.s.keyLogOf
	owner, _ := w.s.DataStore.GetIdentity()
	now := witness.NowRFC3339()
	_ = w.s.WitnessService.Store.SaveFinalization(witness.FinalizationState{
		EventSAID: w.said, SignerAID: owner.AID, State: witness.FinalizePending, Threshold: 2, StartedAt: now, UpdatedAt: now,
	})
	got := func() witness.FinalizationState {
		f, _ := w.s.WitnessService.Store.GetFinalization(w.said)
		return *f
	}
	for i := 0; i < 2; i++ { // the second is a repeat
		w.submit(t, map[string]interface{}{"event_said": w.said, "witness_aid": w.witnesses[0], "cesr_signature": w.sign(0)})
	}
	if f := got(); f.ReceiptCount != 1 || f.State != witness.FinalizePartial {
		t.Fatalf("one witness, twice: %+v", f)
	}
	w.submit(t, map[string]interface{}{"event_said": w.said, "witness_aid": w.witnesses[1], "cesr_signature": w.sign(1)})
	if f := got(); f.ReceiptCount != 2 || f.State != witness.FinalizeFinalized {
		t.Fatalf("two witnesses: %+v", f)
	}
}
