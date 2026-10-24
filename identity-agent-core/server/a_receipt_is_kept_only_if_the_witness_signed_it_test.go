package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

type receiptWorld struct {
	s         *CoreServer
	said      string
	witnesses []string
	keys      []ed25519.PrivateKey
}

// witnessedIdentity is an Identity Agent whose identity names two witnesses
// and needs both of their receipts.
func witnessedIdentity(t *testing.T) receiptWorld {
	t.Helper()
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := receiptWorld{s: &CoreServer{DataStore: ds, localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}}
	for i := 0; i < 2; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		w.keys = append(w.keys, priv)
		w.witnesses = append(w.witnesses, iacrypto.NonTransferableAIDQB64(pub))
	}
	signer, _ := keri.GenerateSigner(true)
	next, _ := keri.GenerateSigner(true)
	pub, _ := signer.PublicKey()
	nextPub, _ := next.PublicKey()
	digest, _ := keri.NextDigest(nextPub)
	toad := 2
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub}, NextDigests: []string{digest},
		Witnesses: w.witnesses, Toad: &toad, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(raw)
	w.said = ev.SAID
	if err := ds.SaveIdentity(store.IdentityState{AID: ev.Identifier, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	if err := ds.SaveEvent(store.EventRecord{
		AID: ev.Identifier, SequenceNumber: 0, EventType: "icp", EventJSON: string(raw),
		PublicKey: pub, RawBytesB64: base64.StdEncoding.EncodeToString(raw),
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w receiptWorld) sign(i int) string {
	sig, _ := login.SignString(w.said, w.keys[i].Seed())
	return sig
}

func (w receiptWorld) submit(t *testing.T, body map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	w.s.handleSubmitReceipt(rec, local("POST", "/api/receipt/submit", string(b)))
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Nobody but the owner reaches the route. A witness hands its receipt back in
// its answer to the owner's own request, so there is no one else to accept one
// from.
func TestReceiptSubmissionIsNotPublic(t *testing.T) {
	if got := classify("POST", "/api/receipt/submit"); got != accessOwner {
		t.Fatalf("POST /api/receipt/submit is classified %q; it must be owner only", got)
	}
}

// The forgery as it was: a receipt signed with the submitter's own key, that
// key handed over as the witness's, no trusted list and a threshold of zero.
func TestAReceiptSignedWithTheSubmittersOwnKeyIsRefused(t *testing.T) {
	w := witnessedIdentity(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := login.SignString(w.said, priv.Seed())
	code, _ := w.submit(t, map[string]interface{}{
		"event_said": w.said, "witness_aid": w.witnesses[0], "cesr_signature": forged,
		"witness_public_key": iacrypto.NonTransferableAIDQB64(pub),
		"trusted_witnesses":  []string{}, "threshold": 0,
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("a forged receipt answered %d, want 422", code)
	}
	if held, _ := w.s.DataStore.GetWitnessReceipts(w.said); len(held) != 0 {
		t.Fatalf("a forged receipt was kept: %+v", held)
	}
}

// A real receipt is kept and counted against the identity's own threshold,
// whatever threshold the caller names.
func TestGenuineReceiptsAreKeptAndCountedAgainstTheLogsThreshold(t *testing.T) {
	w := witnessedIdentity(t)
	code, out := w.submit(t, map[string]interface{}{
		"event_said": w.said, "witness_aid": w.witnesses[0], "cesr_signature": w.sign(0), "threshold": 1,
	})
	if code != http.StatusOK || out["accepted"] != true {
		t.Fatalf("a genuine receipt: %d %v", code, out)
	}
	if out["threshold_met"] != false || out["receipt_count"] != float64(1) {
		t.Fatalf("one of two required receipts reported as %v", out)
	}
	_, out = w.submit(t, map[string]interface{}{
		"event_said": w.said, "witness_aid": w.witnesses[1], "cesr_signature": w.sign(1),
	})
	if out["threshold_met"] != true || out["receipt_count"] != float64(2) {
		t.Fatalf("both required receipts reported as %v", out)
	}
	if held, _ := w.s.DataStore.GetWitnessReceipts(w.said); len(held) != 2 {
		t.Fatalf("held %d receipts, want 2", len(held))
	}
}

// A junk receipt that got in first no longer keeps the real one out.
func TestAVerifiedReceiptReplacesAJunkOneHeldFirst(t *testing.T) {
	w := witnessedIdentity(t)
	db := w.s.DataStore.(*store.SQLiteStore).DB()
	if _, err := db.Exec(`INSERT INTO witness_receipts (event_said, witness_aid, cesr_signature, received_at)
		VALUES (?, ?, 'junk', '')`, w.said, w.witnesses[0]); err != nil {
		t.Fatal(err)
	}
	if held, _ := w.s.DataStore.GetWitnessReceipts(w.said); len(held) != 0 {
		t.Fatalf("a junk receipt was read back as held: %+v", held)
	}
	if code, out := w.submit(t, map[string]interface{}{
		"event_said": w.said, "witness_aid": w.witnesses[0], "cesr_signature": w.sign(0),
	}); code != http.StatusOK || out["receipt_count"] != float64(1) {
		t.Fatalf("the real receipt after a junk one: %d %v", code, out)
	}
	held, _ := w.s.DataStore.GetWitnessReceipts(w.said)
	if len(held) != 1 || held[0].CesrSignature != w.sign(0) {
		t.Fatalf("the real receipt did not replace the junk one: %+v", held)
	}
}

// A receipt for an event this identity never published is not kept here.
func TestAReceiptForSomebodyElsesEventIsNotKept(t *testing.T) {
	w := witnessedIdentity(t)
	other := "Esomebody-elses-event"
	sig, _ := login.SignString(other, w.keys[0].Seed())
	if code, _ := w.submit(t, map[string]interface{}{
		"event_said": other, "witness_aid": w.witnesses[0], "cesr_signature": sig,
	}); code != http.StatusNotFound {
		t.Fatalf("a receipt for an event not in this identity's log answered %d, want 404", code)
	}
}
