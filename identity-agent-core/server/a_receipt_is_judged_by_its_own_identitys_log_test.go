package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// secondIdentity stores a second identity's witnessed log beside the primary
// one, as an Identity Agent keeps its record identity's: an inception naming
// two witnesses, both required, then a rotation keeping them. It returns the
// event identifiers, its witnesses and a signer for each.
func secondIdentity(t *testing.T, ds store.Store) (saids, witnesses []string, sign func(witness int, said string) string) {
	t.Helper()
	var keys []ed25519.PrivateKey
	for i := 0; i < 2; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys = append(keys, priv)
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
	two := 2
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub0}, NextDigests: []string{d1}, Witnesses: witnesses, Toad: &two,
		Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(icp)
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: ev.Identifier, Keys: []string{pub1}, PriorSAID: ev.SAID, SN: 1, NextDigests: []string{d2},
		PriorWitnesses: witnesses, Toad: &two,
	})
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := keri.ParseEvent(rot)
	for i, raw := range [][]byte{icp, rot} {
		if err := ds.SaveEvent(store.EventRecord{
			AID: ev.Identifier, SequenceNumber: i, EventType: []string{"icp", "rot"}[i], EventJSON: string(raw),
			RawBytesB64: base64.StdEncoding.EncodeToString(raw),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return []string{ev.SAID, rev.SAID}, witnesses, func(i int, said string) string {
		sig, _ := login.SignString(said, keys[i].Seed())
		return sig
	}
}

func kerlOf(t *testing.T, s *CoreServer, said string) map[string]interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleGetKERL(rec, local("GET", "/api/kerl?event_said="+said, ""))
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v (%s)", err, rec.Body.String())
	}
	return out
}

// An Identity Agent keeps more than its own identity's log: its record
// identity's, and others. An event of one of those is judged against its own
// identity's log. Judged against the primary identity's alone, as it was, it
// had no witnesses and was never met, whatever its receipts.
func TestAnEventOfAnotherKeptIdentityIsJudgedByItsOwnLog(t *testing.T) {
	w := witnessedIdentity(t) // the primary identity
	saids, witnesses, sign := secondIdentity(t, w.s.DataStore)
	keep := func(said string, i int) {
		t.Helper()
		if err := w.s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{
			EventSAID: said, WitnessAID: witnesses[i], CesrSignature: sign(i, said),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// One of two required receipts: not met.
	keep(saids[1], 0)
	if got := kerlOf(t, w.s, saids[1]); got["threshold_met"] != false || got["receipt_count"] != float64(1) {
		t.Fatalf("one of two receipts for the second identity's rotation reported as %v", got)
	}
	// Both, for each of its events: met.
	for _, said := range saids {
		keep(said, 0)
		keep(said, 1)
		if got := kerlOf(t, w.s, said); got["threshold_met"] != true || got["receipt_count"] != float64(2) {
			t.Errorf("the second identity's event %s, receipted by both its witnesses, reported as %v", said, got)
		}
	}
	// The receipt route keeps and judges a receipt for it the same way.
	code, out := w.submit(t, map[string]interface{}{"event_said": saids[0], "witness_aid": witnesses[1], "cesr_signature": sign(1, saids[0])})
	if code != 200 || out["threshold_met"] != true || out["receipt_count"] != float64(2) {
		t.Errorf("a receipt submitted for the second identity's inception: %d %v", code, out)
	}

	// A damaged log fails closed for its own identity only.
	db := w.s.DataStore.(*store.SQLiteStore).DB()
	primary, _ := w.s.DataStore.GetIdentity()
	if _, err := db.Exec(`UPDATE kel SET raw_bytes_b64 = '' WHERE aid = ?`, primary.AID); err != nil {
		t.Fatal(err)
	}
	if got := kerlOf(t, w.s, w.said); got["threshold_met"] != false {
		t.Errorf("an event of a log missing its bytes was met: %v", got)
	}
	if got := kerlOf(t, w.s, saids[0]); got["threshold_met"] != true {
		t.Errorf("another identity's damaged log stopped this one being judged: %v", got)
	}
}
