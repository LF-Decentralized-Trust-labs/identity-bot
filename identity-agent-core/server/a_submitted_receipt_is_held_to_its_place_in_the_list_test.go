package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// POST /api/receipt/submit keeps a receipt signed over the event only at the
// witness's own place in the list in force at that event. A genuine signature
// carrying another place is refused and not kept.
func TestASubmittedReceiptIsHeldToItsPlaceInTheList(t *testing.T) {
	w := witnessedIdentity(t)
	id, _ := w.s.DataStore.GetIdentity()
	evs, err := w.s.DataStore.GetEvents(id.AID)
	if err != nil || len(evs) == 0 {
		t.Fatal("no event", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(evs[0].RawBytesB64)
	good, _ := drivers.SignEventReceipt(raw, w.keys[1].Seed(), 1)
	wrongPlace, _ := drivers.SignEventReceipt(raw, w.keys[1].Seed(), 0)
	body := func(sig string) map[string]interface{} {
		return map[string]interface{}{"event_said": w.said, "witness_aid": w.witnesses[1], "cesr_signature": sig}
	}
	held := func() int { h, _ := w.s.DataStore.GetWitnessReceipts(w.said); return len(h) }

	if code, _ := w.submit(t, body(wrongPlace)); code != 422 || held() != 0 {
		t.Fatalf("a receipt at another witness's place: %d, kept %d", code, held())
	}
	if code, _ := w.submit(t, body(good)); code != 200 || held() != 1 {
		t.Fatalf("the receipt at the witness's own place: %d, kept %d", code, held())
	}
}

// The witness list and the event bytes come from the key log, and an event the
// log does not hold gives neither, so the caller refuses.
func TestTheEventAndItsWitnessesAreReadOnlyFromALogThatHoldsIt(t *testing.T) {
	w := witnessedIdentity(t)
	id, _ := w.s.DataStore.GetIdentity()
	in, ok := w.s.logOfEvent(w.said)
	if !ok {
		t.Fatalf("no log for %s", id.AID)
	}
	raw, designated, ok := eventAndWitnessesIn(in, w.said)
	if !ok || len(raw) == 0 || len(designated) != 2 || designated[0] != w.witnesses[0] || designated[1] != w.witnesses[1] {
		t.Fatalf("the event and its list were not read: %v %v", ok, designated)
	}
	if _, _, ok := eventAndWitnessesIn(in, "ENoSuchEvent0123456789ABCDEFGHIJKLMNOPQRSTU"); ok {
		t.Fatal("an event the log does not hold was given a witness list")
	}
	if _, _, ok := eventAndWitnessesIn(drivers.ValidateKELInput{}, w.said); ok {
		t.Fatal("an empty log gave an event and a list")
	}
}

// An event that designates no witness has an empty witness list, which is a
// list: a receipt for it is from a witness it did not designate, and is
// refused, not kept because there was no list to hold its index to.
func TestAReceiptForAnEventThatDesignatesNobodyIsRefused(t *testing.T) {
	w := witnessedIdentityOf(t, 0)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	strangerAID := iacrypto.NonTransferableAIDQB64(stranger.Public().(ed25519.PublicKey))
	id, _ := w.s.DataStore.GetIdentity()
	evs, _ := w.s.DataStore.GetEvents(id.AID)
	raw, _ := base64.StdEncoding.DecodeString(evs[0].RawBytesB64)
	sig, _ := drivers.SignEventReceipt(raw, stranger.Seed(), 0)

	code, _ := w.submit(t, map[string]interface{}{"event_said": w.said, "witness_aid": strangerAID, "cesr_signature": sig})
	if code != 422 {
		t.Fatalf("a receipt from a witness the event does not designate: %d", code)
	}
	if h, _ := w.s.DataStore.GetWitnessReceipts(w.said); len(h) != 0 {
		t.Fatalf("it was kept: %d", len(h))
	}
}
