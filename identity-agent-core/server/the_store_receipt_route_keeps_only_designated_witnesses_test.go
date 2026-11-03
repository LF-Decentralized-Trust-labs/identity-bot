package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// POST /api/store/receipt keeps a receipt only from a witness the event's own
// key log designates, as the other receipt route does: a genuine signature from
// a stranger is refused and not stored, and so is a receipt for an event no
// kept log holds.
func TestTheStoreReceiptRouteRefusesAnUndesignatedWitness(t *testing.T) {
	w := witnessedIdentity(t)
	post := func(said, witness, sig string) int {
		body, _ := json.Marshal(map[string]string{"event_said": said, "witness_aid": witness, "cesr_signature": sig})
		rec := httptest.NewRecorder()
		w.s.handleStoreReceipt(rec, local("POST", "/api/store/receipt", string(body)))
		return rec.Code
	}
	held := func(said string) int {
		r, _ := w.s.DataStore.GetWitnessReceipts(said)
		return len(r)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := iacrypto.NonTransferableAIDQB64(pub)
	sig, _ := login.SignString(w.said, priv.Seed())
	if code := post(w.said, stranger, sig); code != 422 || held(w.said) != 0 {
		t.Fatalf("a stranger's genuine receipt: status %d, %d kept", code, held(w.said))
	}
	if code := post("ENoLogHoldsThisEvent000000000000000000000000", stranger, sig); code != 404 {
		t.Fatalf("a receipt for an event in no kept log: status %d", code)
	}
	if code := post(w.said, w.witnesses[0], w.sign(0)); code != 201 || held(w.said) != 1 {
		t.Fatalf("a designated witness's receipt: status %d, %d kept", code, held(w.said))
	}
}
