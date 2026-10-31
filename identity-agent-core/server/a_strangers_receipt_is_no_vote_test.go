package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// The receipt endpoints judge a threshold by the event's own witnesses and
// threshold. They counted every stored receipt that verified, so a receipt
// from a witness the event never named — anybody can make a key and sign an
// event's digest — met a threshold of two beside one genuine receipt. And
// they took the caller's threshold as given, so a threshold of one was met by
// half the witnesses the event requires.
func TestAStrangersReceiptDoesNotMeetTheThreshold(t *testing.T) {
	w := witnessedIdentity(t) // two witnesses, both required
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := iacrypto.NonTransferableAIDQB64(pub)
	strangerSig, _ := login.SignString(w.said, priv.Seed())
	for _, r := range []store.WitnessReceiptRecord{
		{EventSAID: w.said, WitnessAID: w.witnesses[0], CesrSignature: w.sign(0)},
		{EventSAID: w.said, WitnessAID: stranger, CesrSignature: strangerSig},
	} {
		if err := w.s.DataStore.SaveWitnessReceipt(r); err != nil {
			t.Fatal(err)
		}
	}
	if held, _ := w.s.DataStore.GetWitnessReceipts(w.said); len(held) != 2 {
		t.Fatalf("held %d receipts, want both (the stranger's verifies)", len(held))
	}

	ask := func(path string, handler func(*CoreServer) func(rw *httptest.ResponseRecorder, url string)) map[string]interface{} {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(w.s)(rec, path)
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v (%s)", path, err, rec.Body.String())
		}
		return out
	}
	kerl := func(s *CoreServer) func(*httptest.ResponseRecorder, string) {
		return func(rec *httptest.ResponseRecorder, url string) { s.handleGetKERL(rec, local("GET", url, "")) }
	}
	stored := func(s *CoreServer) func(*httptest.ResponseRecorder, string) {
		return func(rec *httptest.ResponseRecorder, url string) { s.handleGetStoreReceipts(rec, local("GET", url, "")) }
	}
	for _, c := range []struct {
		name    string
		path    string
		handler func(*CoreServer) func(*httptest.ResponseRecorder, string)
	}{
		{"kerl, threshold 2", "/api/kerl?event_said=" + w.said + "&threshold=2", kerl},
		{"kerl, threshold 1", "/api/kerl?event_said=" + w.said + "&threshold=1", kerl},
		{"kerl, no threshold", "/api/kerl?event_said=" + w.said, kerl},
		{"store, threshold 2", "/api/store/receipts?event_said=" + w.said + "&threshold=2", stored},
		{"store, threshold 1", "/api/store/receipts?event_said=" + w.said + "&threshold=1", stored},
	} {
		out := ask(c.path, c.handler)
		if out["threshold_met"] != false || out["receipt_count"] != float64(1) {
			t.Errorf("%s: one of two designated witnesses and a stranger reported as %v", c.name, out)
		}
	}

	// With the second designated witness's receipt, it is met.
	if err := w.s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{
		EventSAID: w.said, WitnessAID: w.witnesses[1], CesrSignature: w.sign(1),
	}); err != nil {
		t.Fatal(err)
	}
	out := ask("/api/kerl?event_said="+w.said, kerl)
	if out["threshold_met"] != true || out["receipt_count"] != float64(2) {
		t.Errorf("both designated witnesses reported as %v", out)
	}
	// A caller may ask for more than the event requires, and is told no.
	out = ask("/api/kerl?event_said="+w.said+"&threshold=3", kerl)
	if out["threshold_met"] != false {
		t.Errorf("a threshold of three was met by two witnesses: %v", out)
	}
}
