package server

import (
	"regexp"
	"testing"

	"identity-agent-core/drivers"
)

// An inception with no threshold is a log that cannot be read as far as its
// first event: the witnesses it names are not a list a receipt can be held
// against.
func withoutAThreshold(raw []byte) []byte {
	return regexp.MustCompile(`"bt":"[0-9a-f]*",?`).ReplaceAll(raw, nil)
}

// A receipt is kept on neither route that keeps one where the witness list in
// force at its event cannot be read, though the witness is named in the event
// and the signature is its own.
func TestAReceiptIsNotKeptWhereTheWitnessListCannotBeRead(t *testing.T) {
	w := witnessedIdentityAs(t, 2, withoutAThreshold)
	in, ok := w.s.logOfEvent(w.said)
	if !ok {
		t.Fatal("the log is not claimed")
	}
	if row, found := drivers.WitnessingOf(in, w.said); !found || row.Known {
		t.Fatalf("the test's log is meant to be one that cannot be read: found=%v known=%v", found, row.Known)
	}
	held := func() int { h, _ := w.s.DataStore.GetWitnessReceipts(w.said); return len(h) }

	if code := storeReceipt(t, w.s, w.said, w.witnesses[0], w.sign(0)); code != 422 || held() != 0 {
		t.Fatalf("POST /api/store/receipt: %d, kept %d", code, held())
	}
	code, _ := w.submit(t, map[string]interface{}{"event_said": w.said, "witness_aid": w.witnesses[0], "cesr_signature": w.sign(0)})
	if code != 422 || held() != 0 {
		t.Fatalf("POST /api/receipt/submit: %d, kept %d", code, held())
	}
}
