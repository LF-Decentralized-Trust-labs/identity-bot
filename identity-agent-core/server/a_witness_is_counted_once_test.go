package server

import (
	"strings"
	"testing"

	"identity-agent-core/store"
)

// One witness, its receipt held three times, once under a second spelling
// of its identifier, is one witness. Counted by stored row, as the receipt
// endpoints did, it met a threshold of two alone. (Counting by key rather
// than text is a backstop here: strict decoding already stops the second
// spelling verifying.)
func TestAWitnessUnderTwoSpellingsIsCountedOnce(t *testing.T) {
	w := witnessedIdentity(t) // two witnesses, both required
	aid := w.witnesses[0]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	v := strings.IndexByte(alphabet, aid[1])
	other := aid[:1] + string(alphabet[v&0x0f|1<<4]) + aid[2:]
	receipts := []store.WitnessReceiptRecord{
		{EventSAID: w.said, WitnessAID: aid, CesrSignature: w.sign(0)},
		{EventSAID: w.said, WitnessAID: other, CesrSignature: w.sign(0)},
		{EventSAID: w.said, WitnessAID: aid, CesrSignature: w.sign(0)},
	}
	if n, met := w.s.receiptsAgainstItsLog(w.said, receipts, 0); n != 1 || met {
		t.Fatalf("one witness was counted %d times (met=%v)", n, met)
	}
}

// A record's witness threshold is read as KERI writes it, and anything else
// matches no inception.
func TestARecordWitnessThresholdHasOneSpelling(t *testing.T) {
	for in, want := range map[interface{}]int{"0": 0, "2": 2, "a": 10, "02": -1, "A": -1, "": -1, 2: -1, "ffffffffff": -1} {
		if got := thresholdOf(in); got != want {
			t.Errorf("thresholdOf(%#v) = %d, want %d", in, got, want)
		}
	}
}
