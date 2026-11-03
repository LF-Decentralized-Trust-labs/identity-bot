package drivers

import (
	"bytes"
	"testing"
)

// An event whose content does not derive the identifier it claims is not in
// the witnessing report, and an honest receipt for that identifier counts for
// nothing. ParseEvent reads d as written; only validation re-derives it.
func TestAnEventWhoseIdentifierIsNotItsOwnIsNotReported(t *testing.T) {
	l := newRotatedLog(t)
	// Same length, so only the digest check can notice: a witness is added to
	// the content while d stays as the genuine event's.
	forged := bytes.Replace(append([]byte(nil), l.icp...), []byte(l.w2), []byte(l.w3), 1)
	if bytes.Equal(forged, l.icp) {
		t.Fatal("the test did not alter the event")
	}
	in := ValidateKELInput{
		RawEvents: [][]byte{forged},
		Receipts:  map[string][]WitnessReceipt{l.icpSAID: {{WitnessAID: l.w1, CesrSignature: l.sign1(l.icpSAID)}}},
	}
	if row, ok := WitnessingOf(in, l.icpSAID); ok {
		t.Fatalf("an event whose content does not derive its identifier was reported: %+v", row)
	}
	if _, ok := WitnessingOf(ValidateKELInput{RawEvents: [][]byte{l.icp}}, l.icpSAID); !ok {
		t.Fatal("the genuine event is not reported")
	}
}
