package drivers

import "testing"

// CountDesignated is the one count: distinct designated witnesses with a
// verifying receipt, each once, nobody else.
func TestCountDesignatedCountsDistinctDesignatedVerifiedWitnesses(t *testing.T) {
	a, signA := witness(t)
	b, _ := witness(t)
	stranger, signS := witness(t)
	const said = "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	receipts := []WitnessReceipt{
		{WitnessAID: a, CesrSignature: signA(said)},
		{WitnessAID: a, CesrSignature: signA(said)},        // again: once
		{WitnessAID: b, CesrSignature: signA(said)},        // not b's signature
		{WitnessAID: stranger, CesrSignature: signS(said)}, // genuine, undesignated
		{WitnessAID: "not-a-witness", CesrSignature: "x"},
	}
	if got := CountDesignated([]string{a, b}, receipts, said); got != 1 {
		t.Fatalf("counted %d, want 1", got)
	}
	if got := CountDesignated(nil, receipts, said); got != 0 {
		t.Fatalf("with nobody designated counted %d", got)
	}
	if !DesignatesWitness([]string{a, b}, b) || DesignatesWitness([]string{a, b}, stranger) || DesignatesWitness([]string{"junk"}, "junk") {
		t.Fatal("DesignatesWitness disagrees with the key rule")
	}
}
