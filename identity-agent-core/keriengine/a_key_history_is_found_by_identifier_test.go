package keriengine

import "testing"

// A key history is found by identifier, whatever name it is held under, and an
// identifier the engine does not hold is an error rather than something made.
func TestAKeyHistoryIsFoundByIdentifier(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	made, err := e.CreateInceptionNamed(pub, next, "Desk assistant")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKelByAID(made.AID)
	if err != nil || kel.AID != made.AID || len(kel.RawEventsB64) != 1 {
		t.Fatalf("the key history was not found by its identifier: %+v %v", kel, err)
	}
	if _, err := e.GetKelByAID("ENOTHELD00000000000000000000000000000000000000"); err == nil {
		t.Fatal("an identifier the engine does not hold was answered")
	}
	if len(e.state.identities) != 1 {
		t.Fatalf("looking an identifier up made identities: %d held", len(e.state.identities))
	}
}
