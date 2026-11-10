package witness

import (
	"encoding/json"
	"testing"
)

// A witness is reported by the class ADR-070 names, on the wire as well as in
// code, and the boolean older clients read agrees with it.
func TestWitnessEntryCarriesItsClass(t *testing.T) {
	if ClassOf(true) != "COMMERCIAL" || ClassOf(false) != "PEER" {
		t.Fatalf("ClassOf: %s %s", ClassOf(true), ClassOf(false))
	}
	b, _ := json.Marshal(WitnessEntry{Class: ClassOf(true), IsCommercial: true})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["class"] != "COMMERCIAL" || m["is_commercial"] != true {
		t.Fatalf("wire form: %s", b)
	}
}
