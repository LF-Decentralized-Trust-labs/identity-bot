package witnessproto

import (
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The witness list in force, as witnessproto states it to a watcher that imports
// nothing else: an inception names it, a rotation cuts br then adds ba once each,
// delegated events the same, and nothing else touches it.
func TestTheWitnessListInForceFollowsBrAndBa(t *testing.T) {
	for _, ilk := range []string{"icp", "dip"} {
		ev := &keri.Event{Ilk: ilk, Witnesses: []string{"BW1", "BW2"}}
		got, touched := WitnessesAfter([]string{"BOld"}, ev)
		if !touched || strings.Join(got, ",") != "BW1,BW2" {
			t.Errorf("%s: %v, %v", ilk, got, touched)
		}
		got[0] = "BChanged"
		if ev.Witnesses[0] != "BW1" {
			t.Errorf("%s: the list given back shares the event's", ilk)
		}
	}
	for _, ilk := range []string{"rot", "drt"} {
		ev := &keri.Event{Ilk: ilk, WitnessCut: []string{"BW1"}, WitnessAdd: []string{"BW3", "BW2", "BW3"}}
		got, touched := WitnessesAfter([]string{"BW1", "BW2"}, ev)
		if !touched || strings.Join(got, ",") != "BW2,BW3" {
			t.Errorf("%s: %v, %v; want BW2,BW3", ilk, got, touched)
		}
	}
	got, touched := WitnessesAfter([]string{"BW1"}, &keri.Event{Ilk: "ixn"})
	if touched || strings.Join(got, ",") != "BW1" {
		t.Errorf("ixn: %v, %v", got, touched)
	}
}
