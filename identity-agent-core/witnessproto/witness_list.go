package witnessproto

import keri "github.com/grapeid/keri-go"

// WitnessesAfter is the one rule for the witness list in force: what an event
// leaves it as, given what it was before. An inception (or delegated
// inception) names the list outright; a rotation (or delegated rotation) cuts
// the witnesses in br, then adds those in ba that are not already in it, so a
// witness is in the list once and stands at one place; every other event
// leaves it as it was. The bool is whether the event touched the list.
//
// A witness's receipt carries its place in this list, so everything that
// reads a list, from a log's own events to a receipt arriving late, reads it
// here.
func WitnessesAfter(current []string, ev *keri.Event) ([]string, bool) {
	switch ev.Ilk {
	case "icp", "dip":
		return append([]string{}, ev.Witnesses...), true
	case "rot", "drt":
		out := make([]string, 0, len(current)+len(ev.WitnessAdd))
		for _, w := range current {
			if !contains(ev.WitnessCut, w) {
				out = append(out, w)
			}
		}
		for _, w := range ev.WitnessAdd {
			if !contains(out, w) {
				out = append(out, w)
			}
		}
		return out, true
	}
	return current, false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
