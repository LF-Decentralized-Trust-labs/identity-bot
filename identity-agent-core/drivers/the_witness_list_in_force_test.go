package drivers

import (
	"fmt"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func icpNaming(aid string, toad string, witnesses ...string) []byte {
	return []byte(fmt.Sprintf(`{"t":"icp","d":"E0","i":%q,"s":"0","b":%s,"bt":%q}`, aid, quoted(witnesses), toad))
}

func rotAt(aid string, sn int, prior, said string, cut, add []string, toad string) []byte {
	return []byte(fmt.Sprintf(`{"t":"rot","d":%q,"i":%q,"s":"%x","p":%q,"br":%s,"ba":%s,"bt":%q}`,
		said, aid, sn, prior, quoted(cut), quoted(add), toad))
}

func quoted(v []string) string {
	out := "["
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%q", s)
	}
	return out + "]"
}

func parsed(t *testing.T, raw []byte) *keri.Event {
	t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// The rule for the list in force is one rule: a rotation that adds a witness
// the list already has leaves it once, at the place it had.
func TestARotationThatReAddsAWitnessLeavesItOnceAtItsOldPlace(t *testing.T) {
	icp := parsed(t, icpNaming("EA", "1", "BW1", "BW2"))
	list, touched := WitnessesAfter(nil, icp)
	if !touched || len(list) != 2 {
		t.Fatalf("an inception answered %v, %v", list, touched)
	}
	rot := parsed(t, rotAt("EA", 1, "E0", "E1", nil, []string{"BW1"}, "1"))
	if list, _ = WitnessesAfter(list, rot); len(list) != 2 || list[0] != "BW1" || list[1] != "BW2" {
		t.Fatalf("a rotation re-adding BW1 left %v, want [BW1 BW2]", list)
	}
	// Cut and re-added in one rotation: it leaves, then joins at the end.
	cutAndAdd := parsed(t, rotAt("EA", 2, "E1", "E2", []string{"BW1"}, []string{"BW1"}, "1"))
	if list, _ = WitnessesAfter(list, cutAndAdd); len(list) != 2 || list[0] != "BW2" || list[1] != "BW1" {
		t.Fatalf("a rotation cutting and re-adding BW1 left %v, want [BW2 BW1]", list)
	}
	// A rotation that cuts every witness leaves a list with nobody in it, not nothing.
	cutAll := parsed(t, rotAt("EA", 3, "E2", "E3", []string{"BW2", "BW1"}, nil, "0"))
	if list, _ = WitnessesAfter(list, cutAll); list == nil || len(list) != 0 {
		t.Fatalf("a cut-all rotation left %#v", list)
	}
	ixn := parsed(t, []byte(`{"t":"ixn","d":"E4","i":"EA","s":"4","p":"E3"}`))
	if list, touched = WitnessesAfter([]string{"BW9"}, ixn); touched || len(list) != 1 {
		t.Fatalf("an interaction changed the list: %v, %v", list, touched)
	}
}

// What a log says of an event is read at the event's own place, by the same
// walk whether the event is in the log or about to go in.
func TestAnEventIsReadAtItsOwnPlaceInTheLog(t *testing.T) {
	icp := icpNaming("EA", "1", "BW1")
	rot := rotAt("EA", 1, "E0", "E1", []string{"BW1"}, []string{"BW2"}, "1")
	row, ok := WitnessingOf(ValidateKELInput{AID: "EA", RawEvents: [][]byte{icp, rot}}, "E0")
	if !ok || !row.Known || len(row.Designated) != 1 || row.Designated[0] != "BW1" || row.Threshold != 1 {
		t.Fatalf("event 0 read as %+v, %v", row, ok)
	}
	row, _ = WitnessingOf(ValidateKELInput{AID: "EA", RawEvents: [][]byte{icp, rot}}, "E1")
	if !row.Known || len(row.Designated) != 1 || row.Designated[0] != "BW2" {
		t.Fatalf("event 1 read as %+v", row)
	}
}

// A log whose events do not all read does not know the list from there on: the
// damaged event could be the rotation that cut a witness.
func TestAfterADamagedEventTheListIsNotKnown(t *testing.T) {
	icp := icpNaming("EA", "1", "BW1")
	damaged := []byte(`{"t":"rot", this is damaged`)
	rot := rotAt("EA", 2, "E1", "E2", nil, nil, "1")
	row, ok := WitnessingOf(ValidateKELInput{AID: "EA", RawEvents: [][]byte{icp, damaged, rot}}, "E2")
	if !ok || row.Known {
		t.Fatalf("an event after a damaged one read as known: %+v, %v", row, ok)
	}
	// And an establishment event with no usable threshold.
	noThreshold := []byte(`{"t":"rot","d":"E1","i":"EA","s":"1","p":"E0","br":[],"ba":[]}`)
	row, _ = WitnessingOf(ValidateKELInput{AID: "EA", RawEvents: [][]byte{icp, noThreshold}}, "E1")
	if row.Known {
		t.Fatalf("an event whose threshold is missing read as known: %+v", row)
	}
}

// A log is extended only by an event that could be next in it.
func TestALogIsExtendedOnlyByAnEventThatCouldBeNext(t *testing.T) {
	icp := icpNaming("EA", "1", "BW1")
	next := rotAt("EA", 1, "E0", "E1", nil, []string{"BW2"}, "1")
	for name, c := range map[string]struct {
		log  [][]byte
		next []byte
		ok   bool
	}{
		"an inception to an empty log":        {nil, icp, true},
		"a rotation to an empty log":          {nil, next, false},
		"the next event":                      {[][]byte{icp}, next, true},
		"the event already there":             {[][]byte{icp, next}, next, true},
		"a gap in the sequence":               {[][]byte{icp}, rotAt("EA", 7, "E0", "E7", nil, nil, "1"), false},
		"another prior":                       {[][]byte{icp}, rotAt("EA", 1, "EOther", "E1x", nil, nil, "1"), false},
		"another identifier":                  {[][]byte{icp}, rotAt("EB", 1, "E0", "E1y", nil, nil, "1"), false},
		"a second inception":                  {[][]byte{icp}, []byte(`{"t":"icp","d":"Esecond","i":"EA","s":"0","b":[],"bt":"0"}`), false},
		"a log with an event that is damaged": {[][]byte{[]byte("{")}, next, false},
	} {
		got, err := AppendEvent(c.log, c.next)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
		}
		if err == nil && name == "the next event" && len(got) != 2 {
			t.Errorf("%s: the log has %d events", name, len(got))
		}
		if err == nil && name == "the event already there" && len(got) != 2 {
			t.Errorf("%s: the event was added again: %d events", name, len(got))
		}
	}
}
