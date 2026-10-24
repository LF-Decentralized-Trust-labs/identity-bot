package witnessproto

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type digestVector struct {
	Name   string                   `json:"name"`
	Events []map[string]interface{} `json:"events"`
	Seq    int                      `json:"seq"`
	Digest string                   `json:"digest"`
}

// The vectors are the contract with every other implementation of the digest.
// A change that alters any of them changes what a watcher publishes, and every
// Identity Agent that compares against it would read an honest identity as
// having two histories. So a failure here is never fixed by regenerating the
// file.
func TestDigestMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("kel-digest-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []digestVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 5 {
		t.Fatalf("only %d vectors; the file has lost cases", len(vs))
	}
	for _, v := range vs {
		got, err := KelDigestAtSeq(v.Events, v.Seq)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if got != v.Digest {
			t.Errorf("%s: digest %s, the vectors say %s", v.Name, got, v.Digest)
		}
	}
}

func TestSequenceNumberIsHexadecimal(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "9": 9, "a": 10, "f": 15, "10": 16, "1a": 26, "ff": 255} {
		got, err := SequenceNumber(map[string]interface{}{"s": in})
		if err != nil || got != want {
			t.Errorf("%q read as %d (%v), want %d", in, got, err, want)
		}
	}
	for _, bad := range []interface{}{"", "-1", "+a", "g", "0x10", -1.0, 1.5, nil, true} {
		if n, err := SequenceNumber(map[string]interface{}{"s": bad}); err == nil {
			t.Errorf("%#v read as %d; an unreadable sequence number must be an error", bad, n)
		}
	}
}

// Every event after the tenth moves the log forward. Read as decimal, events
// "a" to "f" collapsed onto 0 and the current position stuck at 9 while the
// digest kept changing, which is what an equivocating identity looks like.
func TestEachNewEventIsANewPosition(t *testing.T) {
	var kel []map[string]interface{}
	seen := map[int]string{}
	for i := 0; i < 40; i++ {
		kel = append(kel, map[string]interface{}{"t": "ixn", "i": "EAlice", "s": fmt.Sprintf("%x", i)})
		at, err := CurrentSeq(kel)
		if err != nil {
			t.Fatal(err)
		}
		if at != i {
			t.Fatalf("after %d events the current position is %d, want %d", i+1, at, i)
		}
		d, err := KelDigestAtSeq(kel, at)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[at]; dup {
			t.Fatalf("position %d digested twice", at)
		}
		seen[at] = d
		// What was recorded at earlier positions does not change as the log grows.
		for p, was := range seen {
			if now, _ := KelDigestAtSeq(kel, p); now != was {
				t.Fatalf("after %d events the digest at %d changed from %s to %s", i+1, p, was, now)
			}
		}
	}
}

func TestAnUnreadableEventIsRefusedRatherThanPlaced(t *testing.T) {
	kel := []map[string]interface{}{{"s": "0"}, {"s": "zz"}}
	if _, err := KelDigestAtSeq(kel, 0); err == nil {
		t.Fatal("a log with an unreadable sequence number was digested")
	}
	if _, err := CurrentSeq(kel); err == nil {
		t.Fatal("a log with an unreadable sequence number was given a position")
	}
}
