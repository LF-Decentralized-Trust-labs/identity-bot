package server

import (
	"testing"
)

// The witness list comes out of the KEL already on disk. That is what makes
// recovery possible at all: nothing here needs the address that just died.
func TestWitnessesComeFromTheStoredInception(t *testing.T) {
	kel := []map[string]interface{}{
		{"t": "icp", "s": "0", "b": []interface{}{"EWitOne", "EWitTwo"}},
	}
	got := witnessesFromStoredKEL(kel)
	if len(got) != 2 || got[0] != "EWitOne" || got[1] != "EWitTwo" {
		t.Fatalf("expected both witnesses from the inception event, got %v", got)
	}
}

// A rotation can change the witness set, so the last event that carries one
// wins. Using the inception forever would send recovery to operators the
// contact has since left.
func TestARotationReplacesTheWitnessSet(t *testing.T) {
	kel := []map[string]interface{}{
		{"t": "icp", "s": "0", "b": []interface{}{"EOldWit"}},
		{"t": "ixn", "s": "1"},
		{"t": "rot", "s": "2", "b": []interface{}{"ENewWitA", "ENewWitB"}},
	}
	got := witnessesFromStoredKEL(kel)
	if len(got) != 2 || got[0] != "ENewWitA" {
		t.Fatalf("a later rotation should replace the set, got %v", got)
	}
}

// An event with no `b` field says nothing about witnesses; an event with an
// empty one says the set was cleared. Conflating them would keep querying
// operators a contact deliberately dropped.
func TestAnAbsentWitnessFieldDiffersFromAnEmptyOne(t *testing.T) {
	silent := witnessesFromStoredKEL([]map[string]interface{}{
		{"t": "icp", "s": "0", "b": []interface{}{"EWit"}},
		{"t": "ixn", "s": "1"},
	})
	if len(silent) != 1 {
		t.Errorf("an interaction event should not disturb the witness set, got %v", silent)
	}

	cleared := witnessesFromStoredKEL([]map[string]interface{}{
		{"t": "icp", "s": "0", "b": []interface{}{"EWit"}},
		{"t": "rot", "s": "1", "b": []interface{}{}},
	})
	if len(cleared) != 0 {
		t.Errorf("an explicitly empty set should clear the witnesses, got %v", cleared)
	}
}

func TestWitnessBaseURLStripsTheOOBIPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://wit.example.test/public/oobi/EWit": "https://wit.example.test",
		"https://wit.example.test/":                 "https://wit.example.test",
		"https://wit.example.test":                  "https://wit.example.test",
	} {
		if got := witnessBaseURL(in); got != want {
			t.Errorf("witnessBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Recovery needs a contact resolved at least once. First contact genuinely
// requires a working address, and saying so is better than a confusing failure
// further down.
func TestRecoveryNeedsAContactSeenBefore(t *testing.T) {
	s := witnessWithStore(t)
	if _, err := s.RecoverContactEndpoint("ENeverSeen"); err == nil {
		t.Fatal("expected recovery to refuse a contact with no stored KEL")
	}
}
