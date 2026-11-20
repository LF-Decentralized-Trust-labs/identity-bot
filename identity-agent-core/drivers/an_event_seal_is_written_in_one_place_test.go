package drivers

import "testing"

// The bytes of an event seal are fixed: other implementations read them, and
// every caller in the core gets them from here.
func TestAnEventSealHasItsFieldsInTheSpecifiedOrder(t *testing.T) {
	seal, err := EventSeal("EIdentifier", "1a", "EDigest")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"i":"EIdentifier","s":"1a","d":"EDigest"}`; string(seal) != want {
		t.Fatalf("got %s, want %s", seal, want)
	}
	// A value cannot break out of the seal.
	seal, err = EventSeal(`E"x`, "0", `E\y`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"i":"E\"x","s":"0","d":"E\\y"}`; string(seal) != want {
		t.Fatalf("got %s, want %s", seal, want)
	}
	for _, missing := range [][3]string{{"", "0", "E"}, {"E", "", "E"}, {"E", "0", ""}} {
		if _, err := EventSeal(missing[0], missing[1], missing[2]); err == nil {
			t.Errorf("a seal with an empty field was written: %q", missing)
		}
	}
}
