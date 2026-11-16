package backendaddr

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const vectorsPath = "../../packages/login-verify/test-vectors/back-end-addresses.json"

type vectors struct {
	Addresses []struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Accepted bool   `json:"accepted"`
		DevOnly  bool   `json:"dev_only"`
	} `json:"addresses"`
}

// The core decides every shared case as the file says: an address is accepted
// or refused alike here, in the login page and in the Dart link reader.
func TestTheCoreDecidesTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("the shared vectors cannot be read: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Addresses) < 40 {
		t.Fatalf("the shared vectors hold %d cases, so something was lost", len(v.Addresses))
	}
	for _, c := range v.Addresses {
		// Outside a development build.
		wantOutside := c.Accepted && !c.DevOnly
		if got := Check(c.Address, false) == nil; got != wantOutside {
			t.Errorf("%s (%q): accepted outside dev = %v, the file says %v", c.Name, c.Address, got, wantOutside)
		}
		// In one, what the file accepts is accepted, and nothing it refuses is.
		if got := Check(c.Address, true) == nil; got != c.Accepted {
			t.Errorf("%s (%q): accepted in dev = %v, the file says %v", c.Name, c.Address, got, c.Accepted)
		}
	}
}

func TestAnAddressLongerThanTheBoundIsRefused(t *testing.T) {
	if Check("https://tasks.example.com/"+strings.Repeat("a", MaxLength), false) == nil {
		t.Error("an address over the bound was accepted")
	}
}

func TestARelayIdentifierIsFortyFourCharactersOfTheURLSafeAlphabet(t *testing.T) {
	ok := "E" + strings.Repeat("a", 43)
	if err := CheckRelayID(ok); err != nil {
		t.Errorf("a good identifier was refused: %v", err)
	}
	for name, rid := range map[string]string{
		"empty": "", "short": ok[:43], "long": ok + "a", "lower-case first": "e" + strings.Repeat("a", 43),
		"a space": "E" + strings.Repeat("a", 42) + " ", "a slash": "E" + strings.Repeat("a", 42) + "/",
		"a plus": "E" + strings.Repeat("a", 42) + "+", "a digit first": "1" + strings.Repeat("a", 43),
	} {
		if CheckRelayID(rid) == nil {
			t.Errorf("%s: %q was accepted", name, rid)
		}
	}
}
