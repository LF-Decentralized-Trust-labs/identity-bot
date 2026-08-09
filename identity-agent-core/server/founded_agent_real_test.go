package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
)

// The same check a counterparty runs, against what a real agent actually
// produced — a real keripy inception event and the DID that agent published,
// captured from a running pair rather than built here.
//
// The in-memory tests can only prove this code agrees with itself. They passed
// against a stub that echoed the anchors back while the real driver was
// silently discarding them, so the change was inert everywhere it mattered and
// every test was green. This fixture is the part that could not have been
// self-consistent: if the seal shape, the CESR codes or the DID field names
// drift, the identifier stops committing to anything and only this fails.
func TestARealFoundedAgentIsTrustedByItsOwnInceptionEvent(t *testing.T) {
	raw, err := os.ReadFile("testdata/founded_agent_keripy.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var captured struct {
		Event map[string]interface{} `json:"event"`
		DID   didcomm.DID            `json:"did"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if captured.DID.AID == "" || captured.Event["i"] != captured.DID.AID {
		t.Fatalf("the fixture's event and DID are not the same identity")
	}

	// No signing key: an anchored identity must be trustable with nothing else
	// established first.
	trust, err := checkPeerKeys(&captured.DID, []map[string]interface{}{captured.Event}, "")
	if err != nil {
		t.Fatalf("a real agent's published keys were not trusted against its own "+
			"inception event: %v", err)
	}
	if trust != peerKeysAnchored {
		t.Fatalf("trust was %q, want %q", trust, peerKeysAnchored)
	}
}

// And the identifier is what actually protects it: swap one key and the same
// event no longer vouches for the DID.
func TestARealAgentsKeysCannotBeSubstituted(t *testing.T) {
	raw, err := os.ReadFile("testdata/founded_agent_keripy.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var captured struct {
		Event map[string]interface{} `json:"event"`
		DID   didcomm.DID            `json:"did"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	// One character of the agreement key, changed.
	swapped := captured.DID
	orig := swapped.X25519
	if orig == "" {
		t.Fatal("the fixture carries no agreement key")
	}
	first := "A"
	if strings.HasPrefix(orig, "A") {
		first = "B"
	}
	swapped.X25519 = first + orig[1:]

	if _, err := checkPeerKeys(&swapped, []map[string]interface{}{captured.Event}, ""); err == nil {
		t.Fatal("a substituted agreement key was accepted for a real identifier")
	}
}
