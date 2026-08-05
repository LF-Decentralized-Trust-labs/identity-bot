package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/drivers"
)

// An agent that exists to serve somebody else refuses to found an identity that
// names nobody.
//
// TestFoundingARootIdentityWithoutAnOwnerIsRefused already closes this on
// /api/pairing/adopt. This closes the other door, and it is the one that
// matters in practice: /api/inception is the route the organisation app's own
// onboarding calls, so it is the route anything else reaching the agent would
// call too.
func inceptionRequest(t *testing.T, s *CoreServer, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/inception", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	s.handleInception(w, r)
	return w
}

func TestAnAgentThatServesSomebodyElseRefusesToFoundAnUnownedIdentity(t *testing.T) {
	s := witnessWithStore(t)
	s.requireOwnerAtInception = true
	// Non-nil so the request reaches the owner check; never called, because the
	// refusal happens before anything is minted.
	s.KeriDriver = &drivers.KeriDriver{}

	w := inceptionRequest(t, s, map[string]any{
		"public_key":      "Dpub",
		"next_public_key": "Dnext",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("an unowned identity was founded on an agent that serves somebody else: got %d, want 400", w.Code)
	}
	// The message has to say why, because the remedy is not "try again" — it is
	// "go and get the owner first", and nothing later can repair it.
	if !strings.Contains(strings.ToLower(w.Body.String()), "owner") {
		t.Errorf("refused, but the reason never mentions the owner: %s", w.Body.String())
	}
}

// The default must stay off, or every individual agent breaks.
//
// A person's own identity answers to nobody, and its delegator is already named
// in its event. Requiring an owner everywhere would make the common case
// impossible, which is the failure mode a rule like this invites.
func TestAPersonsOwnAgentStillFoundsAnIdentityWithNoOwner(t *testing.T) {
	s := witnessWithStore(t)
	if s.requireOwnerAtInception {
		t.Fatal("the default is on; it must be off or no individual agent can found its identity")
	}

	// Left nil deliberately. Reaching the driver at all proves the owner check
	// did not refuse first, which is the whole assertion — and it means this
	// test needs no KERI runtime to make its point.
	s.KeriDriver = nil
	w := inceptionRequest(t, s, map[string]any{
		"public_key":      "Dpub",
		"next_public_key": "Dnext",
	})

	if w.Code == http.StatusBadRequest && strings.Contains(strings.ToLower(w.Body.String()), "owner") {
		t.Fatalf("an ordinary agent was refused for having no owner: %s", w.Body.String())
	}
}

// With the rule on, naming an owner gets past it.
//
// Without this, a check that refused everything unconditionally would pass the
// test above and still be broken.
func TestNamingAnOwnerGetsPastTheCheck(t *testing.T) {
	s := witnessWithStore(t)
	s.requireOwnerAtInception = true
	s.KeriDriver = nil // as above: reaching it is the proof

	w := inceptionRequest(t, s, map[string]any{
		"public_key":      "Dpub",
		"next_public_key": "Dnext",
		"owner_aid":       "EFounder",
	})

	if w.Code == http.StatusBadRequest && strings.Contains(strings.ToLower(w.Body.String()), "owner") {
		t.Fatalf("an owner was named and it was still refused for having none: %s", w.Body.String())
	}
}

// The switch is readable from the environment, so a deployment can turn it on
// without a rebuild.
func TestTheRuleCanBeTurnedOnByConfiguration(t *testing.T) {
	for _, on := range []string{"true", "1"} {
		t.Setenv("REQUIRE_OWNER_AT_INCEPTION", on)
		if !DefaultConfig().RequireOwnerAtInception {
			t.Errorf("REQUIRE_OWNER_AT_INCEPTION=%s did not turn the rule on", on)
		}
	}
	t.Setenv("REQUIRE_OWNER_AT_INCEPTION", "")
	if DefaultConfig().RequireOwnerAtInception {
		t.Error("the rule is on by default; it must be off")
	}
}
