package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A box that has been told which claim to accept, and from whom, with key
// material already offered — the state a real instance is in when a claim
// arrives.
// Real, decodable Ed25519 verkeys — 32 raw bytes, base64url.
//
// They have to be real. The first draft of this file used readable placeholders
// like "DSomeKeyTheAttackerControls", and the owner-key check refused them
// before the ownership check was ever reached. Every test below then passed
// with the ownership binding deleted, because something else happened to stop
// the attacker. A test that green-lights the absence of the thing it tests is
// worse than no test.
const (
	buyerKey    = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	attackerKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"
)

func boxAwaitingClaim(t *testing.T, token, ownerAID string) *CoreServer {
	t.Helper()
	s := witnessWithStore(t)

	resetExpectedClaimForTest()
	if err := SetExpectedClaim(token, ownerAID); err != nil {
		t.Fatalf("could not set the expectation: %v", err)
	}

	pairingState.Lock()
	pairingState.offered = &pairingBeginResponse{
		PublicKey:     "DOfferedKey",
		NextPublicKey: "DOfferedNextKey",
	}
	pairingState.Unlock()
	t.Cleanup(func() {
		pairingState.Lock()
		pairingState.offered, pairingState.seed = nil, nil
		pairingState.Unlock()
		resetExpectedClaimForTest()
	})
	return s
}

func claim(t *testing.T, s *CoreServer, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	s.handlePairingComplete(w, httptest.NewRequest(http.MethodPost, "/api/pairing/complete", bytes.NewReader(raw)))
	return w
}

// Holding the token is not enough — you must be who it was issued to.
//
// This is the binding. Without it a token that leaked anywhere on its way to
// the buyer would let whoever picked it up install themselves as owner, which
// is most of what the token exists to prevent.
func TestAClaimFromTheWrongIdentityIsRefusedEvenWithTheRightToken(t *testing.T) {
	s := boxAwaitingClaim(t, "TOKEN-ISSUED-TO-THE-BUYER", "EBuyer")
	s.KeriDriver = nil // never reached: the refusal comes first

	w := claim(t, s, map[string]any{
		"adoption_code": "TOKEN-ISSUED-TO-THE-BUYER",
		"found_as_root": true,
		"owner_aid":     "EAttacker",
		// A real key the attacker controls, so the ONLY thing that can refuse
		// this request is the ownership binding.
		"owner_public_key": attackerKey,
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("a stranger holding the buyer's token claimed the box: got %d, want 403 — %s", w.Code, w.Body)
	}
}

// The buyer, presenting the token it was issued with, gets past the gate.
//
// Without this a check that refused everyone would pass the test above and
// still be useless.
func TestTheBuyerGetsPastTheGate(t *testing.T) {
	s := boxAwaitingClaim(t, "TOKEN-ISSUED-TO-THE-BUYER", "EBuyer")
	s.KeriDriver = nil // reaching it is the proof; no KERI runtime needed

	w := claim(t, s, map[string]any{
		"adoption_code":    "TOKEN-ISSUED-TO-THE-BUYER",
		"found_as_root":    true,
		"owner_aid":        "EBuyer",
		"owner_public_key": buyerKey,
	})

	if w.Code == http.StatusForbidden {
		t.Fatalf("the rightful buyer was refused: %s", w.Body)
	}
}

// An owner named but unable to sign is the failure that cannot be repaired.
//
// The identity is founded and persisted before the owner is sealed. If sealing
// then fails, the box refuses every further attempt while naming an owner whose
// key it cannot resolve: administrable by nobody, permanently, with no remedy
// but founding it again. So the key is checked before anything is minted.
func TestAClaimWithNoOwnerKeyIsRefusedBeforeAnythingIsMinted(t *testing.T) {
	s := boxAwaitingClaim(t, "TOKEN", "EBuyer")
	s.KeriDriver = nil

	w := claim(t, s, map[string]any{
		"adoption_code": "TOKEN",
		"found_as_root": true,
		"owner_aid":     "EBuyer",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("founded an identity whose owner cannot sign: got %d, want 400 — %s", w.Code, w.Body)
	}
	if id, _ := s.DataStore.GetIdentity(); id != nil {
		t.Fatal("an identity was persisted despite the claim being refused")
	}
}

func TestAnUnreadableOwnerKeyIsRefused(t *testing.T) {
	s := boxAwaitingClaim(t, "TOKEN", "EBuyer")
	s.KeriDriver = nil

	w := claim(t, s, map[string]any{
		"adoption_code":    "TOKEN",
		"found_as_root":    true,
		"owner_aid":        "EBuyer",
		"owner_public_key": "!!! not a key !!!",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("accepted an owner key it cannot verify signatures with: got %d — %s", w.Code, w.Body)
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "key") {
		t.Errorf("refused, but the reason never mentions the key: %s", w.Body)
	}
}

// A box nobody has spoken to accepts nothing at all.
//
// This is the whole shape of the fix: the instance no longer mints a secret and
// publishes it, so until the provisioner tells it what to expect there is
// nothing to guess and nothing to steal.
func TestABoxNobodyToldCannotBeClaimed(t *testing.T) {
	s := witnessWithStore(t)
	s.KeriDriver = nil
	resetExpectedClaimForTest()
	pairingState.Lock()
	pairingState.offered = &pairingBeginResponse{PublicKey: "DK", NextPublicKey: "DN"}
	pairingState.Unlock()
	t.Cleanup(func() {
		pairingState.Lock()
		pairingState.offered = nil
		pairingState.Unlock()
	})

	w := claim(t, s, map[string]any{
		"adoption_code":    "anything-at-all",
		"found_as_root":    true,
		"owner_aid":        "EAttacker",
		"owner_public_key": buyerKey,
	})

	if w.Code == http.StatusOK {
		t.Fatal("a box that was never provisioned for anybody was claimed")
	}
}
