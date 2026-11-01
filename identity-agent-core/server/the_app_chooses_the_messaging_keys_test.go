package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"identity-agent-core/keymath"
)

// An identity whose key the app holds anchors the messaging keys the app chose:
// the founding is refused until the core holds that keyset, the anchor the
// core answers with is the one keymath gives the app, and once committed the
// keyset is filed under the new identity.
func TestTheAppChoosesTheMessagingKeysAndTheCoreHoldsThem(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(2)
	msgSeed := appSeeds(3)[2]
	anchor, err := keymath.MessagingKeySet(msgSeed)
	if err != nil {
		t.Fatal(err)
	}
	anchorJSON, _ := json.Marshal(anchor)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1",
		"a": []json.RawMessage{anchorJSON}})
	icp := preparedBytes(t, out)
	commit := func() (int, map[string]any) {
		return call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
			"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}})
	}
	if code, out := commit(); code != http.StatusBadRequest || out["error"] != "messaging_keyset_not_held" {
		t.Fatalf("a founding anchoring keys the core does not hold: %d %v", code, out)
	}

	code, out := call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
		map[string]any{"seed_hex": hex.EncodeToString(msgSeed)})
	if code != http.StatusOK {
		t.Fatalf("handing over the messaging seed: %d %v", code, out)
	}
	got, _ := json.Marshal(out["anchor"])
	var want any
	_ = json.Unmarshal(anchorJSON, &want)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Fatalf("the core anchors %s and the app's keymath %s", got, wantJSON)
	}
	if code, out := commit(); code != http.StatusCreated {
		t.Fatalf("the founding, once the core holds its keys: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()
	if held, err := s.keySetAnchorHeld(own.AID, anchor); err != nil || !held {
		t.Fatalf("the keyset is not filed under the new identity: %v", err)
	}
	if left, _ := s.hasKeySet(pendingKeySetLabel(anchor)); left {
		t.Fatal("the keyset handed over before the founding is still held aside")
	}
}
