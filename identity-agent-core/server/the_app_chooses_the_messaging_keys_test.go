package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"identity-agent-core/didcomm"
	"net/http"
	"testing"
	"time"

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

	// A keyset whose seed was never handed over is refused, by an
	// interaction as by a founding.
	stranger := appSeeds(5)[4]
	strangerAnchor, _ := keymath.MessagingKeySet(stranger)
	strangerJSON, _ := json.Marshal(strangerAnchor)
	_, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID, "t": "ixn",
		"a": []json.RawMessage{strangerJSON}, "after": map[string]string{"s": "0", "d": own.AID}})
	unheld := preparedBytes(t, out)
	if code, _ := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(unheld), "sigs": []string{appSign(t, k[0], unheld, false)}}); code != http.StatusBadRequest {
		t.Fatalf("an interaction anchoring keys this core does not hold: %d", code)
	}

	// An event anchors one messaging keyset at most.
	two := appSeeds(7)
	a1, _ := keymath.MessagingKeySet(two[5])
	a2, _ := keymath.MessagingKeySet(two[6])
	j1, _ := json.Marshal(a1)
	j2, _ := json.Marshal(a2)
	for _, seed := range [][]byte{two[5], two[6]} {
		call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
			map[string]any{"seed_hex": hex.EncodeToString(seed)})
	}
	_, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID, "t": "ixn",
		"a": []json.RawMessage{j1, j2}, "after": map[string]string{"s": "0", "d": own.AID}})
	both := preparedBytes(t, out)
	if code, out := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(both), "sigs": []string{appSign(t, k[0], both, false)}}); code != http.StatusBadRequest || out["error"] != "one_messaging_keyset_per_event" {
		t.Fatalf("an event anchoring two keysets: %d %v", code, out)
	}
	// One replacement is held at a time: the second hand-over took the
	// first's place.
	if held, _ := s.keySetAnchorHeld(pendingReplacementLabel(own.AID), a2); !held {
		t.Fatal("the latest replacement handed over is not the one held aside")
	}

	// A replacement (ADR-061 section 8): its seed is held aside, the
	// interaction anchoring it is committed, and it takes the earlier
	// keyset's place, which is kept to open messages already sent to it.
	next := appSeeds(4)[3]
	nextAnchor, _ := keymath.MessagingKeySet(next)
	if code, out := call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
		map[string]any{"seed_hex": hex.EncodeToString(next)}); code != http.StatusOK || out["filed"] != "pending" {
		t.Fatalf("a seed for keys the log does not yet anchor is held aside: %d %v", code, out)
	}
	if held, _ := s.keySetAnchorHeld(own.AID, anchor); !held {
		t.Fatal("the keyset in force was changed before anything anchored its replacement")
	}
	nextJSON, _ := json.Marshal(nextAnchor)
	_, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID, "t": "ixn",
		"a": []json.RawMessage{nextJSON}, "after": map[string]string{"s": "0", "d": own.AID}})
	ixn := preparedBytes(t, out)
	if code, out := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k[0], ixn, false)}}); code != http.StatusCreated {
		t.Fatalf("an interaction anchoring a replacement whose seed was handed over: %d %v", code, out)
	}
	if held, _ := s.keySetAnchorHeld(own.AID, nextAnchor); !held {
		t.Fatal("the replacement is not the identity's keyset")
	}
	prev := s.previousKeySetFor(own.AID)
	if prev == nil {
		t.Fatal("the replaced keyset was not kept")
	}
	if got, _ := prev.Anchor(); !sameJSON(got, anchor) {
		t.Fatal("the keyset kept is not the one replaced")
	}
	if left, _ := s.hasKeySet(pendingReplacementLabel(own.AID)); left {
		t.Fatal("the replacement is still held aside")
	}
	if !s.anchoredLast(own.AID, nextAnchor) {
		t.Fatal("the replacement is not what the log anchors last")
	}
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// A message a counterparty encrypted to the keyset a replacement has just
// taken out of use is still opened: until counterparties have read the
// replacement they encrypt to the earlier keys (ADR-061 section 8).
func TestAMessageSentToReplacedKeysIsStillOpened(t *testing.T) {
	m := newMessaging(t)
	m.anchored(t)
	replacement, err := didcomm.GenerateKeySet(m.receiverAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.receiver.replaceKeySetFor(m.receiverAID, replacement); err != nil {
		t.Fatal(err)
	}
	// The sender has not yet read the replacement: it encrypts to the keys it
	// knew.
	n := m.send(t, `{"title":"sent to the earlier keys"}`)
	if n.ID == "" {
		t.Fatal("the message sent to the earlier keys was not taken")
	}
}

// A replacement committed whose filing did not finish is filed when its seed
// is handed over again; a replaced keyset opens messages only for a grace
// period; and no keyset kept aside is ever a message's recipient.
func TestAReplacementIsRepairedRetiredAndNeverAddressed(t *testing.T) {
	s, own, anchor, k := anIdentityWithAppMessagingKeys(t)
	next := appSeeds(4)[3]
	nextAnchor, _ := keymath.MessagingKeySet(next)
	call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
		map[string]any{"seed_hex": hex.EncodeToString(next)})
	nextJSON, _ := json.Marshal(nextAnchor)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own, "t": "ixn",
		"a": []json.RawMessage{nextJSON}, "after": map[string]string{"s": "0", "d": own}})
	ixn := preparedBytes(t, out)
	if code, out := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(ixn), "sigs": []string{appSign(t, k, ixn, false)}}); code != http.StatusCreated {
		t.Fatalf("the replacement: %d %v", code, out)
	}
	// As though filing had failed: the identity still holds the earlier keys.
	earlier := s.previousKeySetFor(own)
	if earlier == nil {
		t.Fatal("no earlier keyset was kept")
	}
	if err := s.putKeySet(own, earlier); err != nil {
		t.Fatal(err)
	}
	if code, out := call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
		map[string]any{"seed_hex": hex.EncodeToString(next)}); code != http.StatusOK || out["filed"] != "identity" {
		t.Fatalf("handing the seed of the keys the log anchors last again: %d %v", code, out)
	}
	if held, _ := s.keySetAnchorHeld(own, nextAnchor); !held {
		t.Fatal("the replacement the log anchors was not filed")
	}
	if got, _ := s.previousKeySetFor(own).Anchor(); !sameJSON(got, anchor) {
		t.Fatal("the keyset kept as previous is not the earlier one")
	}

	// Past its grace the replaced keyset is forgotten.
	didcommMu.Lock()
	keys, _ := s.loadDIDCommKeys()
	old, _ := json.Marshal(time.Now().Add(-previousKeySetGrace - time.Hour).UTC().Format(time.RFC3339))
	keys[previousKeySetSinceLabel(own)] = old
	_ = s.saveDIDCommKeys(keys)
	didcommMu.Unlock()
	if s.previousKeySetFor(own) != nil {
		t.Fatal("a replaced keyset still opens messages past its grace")
	}

	for _, label := range []string{previousKeySetLabel(own), pendingReplacementLabel(own),
		pendingKeySetLabel(nextAnchor), previousKeySetSinceLabel(own)} {
		if ok, _ := s.hasRecipientKeySet(label); ok {
			t.Fatalf("%s may be addressed as a recipient", label)
		}
	}
	if ok, _ := s.hasRecipientKeySet(own); !ok {
		t.Fatal("the identity itself is not a recipient")
	}
}

// anIdentityWithAppMessagingKeys founds an identity on a new core whose
// messaging keys the app chose, and returns the core, the identifier, the
// keyset's anchor and the seed of the key in force.
func anIdentityWithAppMessagingKeys(t *testing.T) (*CoreServer, string, map[string]interface{}, []byte) {
	t.Helper()
	s := appHeldCore(t)
	k := appSeeds(2)
	msgSeed := appSeeds(3)[2]
	anchor, err := keymath.MessagingKeySet(msgSeed)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := call(t, s, s.handleMessagingSeed, "/api/keystore/messaging-seed",
		map[string]any{"seed_hex": hex.EncodeToString(msgSeed)}); code != http.StatusOK {
		t.Fatalf("handing over the messaging seed: %d %v", code, out)
	}
	anchorJSON, _ := json.Marshal(anchor)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1",
		"a": []json.RawMessage{anchorJSON}})
	icp := preparedBytes(t, out)
	if code, out := call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}}); code != http.StatusCreated {
		t.Fatalf("the founding: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()
	return s, own.AID, anchor, k[0]
}
