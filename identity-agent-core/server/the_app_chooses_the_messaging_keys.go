package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// The app chooses the messaging keys; the core holds them (ADR-061 section 8).
//
// The core receives messages for the identity while the app is closed, so it
// holds the messaging keys' private halves. Where the app holds the
// identity's key, the app chooses them: it derives the messaging seed from its
// phrase, hands the core that one hardened child here, and checks the anchor
// the core answers with against its own before anchoring it. The seed lets the
// core read and sign messages for the identity, which is its job, and gives it
// no part of the signing or pre-rotation keys.

// pendingKeySetLabel is where a keyset handed over before the identity exists
// is filed until the founding that anchors it is committed.
func pendingKeySetLabel(anchor map[string]interface{}) string {
	b, _ := json.Marshal(anchor)
	d, _ := iacrypto.Blake3QB64(b)
	return "pending-messaging:" + d
}

func (s *CoreServer) handleMessagingSeed(w http.ResponseWriter, r *http.Request) {
	if !s.theOwnerAsks(r) {
		writeError(w, http.StatusForbidden, "Messaging keys are the owner's", "")
		return
	}
	var req struct {
		SeedHex string `json:"seed_hex"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", "seed_hex is required")
		return
	}
	seed, err := hex.DecodeString(req.SeedHex)
	if err != nil || len(seed) != 32 {
		writeError(w, http.StatusBadRequest, "seed_hex is not a 32-byte seed in hexadecimal", "")
		return
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	ks, err := didcomm.DeriveKeySet("", seed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "The messaging keys could not be derived", "")
		return
	}
	anchor, err := ks.Anchor()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The messaging keys could not be anchored", err.Error())
		return
	}
	// An identity already here takes only the keyset its founding anchors,
	// the one every verifier reads (an identity restored here, say). Before
	// founding it is held aside until the founding that anchors it is
	// committed. No seed handed over here stands in for keys the identity's
	// founding does not commit to.
	label, filed := pendingKeySetLabel(anchor), "pending"
	if own, _ := s.DataStore.GetIdentity(); own != nil {
		if !s.anchoredAtFounding(own.AID, anchor) {
			writeError(w, http.StatusConflict, "These are not the messaging keys this identity's founding anchors",
				"replacing an identity's messaging keys is not done here yet")
			return
		}
		if held, _ := s.keySetAnchorHeld(own.AID, anchor); held {
			writeJSONResponse(w, map[string]any{"anchor": anchor, "filed": "identity"})
			return
		}
		if has, _ := s.hasKeySet(own.AID); has {
			writeError(w, http.StatusConflict, "This identity holds other messaging keys", "")
			return
		}
		label, filed = own.AID, "identity"
	}
	if held, err := s.hasKeySet(label); err != nil {
		writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be read", err.Error())
		return
	} else if !held {
		if err := s.storeKeySetFor(label, ks); err != nil {
			writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be kept", err.Error())
			return
		}
	}
	writeJSONResponse(w, map[string]any{"anchor": anchor, "filed": filed})
}

// keySetAnchorHeld reports whether the keyset filed under label is the one
// anchor commits to.
func (s *CoreServer) keySetAnchorHeld(label string, anchor map[string]interface{}) (bool, error) {
	has, err := s.hasKeySet(label)
	if err != nil || !has {
		return false, err
	}
	ks, err := s.keySetFor(label)
	if err != nil {
		return false, err
	}
	held, err := ks.Anchor()
	if err != nil {
		return false, err
	}
	a, _ := json.Marshal(held)
	b, _ := json.Marshal(anchor)
	return string(a) == string(b), nil
}

// messagingAnchorsIn are the IA-HYBRID-1 keyset anchors an event carries.
func messagingAnchorsIn(raw []byte) []map[string]interface{} {
	var ev struct {
		A []json.RawMessage `json:"a"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	return messagingAnchorsAmong(ev.A)
}

// messagingSealsAmong are the IA-HYBRID-1 keyset anchors among an event's
// seals, as the event carries them: the one reading of which seal commits to
// messaging keys.
func messagingSealsAmong(seals []json.RawMessage) []json.RawMessage {
	var out []json.RawMessage
	for _, a := range seals {
		var probe struct {
			IA string `json:"ia"`
		}
		if json.Unmarshal(a, &probe) == nil && probe.IA == iacrypto.CipherSuiteIAHybrid1 {
			out = append(out, a)
		}
	}
	return out
}

// messagingAnchorsAmong is messagingSealsAmong, each read into a map.
func messagingAnchorsAmong(seals []json.RawMessage) []map[string]interface{} {
	var out []map[string]interface{}
	for _, a := range messagingSealsAmong(seals) {
		var m map[string]interface{}
		if json.Unmarshal(a, &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// refuseAnUnheldKeySet answers an event that anchors a messaging keyset this
// Identity Agent does not hold: it would commit the identity to keys whose
// private halves nobody here has, and messages sent to it would be lost.
//
// An interaction anchoring a keyset other than the one held is refused too:
// every verifier reads an identity's messaging keys from its founding, and the
// earlier keys must stay live until a replacement is witnessed, so replacing a
// keyset waits until both are built.
func (s *CoreServer) refuseAnUnheldKeySet(w http.ResponseWriter, raw []byte, aid string) bool {
	if ev, err := keri.ParseEvent(raw); err == nil && ev.Ilk != "icp" {
		for _, anchor := range messagingAnchorsIn(raw) {
			if held, _ := s.keySetAnchorHeld(aid, anchor); !held {
				writeError(w, http.StatusConflict, "messaging_keyset_replacement_not_supported",
					"an identity's messaging keys are the ones its founding anchors; replacing them is not done here yet")
				return true
			}
		}
		return false
	}
	for _, anchor := range messagingAnchorsIn(raw) {
		heldHere, _ := s.keySetAnchorHeld(aid, anchor)
		pending, _ := s.keySetAnchorHeld(pendingKeySetLabel(anchor), anchor)
		if !heldHere && !pending {
			writeError(w, http.StatusBadRequest, "messaging_keyset_not_held",
				"the event anchors messaging keys this Identity Agent does not hold; hand it the messaging seed first "+
					"(POST /api/keystore/messaging-seed)")
			return true
		}
	}
	return false
}

// anchoredAtFounding reports whether aid's stored founding anchors this
// keyset: the anchor every verifier reads an identity's messaging keys from.
func (s *CoreServer) anchoredAtFounding(aid string, anchor map[string]interface{}) bool {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil || len(events) == 0 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(events[0].RawBytesB64)
	if err != nil {
		return false
	}
	want, _ := json.Marshal(anchor)
	for _, a := range messagingAnchorsIn(raw) {
		if got, _ := json.Marshal(a); string(got) == string(want) {
			return true
		}
	}
	return false
}

// fileCommittedKeySet files a keyset held aside under the identity whose
// founding anchoring it was just committed.
func (s *CoreServer) fileCommittedKeySet(raw []byte, aid string) error {
	for _, anchor := range messagingAnchorsIn(raw) {
		label := pendingKeySetLabel(anchor)
		if held, _ := s.keySetAnchorHeld(label, anchor); !held {
			continue
		}
		if has, _ := s.hasKeySet(aid); has {
			continue
		}
		ks, err := s.keySetFor(label)
		if err != nil {
			return err
		}
		if err := s.storeKeySetFor(aid, ks); err != nil {
			return err
		}
		return s.forgetKeySet(label)
	}
	return nil
}

// forgetKeySet removes the keyset filed under label, once it is filed under
// the identity it belongs to.
func (s *CoreServer) forgetKeySet(label string) error {
	didcommMu.Lock()
	defer didcommMu.Unlock()
	keys, err := s.loadDIDCommKeys()
	if err != nil {
		return err
	}
	delete(keys, label)
	return s.saveDIDCommKeys(keys)
}
