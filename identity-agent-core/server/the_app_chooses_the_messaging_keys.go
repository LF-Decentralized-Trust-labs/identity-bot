package server

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
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
	if !s.isOwner(r) {
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
	label := pendingKeySetLabel(anchor)
	if own, _ := s.DataStore.GetIdentity(); own != nil {
		// An identity already founded here: its keyset is filed under it.
		label = own.AID
	}
	if held, err := s.hasKeySet(label); err != nil {
		writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be read", err.Error())
		return
	} else if !held {
		if err := s.storeKeySetFor(label, ks); err != nil {
			writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be kept", err.Error())
			return
		}
	} else if held, _ := s.keySetAnchorHeld(label, anchor); !held {
		writeError(w, http.StatusConflict, "This identity already holds other messaging keys",
			"replacing a keyset is done by anchoring the new one in an interaction")
		return
	}
	writeJSONResponse(w, map[string]any{"anchor": anchor})
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
	var out []map[string]interface{}
	for _, a := range ev.A {
		var m map[string]interface{}
		if json.Unmarshal(a, &m) == nil && m["ia"] == iacrypto.CipherSuiteIAHybrid1 {
			out = append(out, m)
		}
	}
	return out
}

// refuseAnUnheldKeySet answers an event that anchors a messaging keyset this
// Identity Agent does not hold: it would commit the identity to keys whose
// private halves nobody here has, and messages sent to it would be lost.
func (s *CoreServer) refuseAnUnheldKeySet(w http.ResponseWriter, raw []byte, aid string) bool {
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

// fileCommittedKeySet files a keyset handed over before the founding under the
// identity the founding made, once that founding is committed.
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
