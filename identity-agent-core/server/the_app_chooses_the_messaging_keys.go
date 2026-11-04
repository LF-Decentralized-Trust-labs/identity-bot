package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"identity-agent-core/messagingkeys"
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
	// An identity already here files at once only the keyset its log anchors
	// last, the one every verifier reads (an identity restored here, say).
	// Any other keyset is held aside, as one before founding is, until an
	// event anchoring it is committed: a replacement (ADR-061 section 8). No
	// seed handed over here stands in for keys the identity's log does not
	// commit to.
	label, filed := pendingKeySetLabel(anchor), "pending"
	if own, _ := s.DataStore.GetIdentity(); own != nil {
		if !s.anchoredLast(own.AID, anchor) {
			// A replacement not yet anchored: held in the identity's one
			// replacement slot, in place of any earlier one.
			if err := s.putKeySet(pendingReplacementLabel(own.AID), ks); err != nil {
				writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be kept", err.Error())
				return
			}
			writeJSONResponse(w, map[string]any{"anchor": anchor, "filed": "pending"})
			return
		}
		if held, _ := s.keySetAnchorHeld(own.AID, anchor); held {
			writeJSONResponse(w, map[string]any{"anchor": anchor, "filed": "identity"})
			return
		}
		// The log anchors these keys last and the identity holds others: a
		// replacement whose filing did not finish when it was committed. The
		// seed proves the keys, and the log says they are in force.
		if has, _ := s.hasKeySet(own.AID); has {
			if err := s.replaceKeySetFor(own.AID, ks); err != nil {
				writeError(w, statusForUnreadable(err, http.StatusInternalServerError), "The messaging keys could not be kept", err.Error())
				return
			}
			_ = s.forgetKeySet(pendingReplacementLabel(own.AID))
			writeJSONResponse(w, map[string]any{"anchor": anchor, "filed": "identity"})
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
// seals (messagingkeys.SealsAmong).
func messagingSealsAmong(seals []json.RawMessage) []json.RawMessage {
	return messagingkeys.SealsAmong(seals)
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
// A later event may anchor a replacement keyset (ADR-061 section 8) once its
// seed has been handed over and held aside; when it is committed the
// replacement takes the earlier keyset's place, and the earlier one is kept to
// open messages already sent to it.
func (s *CoreServer) refuseAnUnheldKeySet(w http.ResponseWriter, raw []byte, aid string) bool {
	if title, detail := s.unheldKeySetRefusal(raw, aid); title != "" {
		writeError(w, http.StatusBadRequest, title, detail)
		return true
	}
	return false
}

// unheldKeySetRefusal is refuseAnUnheldKeySet's judgement: the refusal's title
// and detail, empty when raw anchors no keyset this Identity Agent lacks.
func (s *CoreServer) unheldKeySetRefusal(raw []byte, aid string) (title, detail string) {
	anchors := messagingAnchorsIn(raw)
	if len(anchors) > 1 {
		return "one_messaging_keyset_per_event",
			"an event anchors at most one messaging keyset: the one the identity is reached on after it"
	}
	for _, anchor := range anchors {
		heldHere, _ := s.keySetAnchorHeld(aid, anchor)
		pending, _ := s.keySetAnchorHeld(pendingKeySetLabel(anchor), anchor)
		replacing, _ := s.keySetAnchorHeld(pendingReplacementLabel(aid), anchor)
		if !heldHere && !pending && !replacing {
			return "messaging_keyset_not_held",
				"the event anchors messaging keys this Identity Agent does not hold; hand it the messaging seed first " +
					"(POST /api/keystore/messaging-seed)"
		}
	}
	return "", ""
}

// anchoredLast reports whether anchor is the messaging keyset aid's log
// anchors last: the one the identity is reached on (ADR-061 section 9). For a
// newly founded identity that is its founding's; for one recovered after its
// keys were replaced, the replacement's.
func (s *CoreServer) anchoredLast(aid string, anchor map[string]interface{}) bool {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil || len(events) == 0 {
		return false
	}
	var last map[string]interface{}
	for _, ev := range events {
		raw, err := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		if err != nil {
			return false
		}
		if found := messagingAnchorsIn(raw); len(found) > 0 {
			last = found[len(found)-1]
		}
	}
	if last == nil {
		return false
	}
	want, _ := json.Marshal(anchor)
	got, _ := json.Marshal(last)
	return string(got) == string(want)
}

// fileCommittedKeySet files a keyset held aside under the identity whose
// event anchoring it was just committed: a founding's, or a replacement's,
// which takes the earlier keyset's place and keeps it as the previous one.
func (s *CoreServer) fileCommittedKeySet(raw []byte, aid string) error {
	for _, anchor := range messagingAnchorsIn(raw) {
		label := ""
		for _, l := range []string{pendingReplacementLabel(aid), pendingKeySetLabel(anchor)} {
			if held, _ := s.keySetAnchorHeld(l, anchor); held {
				label = l
				break
			}
		}
		if label == "" {
			continue
		}
		ks, err := s.keySetFor(label)
		if err != nil {
			return err
		}
		if has, _ := s.hasKeySet(aid); has {
			if same, _ := s.keySetAnchorHeld(aid, anchor); same {
				return s.forgetKeySet(label)
			}
			err = s.replaceKeySetFor(aid, ks)
		} else {
			err = s.storeKeySetFor(aid, ks)
		}
		if err != nil {
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
