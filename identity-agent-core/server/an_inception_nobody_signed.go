package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// Attaching the signature that makes a founding worth anything.
//
// FOUNDING IS TWO STEPS, and it has to be. The engine serialises the inception
// event; the signature is over those exact bytes; and the key that signs them is
// on the device that holds the recovery phrase, which is not this core. So there
// is nothing to sign until the event exists, and the event exists before anyone
// has signed it.
//
// That window was never closed. The application computed the signature
// correctly, held it in a field, and nothing ever read it — so every identity
// founded through it published a key history in which nobody had authorised
// anything. A counterparty checking properly refuses such a log, which means
// such an identity works alone and can convince nobody, and nothing said so at
// any point.
//
// WHAT THIS REFUSES IS THE POINT. It verifies the signature against the event's
// own canonical bytes and the key the identity was founded with, before storing
// it. Anything less would be a route for writing a chosen signature onto
// somebody's key history, which is worse than the gap it closes: an unsigned log
// is refused by everyone, and a wrongly signed one is refused by everyone while
// looking, to its owner, exactly like a good one.

type attachInceptionSignatureRequest struct {
	// AID is the identity whose founding event this signs. Named rather than
	// assumed, so a caller cannot attach to whatever happens to be here.
	AID string `json:"aid"`
	// CesrSignature is the CESR-encoded signature over the event's raw bytes.
	CesrSignature string `json:"cesr_signature"`
}

func (s *CoreServer) handleAttachInceptionSignature(w http.ResponseWriter, r *http.Request) {
	var req attachInceptionSignatureRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}
	aid := strings.TrimSpace(req.AID)
	sig := strings.TrimSpace(req.CesrSignature)
	if aid == "" || sig == "" {
		writeError(w, http.StatusBadRequest,
			"say which identity, and the signature over its founding event", "")
		return
	}

	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusConflict, "there is no identity here to sign for", "")
		return
	}
	if identity.AID != aid {
		// A signature is attached to THIS agent's own founding and nothing else.
		writeError(w, http.StatusForbidden,
			"this agent is a different identity", "")
		return
	}

	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not read this identity's key history", err.Error())
		return
	}
	var inception *store.EventRecord
	for i := range events {
		if events[i].SequenceNumber == 0 {
			inception = &events[i]
			break
		}
	}
	if inception == nil {
		writeError(w, http.StatusConflict,
			"this identity has no founding event to sign", "")
		return
	}
	if inception.RawBytesB64 == "" {
		// Without the bytes the engine produced there is nothing to check a
		// signature against, and storing one unchecked is the thing this route
		// exists to avoid.
		writeError(w, http.StatusConflict,
			"this founding event was stored without the bytes it was made from, "+
				"so no signature over it can be checked", "")
		return
	}

	raw, derr := base64.StdEncoding.DecodeString(inception.RawBytesB64)
	if derr != nil {
		writeError(w, http.StatusInternalServerError,
			"this founding event's bytes could not be read", derr.Error())
		return
	}

	// CHECKED BEFORE IT IS STORED, against the key this identity was founded
	// with. A route that wrote whatever it was handed would be a way to put a
	// chosen signature on somebody's key history — worse than the gap it
	// closes, because an unsigned log is refused by everybody while a wrongly
	// signed one looks right to its owner.
	key := inception.PublicKey
	if key == "" {
		key = identity.PublicKey
	}
	pub, kerr := login.DecodeVerkey(key)
	if kerr != nil {
		writeError(w, http.StatusInternalServerError,
			"this identity's own key could not be read", kerr.Error())
		return
	}
	ok, verr := login.VerifyString(string(raw), sig, pub)
	if verr != nil || !ok {
		writeError(w, http.StatusBadRequest,
			"that signature was not made over this founding event by this identity",
			fmt.Sprintf("%v", verr))
		return
	}

	inception.CesrSignature = sig
	if err := s.DataStore.SaveEvent(*inception); err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not record the signature", err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "aid": aid})
}

// theFoundingEventIsUnsigned reports whether this agent's own inception carries
// no signature.
//
// Asked so the agent can say so rather than serving a history nobody will
// accept and leaving its owner to find out from a stranger's refusal.
func (s *CoreServer) theFoundingEventIsUnsigned() bool {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return false
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		return false
	}
	for _, ev := range events {
		if ev.SequenceNumber == 0 {
			return ev.CesrSignature == ""
		}
	}
	return false
}
