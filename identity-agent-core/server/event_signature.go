package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// Attaching the signature to a key event after the event exists.
//
// The order is forced by what a signature is over. Founding an identity
// produces the event, and only then are there bytes to sign — so the controller
// signs what came back and has to send it somewhere. There was nowhere to send
// it. The client computed the signature, returned it to its caller, and dropped
// it, so every identity founded this way stored its inception UNSIGNED.
//
// Nothing complained, because an unsigned event still has an identifier, still
// appears in the log, and still looks like an identity to its owner. What it
// cannot do is convince anybody else: a key history with an unsigned event in it
// is refused, so such an identity can never become a contact, never be
// established as a peer, and never have a credential accepted from it. It works
// perfectly alone and cannot participate.
//
// The signature is CHECKED here rather than filed. A signature that does not
// verify is worse than none: absent, the log says plainly that nothing shows who
// wrote the event; present and wrong, everything downstream reports the history
// as signed right up until a counterparty tries it.

type attachSignatureRequest struct {
	AID            string `json:"aid"`
	SequenceNumber int    `json:"sequence_number"`
	CesrSignature  string `json:"cesr_signature"`
}

func (s *CoreServer) handleAttachEventSignature(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "signing an event is for the owner of this agent", http.StatusForbidden)
		return
	}
	var req attachSignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.AID == "" || req.CesrSignature == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields",
			"aid and cesr_signature are required")
		return
	}

	event, err := s.eventAt(req.AID, req.SequenceNumber)
	if err != nil {
		writeError(w, http.StatusNotFound, "No such event", err.Error())
		return
	}
	if event.RawBytesB64 == "" {
		writeError(w, http.StatusConflict, "This event cannot be signed",
			"the bytes it was serialised as were not kept, so a signature over them could not be checked")
		return
	}
	raw, derr := base64.StdEncoding.DecodeString(event.RawBytesB64)
	if derr != nil {
		writeError(w, http.StatusInternalServerError, "Stored event bytes are unreadable", derr.Error())
		return
	}
	pub, perr := login.DecodeVerkey(event.PublicKey)
	if perr != nil {
		writeError(w, http.StatusConflict, "This event names no key to check a signature against",
			perr.Error())
		return
	}
	ok, verr := login.VerifyString(string(raw), req.CesrSignature, pub)
	if verr != nil || !ok {
		// Refused rather than stored. A signature that does not verify would
		// make the history report itself as signed, and the failure would then
		// surface only at a counterparty, who cannot tell a broken signature
		// from a forged identity.
		writeError(w, http.StatusBadRequest, "That signature does not cover this event",
			"it does not verify against the key this event names")
		return
	}

	event.CesrSignature = req.CesrSignature
	if serr := s.DataStore.SaveEvent(*event); serr != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist the signature", serr.Error())
		return
	}
	log.Printf("[identity-agent-core] SIGNATURE: %s event sn=%d is now signed",
		req.AID, req.SequenceNumber)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "signed", "aid": req.AID,
		"sequence_number": req.SequenceNumber})
}

func (s *CoreServer) eventAt(aid string, sn int) (*store.EventRecord, error) {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return nil, err
	}
	for i := range events {
		if events[i].SequenceNumber == sn {
			return &events[i], nil
		}
	}
	return nil, fmt.Errorf("%s has no event at sequence %d", aid, sn)
}
