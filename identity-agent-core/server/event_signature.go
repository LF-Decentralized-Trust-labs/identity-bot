package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"identity-agent-core/drivers"
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
	// Sigs are indexed signatures, for an event with several signers.
	Sigs []string `json:"sigs"`
}

// eventSigner is an engine that signs, in place, an event held unsigned.
type eventSigner interface {
	AttachSignatures(name string, sn int, raw []byte, sigs []string) ([]string, error)
}

// handleAttachEventSignature attaches signatures to an event an earlier version
// added to the log unsigned, and does nothing else (ADR-061 section 3).
//
// Those bytes are already in the log and may already be at witnesses, so
// signing them in place is the only way to make the log verify. The fence:
// only an event marked unsigned when this version first ran is accepted; the
// signatures must verify over its stored bytes and meet the rule for its type,
// with every event before it signed; no event is created and no field is
// changed. Every event added since the upgrade is added signed or not at all,
// so none of them is ever signed here.
//
// The route goes in the first release that no longer upgrades directly from a
// version that could add events unsigned.
func (s *CoreServer) handleAttachEventSignature(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "signing an event is for the owner of this agent", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyEventBody)
	var req attachSignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	sigs := req.Sigs
	if req.CesrSignature != "" {
		sigs = append([]string{req.CesrSignature}, sigs...)
	}
	if req.AID == "" || len(sigs) == 0 {
		writeError(w, http.StatusBadRequest, "Missing required fields",
			"aid and cesr_signature (or sigs) are required")
		return
	}

	event, err := s.eventAt(req.AID, req.SequenceNumber)
	if err != nil {
		writeError(w, http.StatusNotFound, "No such event", err.Error())
		return
	}
	if held := event.ControllerSignatures(); len(held) > 0 {
		// The same signature recorded again, as an older caller does with
		// the one it is handed back, changes nothing and is not refused.
		if signaturesHeld(held, sigs) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "signed", "aid": req.AID,
				"sequence_number": req.SequenceNumber})
			return
		}
		writeError(w, http.StatusConflict, "This event is already signed",
			"a signature is attached here only to an event added unsigned by an earlier version")
		return
	}
	if !event.UnsignedAtUpgrade {
		writeError(w, http.StatusConflict, "This event cannot be signed after it was added",
			"only an event an earlier version added unsigned is signed in place; every event since is added signed or not at all")
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
	signer, ok := s.KeriDriver.(eventSigner)
	if !ok || s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine here signs events in place", "")
		return
	}
	held, err := signer.AttachSignatures(req.AID, req.SequenceNumber, raw, sigs)
	if err != nil {
		writeEventError(w, err)
		return
	}

	event.Signatures, event.CesrSignature = held, held[0]
	if serr := s.DataStore.SaveEvent(*event); serr != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist the signature", serr.Error())
		return
	}
	log.Printf("[identity-agent-core] SIGNATURE: %s event sn=%d, added unsigned by an earlier version, is now signed",
		req.AID, req.SequenceNumber)

	// The identity's witnesses are brought up to date now the event can be
	// checked, through the one mechanism that keeps them up to date.
	if own, _ := s.DataStore.GetIdentity(); own != nil && own.AID == req.AID {
		s.witnessOwnLog()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "signed", "aid": req.AID,
		"sequence_number": req.SequenceNumber})
}

// signaturesHeld reports whether every signature offered is one already held,
// in whichever form, indexed or not, it was written.
func signaturesHeld(held, offered []string) bool {
	have := map[string]bool{}
	for _, h := range held {
		have[h] = true
		if c, err := drivers.ReadControllerSignature(h); err == nil {
			have[c.QB64] = true
		}
	}
	for _, o := range offered {
		c, err := drivers.ReadControllerSignature(o)
		if !have[o] && (err != nil || !have[c.QB64]) {
			return false
		}
	}
	return true
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
