package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// Installing an identity's key log on an Identity Agent that has none, from
// the log alone (ADR-061 section 10).
//
// A person recovering onto a new device has their phrase and a copy of their
// identity's log, read from its witnesses. The app checks that log is its
// phrase's, and installs it in its new core here. The core installs it only
// after verifying the whole chain, every digest, signature, commitment opened
// and threshold, with the one log verifier; it installs no seed, because the
// key stays where the phrase is.
func (s *CoreServer) handleRestoreIdentity(w http.ResponseWriter, r *http.Request) {
	if !s.theOwnerAsks(r) {
		writeError(w, http.StatusForbidden, "Installing an identity is the owner's", "")
		return
	}
	var req keyStateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKeyStateBody)).Decode(&req); err != nil || req.AID == "" {
		writeError(w, http.StatusBadRequest, "aid and events are required", "")
		return
	}
	if req.StreamB64 != "" {
		writeError(w, http.StatusBadRequest, "Send the log as events",
			"each event's bytes and its signatures, so each is stored as it was signed")
		return
	}
	messages, err := keyStateMessages(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "The key log is unreadable", err.Error())
		return
	}
	state, err := KeyStateOf(req.AID, messages)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "The key log does not verify, so it is not installed", err.Error())
		return
	}
	raws := make([][]byte, 0, len(req.Events))
	given := make([][]string, 0, len(req.Events))
	for _, ev := range req.Events {
		raw, _ := base64.StdEncoding.Strict().DecodeString(ev.RawB64)
		raws, given = append(raws, raw), append(given, ev.Sigs)
	}
	// The gate a founding passes, owner named or not, since this installs an
	// identity just as founding one does.
	s.founding.Lock()
	defer s.founding.Unlock()
	if !s.mayFoundHere(w, ownerNamedIn(raws[0])) {
		return
	}
	// Only the signatures that verify are kept: a copy read from a witness may
	// carry others beside them, and what is kept here is published again.
	kept, err := keriengine.VerifiedSignatures(raws, given)
	if err != nil {
		writeError(w, http.StatusBadRequest, "An event is unreadable", err.Error())
		return
	}
	records := make([]store.EventRecord, 0, len(raws))
	for i, raw := range raws {
		rec, err := eventRecordOf(req.AID, i, raw, kept[i])
		if err != nil {
			writeError(w, http.StatusBadRequest, "An event is unreadable", err.Error())
			return
		}
		records = append(records, rec)
	}
	if err := s.DataStore.SaveRestoredIdentity(records, store.IdentityState{AID: req.AID, PublicKey: state.K[0],
		NextKeyDigest: firstOr(state.N), Created: time.Now().UTC().Format(time.RFC3339),
		EventCount: len(records)}); err != nil {
		writeError(w, http.StatusInternalServerError, "The identity could not be stored", err.Error())
		return
	}
	s.reloadIdentityIntoDriver()
	log.Printf("[identity-agent-core] RESTORE: installed the verified key log of %s (%d events)", req.AID, len(records))
	go s.witnessOwnLog()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"status": "restored", "aid": req.AID, "key_state": state})
}

func firstOr(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}
