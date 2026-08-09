package server

import (
	"encoding/json"
	"log"
	"net/http"

	"identity-agent-core/iacrypto"
)

// Founding an identity somewhere other than here.
//
// On a computer the agent builds the inception itself, so it mints the
// messaging keys first and writes them into the event — the identifier then
// commits to the keys people encrypt to it with, and nothing has to be fetched
// or believed.
//
// On a phone the event is built by the local KERI engine and only the result is
// handed here. That path got neither: no keys derived from the recovery phrase,
// and an inception committing to nothing. Such an identity is refused by every
// counterparty as untied, so it can never be established as a peer — and its
// messaging keys, minted at random on first use, do not come back from the
// recovery phrase.
//
// The keys are still derived HERE rather than duplicated into the other engine.
// This is where the root seed lives and where the derivation is already
// written, and a second implementation of it is a second thing to keep in
// agreement — which is exactly how the two halves of a keyset come to disagree.
// So the caller asks for the seal, puts it in the event it is about to build,
// and hands back the result.

// handlePrepareMessagingKeys returns the seal an identity should commit to.
//
// Called BEFORE the identity exists, because the identifier is derived from an
// event that has to contain this. Deterministic: asking twice yields the same
// keys, so a caller that retries does not strand the first set.
func (s *CoreServer) handlePrepareMessagingKeys(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "preparing an identity's keys is for the owner of this agent", http.StatusForbidden)
		return
	}
	ks, _, err := s.deriveMessagingKeys("")
	if err != nil {
		writeError(w, http.StatusConflict, "Could not derive this identity's messaging keys", err.Error())
		return
	}
	kem, err := ks.KemPub.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not encode the messaging keys", err.Error())
		return
	}
	dsa, err := ks.DsaPub.MarshalBinary()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not encode the messaging keys", err.Error())
		return
	}
	anchor, err := iacrypto.KeySetAnchor(ks.XPub[:], kem, ks.EdPub, dsa)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not build the commitment", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		// Named as it appears in the event, so a caller has nothing to
		// translate and no opportunity to translate it wrongly.
		"anchor": anchor,
	})
}

// fileMessagingKeysFor files the derived keyset under an identity founded
// elsewhere.
//
// Separate from preparing them because the identifier does not exist until the
// event has been built. Same keys either way: derivation is from the root seed
// at a recorded branch, so this is the same set that was sealed into the event.
func (s *CoreServer) fileMessagingKeysFor(aid string) error {
	if aid == "" || s.hasKeySet(aid) {
		return nil
	}
	ks, idx, err := s.deriveMessagingKeys(aid)
	if err != nil {
		return err
	}
	if err := s.storeKeySetFor(aid, ks); err != nil {
		return err
	}
	return s.recordMessagingKeyIndex(aid, idx)
}

// warnIfIdentityCommitsToNothing says so when an identity has been founded
// without committing to its messaging keys.
//
// Said plainly rather than left to be discovered. Such an identity works
// perfectly alone and is refused by every counterparty as untied, and the
// symptom — nobody can ever establish it as a peer — points nowhere near the
// cause.
func warnIfIdentityCommitsToNothing(aid, eventJSON string) {
	if eventJSON == "" {
		return
	}
	var ev map[string]interface{}
	if json.Unmarshal([]byte(eventJSON), &ev) != nil {
		return
	}
	if _, _, err := iacrypto.AnchoredAgreementKeys(ev); err != nil {
		log.Printf("[identity-agent-core] WARNING: %s was founded without committing to its "+
			"messaging keys, so no counterparty can tie those keys to it and it can never be "+
			"established as a peer. An inception cannot be amended; this identity would have to "+
			"be founded again.", aid)
	}
}
