package server

import (
	"log"
	"net/http"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/endpointrecord"
	"identity-agent-core/internal/jsonreply"
)

// GET /api/identity/proof?aid=&origin=&challenge=
//
// An Identity Agent signing a challenge with the keys its identifier has in
// force, so that a party at an address can tell the agent from a proxy of its
// public key log (ADR-062, "An address also proves it holds the keys").
//
// Open to anybody, for the reason /api/attestation is: the asker is deciding
// whether to trust this address and holds nothing yet. It discloses only what
// the identifier's published keys already are, and signs only a statement of
// its own form (didcomm.KeyProofInput), never a string a caller supplies, so
// it cannot be made to sign something that reads as another thing.
//
// The asker names the origin it dialled, and this agent signs only for an
// origin that is its own (isOneOfThisAgentsOrigins). A proxy that relays the
// request therefore either is refused here, or relays an answer for an address
// that is not the one the asker dialled, which the asker refuses.
//
// Only an identifier this agent already holds messaging keys for is answered;
// an anonymous caller cannot make it mint any (the same bound as
// handleGetDIDCommDID's).
func (s *CoreServer) handleIdentityProof(w http.ResponseWriter, r *http.Request) {
	if !s.proofLimiter.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "1")
		jsonError(w, "too many requests from this address", http.StatusTooManyRequests)
		return
	}
	// Signed for exactly one asker and exactly one moment.
	w.Header().Set("Cache-Control", "no-store")

	q := r.URL.Query()
	challenge, origin := q.Get("challenge"), q.Get("origin")
	if err := checkChallengeShape(challenge); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := endpointrecord.CheckOrigin(origin); err != nil {
		jsonError(w, "origin: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.isOneOfThisAgentsOrigins(origin) {
		jsonError(w, "this request is for "+origin+", which is not an address of this Identity Agent. "+
			"If it is reached at that address, set PUBLIC_URL to it", http.StatusForbidden)
		return
	}

	identity, err := s.DataStore.GetIdentity()
	aid := q.Get("aid")
	if aid == "" && err == nil && identity != nil {
		aid = identity.AID
	}
	if aid == "" {
		jsonError(w, "aid is required", http.StatusBadRequest)
		return
	}
	has, herr := s.hasKeySet(aid)
	if herr != nil {
		jsonError(w, "this Identity Agent cannot read its messaging keys right now",
			http.StatusServiceUnavailable)
		return
	}
	if !has {
		jsonError(w, "no messaging keys are held for that aid", http.StatusNotFound)
		return
	}
	ks, kerr := s.keySetFor(aid)
	if kerr != nil {
		log.Printf("[proof] the keys of %s could not be had: %v", aid, kerr)
		jsonError(w, "this Identity Agent cannot give its messaging keys right now",
			statusForUnreadable(kerr, http.StatusInternalServerError))
		return
	}

	// The identity's own signature over the keys, as handleGetDIDCommDID gives,
	// for an identifier whose log anchors no keyset. Only for this agent's own
	// identity: vouchForKeys signs with that identity's key and no other's.
	kelSig := ""
	if err == nil && identity != nil && identity.AID == aid {
		if did, derr := ks.DID(); derr == nil {
			s.vouchForKeys(did)
			kelSig = did.KelSig
		}
	}

	proof, perr := didcomm.ProveKeysInForce(ks, kelSig, origin, challenge, time.Now())
	if perr != nil {
		log.Printf("[proof] could not sign for %s: %v", aid, perr)
		jsonError(w, "this Identity Agent cannot sign right now", http.StatusInternalServerError)
		return
	}
	jsonreply.Write(w, http.StatusOK, proof)
}
