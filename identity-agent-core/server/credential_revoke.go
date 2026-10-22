package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// handleRevokeCredential revokes a credential. For a registry-backed credential it
// emits a cryptographic TEL revocation (rev) event anchored in the issuer KEL — that
// seal in the issuer's signed KEL is a third-party-verifiable revocation proof —
// then marks the record revoked. For a legacy credential it falls back to a local
// status change. Either way the record is kept for audit (distinct from DELETE),
// and anything bound to it (e.g. a capability grant) is denied on next use.
func (s *CoreServer) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	if said == "" {
		writeError(w, http.StatusBadRequest, "Missing SAID", "credential SAID is required")
		return
	}
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		writeError(w, http.StatusNotFound, "Credential not found", said)
		return
	}
	if rec.Status == "revoked" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"said": said, "status": "revoked", "already": true})
		return
	}

	telRevoked, err := s.revokeIssuedCredential(rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TEL revocation failed", err.Error())
		return
	}

	if err := s.DataStore.UpdateCredentialStatus(said, "revoked"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke credential", err.Error())
		return
	}
	log.Printf("[credential] revoked %s (schema %s, holder %s, tel=%v)", said, rec.SchemaSAID, rec.HolderAID, telRevoked)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"said": said, "status": "revoked", "tel_revoked": telRevoked})
}

// revokeIssuedCredential writes the revocation of a credential this identity
// issued into its registry's log, and anchors it in the issuer's key log, which
// is the proof anybody else checks. A credential issued outside a registry has
// no log to write to, and reports false.
//
// It does not change the stored status; the caller does, once it has decided
// the revocation is the one it meant.
//
// The revocation and its anchor are kept together before this returns. If they
// cannot be, the revocation fails and the caller leaves the credential as it
// was: nothing is recorded as revoked that cannot be proved revoked. Two
// revocations of one credential at once make one: the second finds the first
// already kept and reports it.
func (s *CoreServer) revokeIssuedCredential(rec *store.CredentialRecord) (bool, error) {
	if rec.RegistrySAID == "" || rec.IssSAID == "" || s.KeriDriver == nil {
		return false, nil
	}
	defer lockCredential(rec.SAID)()
	if s.alreadyRevoked(rec.RegistrySAID, rec.SAID) {
		return true, nil
	}
	resp, err := s.KeriDriver.RevokeCredential(rec.IssuerAID, rec.SAID, rec.RegistrySAID, rec.IssSAID)
	if err != nil {
		return false, err
	}
	if err := s.keepAnchoredCredentialEvent(rec.RegistrySAID, rec.SAID, resp.RevRawBytesB64,
		rec.IssuerAID, resp.IxnEvent, resp.IxnRawBytesB64, resp.SequenceNumber); err != nil {
		return false, fmt.Errorf("the revocation of %s could not be kept, so it was not made: %w", rec.SAID, err)
	}
	log.Printf("[credential] TEL-revoked %s (rev %s, registry %s)", rec.SAID, resp.RevSaid, rec.RegistrySAID)
	return true, nil
}
