package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// handleRevokeCredential marks a credential revoked WITHOUT deleting it, so the
// record survives for audit and anything bound to it (e.g. a capability grant) is
// denied on next use. This is the status-based revocation path — distinct from
// DELETE, which erases the record. (A cryptographic TEL revocation event, verifiable
// by third parties via a revocation registry, is tracked as separate follow-on work;
// this local status is authoritative for the issuer's own gateway today.)
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
	if err := s.DataStore.UpdateCredentialStatus(said, "revoked"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke credential", err.Error())
		return
	}
	log.Printf("[credential] revoked %s (schema %s, holder %s)", said, rec.SchemaSAID, rec.HolderAID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"said": said, "status": "revoked"})
}
