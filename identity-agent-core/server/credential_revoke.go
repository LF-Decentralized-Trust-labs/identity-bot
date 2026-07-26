package server

import (
	"encoding/json"
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

	telRevoked := false
	if rec.RegistrySAID != "" && rec.IssSAID != "" && s.KeriDriver != nil {
		resp, rerr := s.KeriDriver.RevokeCredential(rec.IssuerAID, said, rec.RegistrySAID, rec.IssSAID)
		if rerr != nil {
			writeError(w, http.StatusInternalServerError, "TEL revocation failed", rerr.Error())
			return
		}
		// Persist the revocation anchor to the issuer KEL (the revocation proof).
		if identity, _ := s.DataStore.GetIdentity(); identity != nil {
			ixnJSON, _ := json.Marshal(resp.IxnEvent)
			if serr := s.DataStore.SaveEvent(store.EventRecord{
				AID:            rec.IssuerAID,
				SequenceNumber: resp.SequenceNumber,
				EventType:      "ixn",
				EventJSON:      string(ixnJSON),
				PublicKey:      identity.PublicKey,
				NextKeyDigest:  identity.NextKeyDigest,
				Timestamp:      rec.IssuedAt,
			}); serr != nil {
				log.Printf("[credential] failed to persist revocation anchor for %s: %v", said, serr)
			}
		}
		telRevoked = true
		log.Printf("[credential] TEL-revoked %s (rev %s, registry %s)", said, resp.RevSaid, rec.RegistrySAID)
	}

	if err := s.DataStore.UpdateCredentialStatus(said, "revoked"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke credential", err.Error())
		return
	}
	log.Printf("[credential] revoked %s (schema %s, holder %s, tel=%v)", said, rec.SchemaSAID, rec.HolderAID, telRevoked)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"said": said, "status": "revoked", "tel_revoked": telRevoked})
}
