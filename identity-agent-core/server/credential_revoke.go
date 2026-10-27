package server

import (
	"encoding/json"
	"errors"
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

	telRevoked, status, err := s.withdrawCredential(rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TEL revocation failed", err.Error())
		return
	}
	log.Printf("[credential] %s %s (schema %s, holder %s, tel=%v)", status, said, rec.SchemaSAID, rec.HolderAID, telRevoked)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"said": said, "status": status, "tel_revoked": telRevoked})
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
	keptInside := s.engineKeepsCredentialLogs()
	resp, err := s.KeriDriver.RevokeCredential(rec.IssuerAID, rec.SAID, rec.RegistrySAID, rec.IssSAID)
	if err == nil && !keptInside {
		err = s.keepAfter(rec.IssuerAID, resp.SequenceNumber, resp.IxnRawBytesB64, resp.RevRawBytesB64)
	}
	if err != nil {
		return false, fmt.Errorf("the revocation of %s was not made: %w", rec.SAID, err)
	}
	log.Printf("[credential] TEL-revoked %s (rev %s, registry %s)", rec.SAID, resp.RevSaid, rec.RegistrySAID)
	return true, nil
}

// withdrawCredential withdraws a credential this identity issued and records
// it so, returning whether its revocation is in the registry's log now and
// the status it is left with.
//
// Where the identity's key is on another device nothing is written into the
// key log here: the credential is marked withdrawing, which is never in
// force, and its revocation is asked of that device on the signing-request
// queue (the_device_log_is_adopted.go). It is revoked when that is signed.
func (s *CoreServer) withdrawCredential(rec *store.CredentialRecord) (bool, string, error) {
	if s.withdrawnByTheDevice(rec) {
		if err := s.DataStore.UpdateCredentialStatus(rec.SAID, credentialStatusWithdrawing); err != nil {
			return false, "", err
		}
		if err := s.queueRevocation(rec.SAID); err != nil && !errors.Is(err, errAlreadyAsked) {
			return false, credentialStatusWithdrawing, fmt.Errorf("it is no longer in force here, and its withdrawal could not be asked for: %w", err)
		}
		s.withdrawLentGitHubAccessNoLongerGranted("a credential is being withdrawn")
		return false, credentialStatusWithdrawing, nil
	}
	revoked, err := s.revokeIssuedCredential(rec)
	if err != nil {
		return false, "", err
	}
	err = s.DataStore.UpdateCredentialStatus(rec.SAID, "revoked")
	// What was lent on the strength of a grant or a body's credential is
	// withdrawn once the credential is: revoking an AI agent ends its access at
	// once, not when what it was lent lapses.
	s.withdrawLentGitHubAccessNoLongerGranted("a credential was revoked")
	return revoked, "revoked", err
}

// withdrawnByTheDevice reports whether a credential's revocation must be
// signed on the device that holds the issuer's key.
func (s *CoreServer) withdrawnByTheDevice(rec *store.CredentialRecord) bool {
	if rec == nil || rec.RegistrySAID == "" || rec.IssSAID == "" {
		return false
	}
	identity, err := s.DataStore.GetIdentity()
	return err == nil && identity != nil && identity.AID == rec.IssuerAID && s.keyIsElsewhere()
}
