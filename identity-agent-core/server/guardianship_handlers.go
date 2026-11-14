package server

import (
	"encoding/json"
	"fmt"
	"identity-agent-core/schemas"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"identity-agent-core/store"

	"identity-agent-core/internal/jsonreply"
)

// guardianshipRoutes registers /api/guardianship endpoints.
func (s *CoreServer) guardianshipRoutes(r chi.Router) {
	r.Route("/guardianship", func(r chi.Router) {
		r.Get("/", s.handleListGuardianships)
		r.Post("/", s.handleCreateGuardianship)
		r.Get("/{id}", s.handleGetGuardianship)
		r.Put("/{id}", s.handleUpdateGuardianship)
		r.Delete("/{id}", s.handleDeleteGuardianship)
		r.Post("/{id}/emancipate", s.handleEmancipateGuardianship)
	})
}

// handleListGuardianships returns all guardianship relationships.
func (s *CoreServer) handleListGuardianships(w http.ResponseWriter, r *http.Request) {
	records, err := s.DataStore.GetGuardianships()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list guardianships", err.Error())
		return
	}

	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"guardianships": records,
		"count":         len(records),
	})
}

// handleCreateGuardianship creates a new guardianship relationship.
func (s *CoreServer) handleCreateGuardianship(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type                 string                      `json:"type"`
		DependentName        string                      `json:"dependent_name"`
		DependentAID         string                      `json:"dependent_aid"`
		HostingType          string                      `json:"hosting_type"`
		HostingURL           string                      `json:"hosting_url"`
		EmancipationTrigger  *store.EmancipationTrigger  `json:"emancipation_trigger"`
		MultisigParticipants []store.MultisigParticipant `json:"multisig_participants"`
		MultisigThreshold    int                         `json:"multisig_threshold"`
		Metadata             map[string]string           `json:"metadata"`
	}
	// A guardian is a key in the dependent's key set, never an identifier, so a
	// body that names one (the delegation-era fields) is refused, not ignored.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if err := checkMultisig(req.MultisigParticipants, req.MultisigThreshold); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multi-signature", err.Error())
		return
	}

	// The credential issued for a guardianship is held to its schema before the
	// guardianship is made, so the type is checked against the schema's own
	// allowed values and not a second list of them kept here.
	claims := map[string]interface{}{
		"dependent_name": req.DependentName,
		"guardian_type":  req.Type,
	}
	if req.DependentAID != "" {
		claims["dependent_aid"] = req.DependentAID
	}
	if err := schemas.Guardianship.CheckClaims(claims); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid guardianship type", err.Error())
		return
	}
	if req.DependentName == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "dependent_name is required")
		return
	}
	validHosting := map[string]bool{"cloud": true, "device": true}
	if req.HostingType != "" && !validHosting[req.HostingType] {
		writeError(w, http.StatusBadRequest, "Invalid hosting type", "hosting_type must be 'cloud' or 'device'")
		return
	}
	if req.HostingType == "" {
		req.HostingType = "cloud"
	}

	// Get current identity AID as the guardian
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusPreconditionFailed, "No identity initialized", "Create an identity before adding dependents")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	record := store.GuardianshipRecord{
		ID:                   uuid.New().String(),
		Type:                 req.Type,
		DependentAID:         req.DependentAID,
		DependentName:        req.DependentName,
		Status:               "active",
		HostingType:          req.HostingType,
		HostingURL:           req.HostingURL,
		CreatedAt:            now,
		UpdatedAt:            now,
		EmancipationTrigger:  req.EmancipationTrigger,
		MultisigParticipants: req.MultisigParticipants,
		MultisigThreshold:    req.MultisigThreshold,
		Metadata:             req.Metadata,
	}
	if record.MultisigParticipants == nil {
		record.MultisigParticipants = []store.MultisigParticipant{}
	}
	if record.Metadata == nil {
		record.Metadata = map[string]string{}
	}

	if err := s.DataStore.SaveGuardianship(record); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create guardianship", err.Error())
		return
	}

	// Auto-issue a Guardianship Credential ACDC so the SAID can serve as a chain-of-trust anchor.
	// This runs synchronously — failure is non-fatal (guardianship record still created).
	if s.KeriDriver != nil {
		guardianshipSchemaSAID := schemas.Guardianship.SAID
		if result, err := s.KeriDriver.IssueCredential(identity.AID, claims, guardianshipSchemaSAID, identity.AID, nil); err == nil {
			record.CredentialSAID = result.AcdcSaid
			if saveErr := s.DataStore.SaveGuardianship(record); saveErr != nil {
				log.Printf("[guardianship] Warning: failed to store guardianship credential SAID %s: %v", result.AcdcSaid, saveErr)
			} else {
				log.Printf("[guardianship] Issued guardianship credential %s for %s", result.AcdcSaid, record.DependentName)
			}
		} else {
			log.Printf("[guardianship] Warning: failed to auto-issue guardianship credential: %v", err)
		}
	}

	log.Printf("[guardianship] Created guardianship %s: type=%s dependent=%s hosting=%s",
		record.ID, record.Type, record.DependentName, record.HostingType)

	jsonreply.Write(w, http.StatusCreated, record)
}

// handleGetGuardianship returns a single guardianship by ID.
func (s *CoreServer) handleGetGuardianship(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.DataStore.GetGuardianship(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get guardianship", err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "Guardianship not found", id)
		return
	}

	jsonreply.Write(w, http.StatusOK, record)
}

// handleUpdateGuardianship partially updates a guardianship record.
func (s *CoreServer) handleUpdateGuardianship(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetGuardianship(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get guardianship", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Guardianship not found", id)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	for _, old := range []string{"guardian_aid", "delegated_aid_prefix", "co_guardians"} {
		if _, ok := req[old]; ok {
			writeError(w, http.StatusBadRequest, "Invalid request body", old+" is not a field: a guardian is a key in the dependent's key set, not an identifier")
			return
		}
	}
	if v, ok := req["dependent_name"].(string); ok && v != "" {
		existing.DependentName = v
	}
	if v, ok := req["dependent_aid"].(string); ok {
		existing.DependentAID = v
	}
	if v, ok := req["status"].(string); ok {
		existing.Status = v
	}
	if v, ok := req["hosting_type"].(string); ok {
		existing.HostingType = v
	}
	if v, ok := req["hosting_url"].(string); ok {
		existing.HostingURL = v
	}
	if v, ok := req["metadata"].(map[string]interface{}); ok {
		meta := map[string]string{}
		for k, val := range v {
			if s, ok := val.(string); ok {
				meta[k] = s
			}
		}
		existing.Metadata = meta
	}

	if err := s.DataStore.SaveGuardianship(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update guardianship", err.Error())
		return
	}

	log.Printf("[guardianship] Updated guardianship %s", id)

	jsonreply.Write(w, http.StatusOK, existing)
}

// handleDeleteGuardianship revokes a guardianship (sets status to "revoked").
func (s *CoreServer) handleDeleteGuardianship(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetGuardianship(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get guardianship", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Guardianship not found", id)
		return
	}

	existing.Status = "revoked"
	if err := s.DataStore.SaveGuardianship(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke guardianship", err.Error())
		return
	}

	log.Printf("[guardianship] Revoked guardianship %s for dependent %s", id, existing.DependentName)

	jsonreply.Write(w, http.StatusOK, existing)
}

// handleEmancipateGuardianship transitions a guardianship to "emancipated" status.
func (s *CoreServer) handleEmancipateGuardianship(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetGuardianship(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get guardianship", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Guardianship not found", id)
		return
	}
	if existing.Status != "active" {
		writeError(w, http.StatusBadRequest, "Cannot emancipate", fmt.Sprintf("guardianship status is '%s', must be 'active'", existing.Status))
		return
	}

	existing.Status = "emancipated"
	if err := s.DataStore.SaveGuardianship(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to emancipate guardianship", err.Error())
		return
	}

	log.Printf("[guardianship] Emancipated guardianship %s — dependent %s is now independent", id, existing.DependentName)

	jsonreply.Write(w, http.StatusOK, existing)
}

// guardianshipRoles are what a key in a dependent's key set may be for.
var guardianshipRoles = map[string]bool{"guardian": true, "co_guardian": true, "court": true, "emergency": true, "dependent": true}

// checkMultisig refuses a key set that is not one: a key that is blank or
// repeated, a role that is not a role, or a threshold no set of that size can meet.
// With no participants named yet the threshold must be 0 (none set).
func checkMultisig(parts []store.MultisigParticipant, threshold int) error {
	seen := map[string]bool{}
	for _, p := range parts {
		if p.PublicKey == "" || len(p.PublicKey) > 128 || strings.ContainsAny(p.PublicKey, " \t\r\n") {
			return fmt.Errorf("a participant's public_key is blank or not a key")
		}
		if !guardianshipRoles[p.Role] {
			return fmt.Errorf("role %q is not one of guardian, co_guardian, court, emergency, dependent", p.Role)
		}
		if seen[p.PublicKey] {
			return fmt.Errorf("the key %q is in the key set twice", p.PublicKey)
		}
		seen[p.PublicKey] = true
	}
	if threshold < 0 || threshold > len(parts) {
		return fmt.Errorf("threshold %d cannot be met by %d keys", threshold, len(parts))
	}
	return nil
}
