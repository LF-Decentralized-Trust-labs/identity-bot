package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"identity-agent-core/store"
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"guardianships": records,
		"count":         len(records),
	})
}

// handleCreateGuardianship creates a new guardianship relationship.
func (s *CoreServer) handleCreateGuardianship(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type                string                     `json:"type"`
		DependentName       string                     `json:"dependent_name"`
		DependentAID        string                     `json:"dependent_aid"`
		DelegatedAIDPrefix  string                     `json:"delegated_aid_prefix"`
		HostingType         string                     `json:"hosting_type"`
		HostingURL          string                     `json:"hosting_url"`
		EmancipationTrigger *store.EmancipationTrigger `json:"emancipation_trigger"`
		CoGuardians         []string                   `json:"co_guardians"`
		MultisigThreshold   int                        `json:"multisig_threshold"`
		Metadata            map[string]string          `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	validTypes := map[string]bool{"minor_child": true, "elderly": true, "disability": true, "temporary": true}
	if !validTypes[req.Type] {
		writeError(w, http.StatusBadRequest, "Invalid guardianship type", fmt.Sprintf("type must be one of: minor_child, elderly, disability, temporary; got: %s", req.Type))
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
		ID:                  uuid.New().String(),
		Type:                req.Type,
		GuardianAID:         identity.AID,
		DependentAID:        req.DependentAID,
		DependentName:       req.DependentName,
		DelegatedAIDPrefix:  req.DelegatedAIDPrefix,
		Status:              "active",
		HostingType:         req.HostingType,
		HostingURL:          req.HostingURL,
		CreatedAt:           now,
		UpdatedAt:           now,
		EmancipationTrigger: req.EmancipationTrigger,
		CoGuardians:         req.CoGuardians,
		MultisigThreshold:   req.MultisigThreshold,
		Metadata:            req.Metadata,
	}
	if record.CoGuardians == nil {
		record.CoGuardians = []string{}
	}
	if record.Metadata == nil {
		record.Metadata = map[string]string{}
	}

	if err := s.DataStore.SaveGuardianship(record); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create guardianship", err.Error())
		return
	}

	log.Printf("[guardianship] Created guardianship %s: type=%s dependent=%s hosting=%s",
		record.ID, record.Type, record.DependentName, record.HostingType)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(record)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(record)
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

	if v, ok := req["dependent_name"].(string); ok && v != "" {
		existing.DependentName = v
	}
	if v, ok := req["dependent_aid"].(string); ok {
		existing.DependentAID = v
	}
	if v, ok := req["delegated_aid_prefix"].(string); ok {
		existing.DelegatedAIDPrefix = v
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
}
