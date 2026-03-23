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

// serviceProviderRoutes registers /api/service-providers endpoints.
func (s *CoreServer) serviceProviderRoutes(r chi.Router) {
	r.Route("/service-providers", func(r chi.Router) {
		r.Get("/", s.handleListServiceProviders)
		r.Post("/", s.handleCreateServiceProvider)
		r.Get("/{id}", s.handleGetServiceProvider)
		r.Put("/{id}", s.handleUpdateServiceProvider)
		r.Delete("/{id}", s.handleDeleteServiceProvider)
		r.Post("/{id}/connect", s.handleConnectServiceProvider)
		r.Post("/{id}/disconnect", s.handleDisconnectServiceProvider)
		r.Post("/{id}/health", s.handleCheckServiceProviderHealth)
	})
}

// handleListServiceProviders returns all service provider entries, with optional filters.
func (s *CoreServer) handleListServiceProviders(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	status := r.URL.Query().Get("status")

	var records []store.ServiceProviderRecord
	var err error

	if category != "" {
		records, err = s.DataStore.GetServiceProvidersByCategory(category)
	} else if status != "" {
		records, err = s.DataStore.GetServiceProvidersByStatus(status)
	} else {
		records, err = s.DataStore.GetServiceProviders()
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list service providers", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": records,
		"count":     len(records),
	})
}

// handleCreateServiceProvider adds a new service provider entry.
func (s *CoreServer) handleCreateServiceProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderName  string            `json:"provider_name"`
		ProviderAID   string            `json:"provider_aid"`
		Category      string            `json:"category"`
		DisplayName   string            `json:"display_name"`
		EndpointURL   string            `json:"endpoint_url"`
		CompanyHQ     string            `json:"company_hq"`
		ServerRegion  string            `json:"server_region"`
		IdentityLevel int               `json:"identity_level"`
		GrapeScore    int               `json:"grape_score"`
		Capabilities  []string          `json:"capabilities"`
		TermsURL      string            `json:"terms_url"`
		Configuration map[string]string `json:"configuration"`
		Source        string            `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	validCategories := map[string]bool{"infrastructure": true, "witness": true, "cloud_hsm": true, "tunneling": true}
	if !validCategories[req.Category] {
		writeError(w, http.StatusBadRequest, "Invalid category", fmt.Sprintf("category must be one of: infrastructure, witness, cloud_hsm, tunneling; got: %s", req.Category))
		return
	}
	if req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "display_name is required")
		return
	}
	if req.EndpointURL == "" {
		writeError(w, http.StatusBadRequest, "Missing required field", "endpoint_url is required")
		return
	}

	if req.Source == "" {
		req.Source = "manual"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	record := store.ServiceProviderRecord{
		ID:            uuid.New().String(),
		ProviderName:  req.ProviderName,
		ProviderAID:   req.ProviderAID,
		Category:      req.Category,
		DisplayName:   req.DisplayName,
		EndpointURL:   req.EndpointURL,
		Status:        "available",
		Health:        "unknown",
		CompanyHQ:     req.CompanyHQ,
		ServerRegion:  req.ServerRegion,
		IdentityLevel: req.IdentityLevel,
		GrapeScore:    req.GrapeScore,
		Capabilities:  req.Capabilities,
		TermsURL:      req.TermsURL,
		Configuration: req.Configuration,
		IsDefault:     false,
		Source:        req.Source,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if record.Capabilities == nil {
		record.Capabilities = []string{}
	}
	if record.Configuration == nil {
		record.Configuration = map[string]string{}
	}

	if err := s.DataStore.SaveServiceProvider(record); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create service provider", err.Error())
		return
	}

	log.Printf("[service-providers] Created %s (%s): %s", record.DisplayName, record.Category, record.EndpointURL)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(record)
}

// handleGetServiceProvider returns a single service provider by ID.
func (s *CoreServer) handleGetServiceProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	record, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(record)
}

// handleUpdateServiceProvider partially updates a service provider.
func (s *CoreServer) handleUpdateServiceProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if v, ok := req["display_name"].(string); ok && v != "" {
		existing.DisplayName = v
	}
	if v, ok := req["endpoint_url"].(string); ok {
		existing.EndpointURL = v
	}
	if v, ok := req["company_hq"].(string); ok {
		existing.CompanyHQ = v
	}
	if v, ok := req["server_region"].(string); ok {
		existing.ServerRegion = v
	}
	if v, ok := req["configuration"].(map[string]interface{}); ok {
		config := map[string]string{}
		for k, val := range v {
			if s, ok := val.(string); ok {
				config[k] = s
			}
		}
		existing.Configuration = config
	}

	if err := s.DataStore.SaveServiceProvider(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update service provider", err.Error())
		return
	}

	log.Printf("[service-providers] Updated %s", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
}

// handleDeleteServiceProvider removes a service provider entry.
func (s *CoreServer) handleDeleteServiceProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	if err := s.DataStore.DeleteServiceProvider(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete service provider", err.Error())
		return
	}

	log.Printf("[service-providers] Deleted %s (%s)", existing.DisplayName, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "id": id})
}

// handleConnectServiceProvider activates a service provider.
func (s *CoreServer) handleConnectServiceProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	existing.Status = "connected"
	existing.ConnectedAt = now
	existing.TermsAcceptedAt = now

	if err := s.DataStore.SaveServiceProvider(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect service provider", err.Error())
		return
	}

	log.Printf("[service-providers] Connected %s (%s)", existing.DisplayName, existing.Category)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
}

// handleDisconnectServiceProvider deactivates a service provider without deleting.
func (s *CoreServer) handleDisconnectServiceProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	existing.Status = "disconnected"

	if err := s.DataStore.SaveServiceProvider(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disconnect service provider", err.Error())
		return
	}

	log.Printf("[service-providers] Disconnected %s (%s)", existing.DisplayName, existing.Category)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
}

// handleCheckServiceProviderHealth pings a provider's health endpoint.
func (s *CoreServer) handleCheckServiceProviderHealth(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.DataStore.GetServiceProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get service provider", err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "Service provider not found", id)
		return
	}

	// Ping the provider's health endpoint
	healthURL := existing.EndpointURL + "/health"
	if existing.EndpointURL == "https://keri.grapeid.org" {
		healthURL = "https://keri.grapeid.org/health"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	existing.HealthCheckedAt = now

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		existing.Health = "unreachable"
		log.Printf("[service-providers] Health check failed for %s: %v", existing.DisplayName, err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			existing.Health = "healthy"
		} else {
			existing.Health = "degraded"
		}
	}

	if err := s.DataStore.SaveServiceProvider(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save health status", err.Error())
		return
	}

	log.Printf("[service-providers] Health check for %s: %s", existing.DisplayName, existing.Health)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existing)
}
