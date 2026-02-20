package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func handleRegisterApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Language    string            `json:"language"`
		EntryPoint  string            `json:"entry_point"`
		Metadata    map[string]string `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "name is required")
		return
	}
	if req.Language == "" {
		req.Language = "unknown"
	}

	app := store.AppRecord{
		ID:           generateID(),
		Name:         req.Name,
		Description:  req.Description,
		Language:     req.Language,
		EntryPoint:   req.EntryPoint,
		Status:       "stopped",
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
		Metadata:     req.Metadata,
	}

	if err := dataStore.SaveApp(app); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to register app", err.Error())
		return
	}

	log.Printf("[app-store] REGISTERED: %s (id: %s, lang: %s)", app.Name, app.ID, app.Language)

	entry := store.AuditLogEntry{
		ID:        generateID(),
		AppID:     app.ID,
		AppName:   app.Name,
		EventType: "system",
		Direction: "internal",
		Target:    "app-store",
		Details:   fmt.Sprintf("App '%s' registered (language: %s)", app.Name, app.Language),
		Action:    "allowed",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	dataStore.AppendAuditLog(entry)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(app)
}

func handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := dataStore.GetApps()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list apps", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

func handleGetApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := dataStore.GetApp(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get app", err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found", fmt.Sprintf("No app found with id: %s", id))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(app)
}

func handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := dataStore.GetApp(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get app", err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found", fmt.Sprintf("No app found with id: %s", id))
		return
	}

	if err := dataStore.DeleteApp(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete app", err.Error())
		return
	}

	log.Printf("[app-store] REMOVED: %s (id: %s)", app.Name, id)

	entry := store.AuditLogEntry{
		ID:        generateID(),
		AppID:     app.ID,
		AppName:   app.Name,
		EventType: "system",
		Direction: "internal",
		Target:    "app-store",
		Details:   fmt.Sprintf("App '%s' removed", app.Name),
		Action:    "allowed",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	dataStore.AppendAuditLog(entry)

	w.WriteHeader(http.StatusNoContent)
}

func handleLaunchApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := dataStore.GetApp(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get app", err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found", fmt.Sprintf("No app found with id: %s", id))
		return
	}

	if app.Status == "running" {
		writeError(w, http.StatusConflict, "App already running", fmt.Sprintf("App '%s' is already running", app.Name))
		return
	}

	app.Status = "running"
	app.LastLaunchedAt = time.Now().UTC().Format(time.RFC3339)

	if err := dataStore.SaveApp(*app); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update app", err.Error())
		return
	}

	log.Printf("[app-store] LAUNCH: %s (id: %s) — stubbed, will send webhook to VPS in future", app.Name, app.ID)

	entry := store.AuditLogEntry{
		ID:        generateID(),
		AppID:     app.ID,
		AppName:   app.Name,
		EventType: "lifecycle",
		Direction: "outbound",
		Target:    "vps-execution-engine",
		Details:   fmt.Sprintf("Launch command issued for '%s' (stubbed — no VPS connected yet)", app.Name),
		Action:    "allowed",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	dataStore.AppendAuditLog(entry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "launched",
		"app":     app,
		"message": "App launch command issued (stubbed). In production, this will send a webhook to the VPS execution engine.",
	})
}

func handleStopApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := dataStore.GetApp(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get app", err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found", fmt.Sprintf("No app found with id: %s", id))
		return
	}

	if app.Status == "stopped" {
		writeError(w, http.StatusConflict, "App already stopped", fmt.Sprintf("App '%s' is already stopped", app.Name))
		return
	}

	app.Status = "stopped"
	if err := dataStore.SaveApp(*app); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update app", err.Error())
		return
	}

	log.Printf("[app-store] STOP: %s (id: %s)", app.Name, app.ID)

	entry := store.AuditLogEntry{
		ID:        generateID(),
		AppID:     app.ID,
		AppName:   app.Name,
		EventType: "lifecycle",
		Direction: "outbound",
		Target:    "vps-execution-engine",
		Details:   fmt.Sprintf("Stop command issued for '%s'", app.Name),
		Action:    "allowed",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	dataStore.AppendAuditLog(entry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "stopped",
		"app":     app,
		"message": "App stop command issued.",
	})
}

func handleAssignPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	app, err := dataStore.GetApp(id)
	if err != nil || app == nil {
		writeError(w, http.StatusNotFound, "App not found", fmt.Sprintf("No app found with id: %s", id))
		return
	}

	if req.PolicyID != "" {
		policy, err := dataStore.GetPolicy(req.PolicyID)
		if err != nil || policy == nil {
			writeError(w, http.StatusNotFound, "Policy not found", fmt.Sprintf("No policy found with id: %s", req.PolicyID))
			return
		}
	}

	app.PolicyID = req.PolicyID
	if err := dataStore.SaveApp(*app); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update app", err.Error())
		return
	}

	log.Printf("[app-store] POLICY ASSIGNED: app=%s policy=%s", app.Name, req.PolicyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(app)
}

func handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		AllowedDomains []string `json:"allowed_domains"`
		BlockedDomains []string `json:"blocked_domains"`
		MaxSpend       float64  `json:"max_spend"`
		AllowFileWrite bool     `json:"allow_file_write"`
		AllowNetAccess bool     `json:"allow_net_access"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "name is required")
		return
	}

	if req.AllowedDomains == nil {
		req.AllowedDomains = []string{}
	}
	if req.BlockedDomains == nil {
		req.BlockedDomains = []string{}
	}

	policy := store.PolicyRecord{
		ID:             generateID(),
		Name:           req.Name,
		Description:    req.Description,
		AllowedDomains: req.AllowedDomains,
		BlockedDomains: req.BlockedDomains,
		MaxSpend:       req.MaxSpend,
		AllowFileWrite: req.AllowFileWrite,
		AllowNetAccess: req.AllowNetAccess,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	if err := dataStore.SavePolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create policy", err.Error())
		return
	}

	log.Printf("[app-store] POLICY CREATED: %s (id: %s)", policy.Name, policy.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

func handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := dataStore.GetPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list policies", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

func handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := dataStore.GetPolicy(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get policy", err.Error())
		return
	}
	if policy == nil {
		writeError(w, http.StatusNotFound, "Policy not found", fmt.Sprintf("No policy found with id: %s", id))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := dataStore.GetPolicy(id)
	if err != nil || policy == nil {
		writeError(w, http.StatusNotFound, "Policy not found", fmt.Sprintf("No policy found with id: %s", id))
		return
	}

	if err := dataStore.DeletePolicy(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete policy", err.Error())
		return
	}

	log.Printf("[app-store] POLICY REMOVED: %s (id: %s)", policy.Name, id)
	w.WriteHeader(http.StatusNoContent)
}

func handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries, err := dataStore.GetAuditLog(appID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get audit log", err.Error())
		return
	}

	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func handleIngestAuditWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID     string `json:"app_id"`
		AppName   string `json:"app_name"`
		EventType string `json:"event_type"`
		Direction string `json:"direction"`
		Target    string `json:"target"`
		Details   string `json:"details"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	entry := store.AuditLogEntry{
		ID:        generateID(),
		AppID:     req.AppID,
		AppName:   req.AppName,
		EventType: req.EventType,
		Direction: req.Direction,
		Target:    req.Target,
		Details:   req.Details,
		Action:    req.Action,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if err := dataStore.AppendAuditLog(entry); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save audit entry", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(entry)
}
