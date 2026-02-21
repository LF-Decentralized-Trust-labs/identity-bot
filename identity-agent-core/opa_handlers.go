package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

func handleCreateRegoPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Module      string `json:"module"`
		Rego        string `json:"rego"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Name == "" || req.Rego == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "name and rego are required")
		return
	}

	if req.Module == "" {
		req.Module = "policy." + req.Name
	}

	if err := opaEngine.ValidateRego(req.Module, req.Rego); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid Rego policy", err.Error())
		return
	}

	policy := store.RegoPolicy{
		ID:          generateID(),
		Name:        req.Name,
		Description: req.Description,
		Module:      req.Module,
		Rego:        req.Rego,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	if err := dataStore.SaveRegoPolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save policy", err.Error())
		return
	}

	if err := opaEngine.AddPolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, "Policy saved but failed to load into engine", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

func handleListRegoPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := dataStore.GetRegoPolicies()
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

func handleGetRegoPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := dataStore.GetRegoPolicy(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get policy", err.Error())
		return
	}
	if policy == nil {
		writeError(w, http.StatusNotFound, "Policy not found", fmt.Sprintf("No rego policy with id: %s", id))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func handleDeleteRegoPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	policy, err := dataStore.GetRegoPolicy(id)
	if err != nil || policy == nil {
		writeError(w, http.StatusNotFound, "Policy not found", fmt.Sprintf("No rego policy with id: %s", id))
		return
	}

	if err := dataStore.DeleteRegoPolicy(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete policy", err.Error())
		return
	}

	opaEngine.RemovePolicy(policy.Module)
	w.WriteHeader(http.StatusNoContent)
}

func handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Query == "" {
		req.Query = "data.sandbox.allow"
	}

	result, err := opaEngine.Evaluate(r.Context(), req.Query, req.Input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Policy evaluation failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleValidateRego(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module string `json:"module"`
		Rego   string `json:"rego"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Module == "" {
		req.Module = "policy.validation_test"
	}

	err := opaEngine.ValidateRego(req.Module, req.Rego)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": true,
		})
	}
}

func handleSimulatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rego   string        `json:"rego"`
		Module string        `json:"module"`
		Query  string        `json:"query"`
		Events []interface{} `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Rego == "" || len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "Missing required fields", "rego and events are required")
		return
	}

	if req.Module == "" {
		req.Module = "policy.simulation"
	}
	if req.Query == "" {
		req.Query = "data.sandbox.allow"
	}

	result, err := opaEngine.Simulate(r.Context(), req.Rego, req.Module, req.Query, req.Events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Simulation failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIngestTelemetry(w http.ResponseWriter, r *http.Request) {
	var batch store.TelemetryBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	saved := map[string]int{}

	if len(batch.SyscallEvents) > 0 {
		for i := range batch.SyscallEvents {
			if batch.SyscallEvents[i].AppID == "" {
				batch.SyscallEvents[i].AppID = batch.AppID
			}
			if batch.SyscallEvents[i].ID == "" {
				batch.SyscallEvents[i].ID = generateID()
			}
		}
		if err := dataStore.SaveSyscallEvents(batch.SyscallEvents); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to save syscall events", err.Error())
			return
		}
		saved["syscall_events"] = len(batch.SyscallEvents)
	}

	if len(batch.NetworkEvents) > 0 {
		for i := range batch.NetworkEvents {
			if batch.NetworkEvents[i].AppID == "" {
				batch.NetworkEvents[i].AppID = batch.AppID
			}
			if batch.NetworkEvents[i].ID == "" {
				batch.NetworkEvents[i].ID = generateID()
			}
		}
		if err := dataStore.SaveNetworkEvents(batch.NetworkEvents); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to save network events", err.Error())
			return
		}
		saved["network_events"] = len(batch.NetworkEvents)
	}

	if len(batch.FileEvents) > 0 {
		for i := range batch.FileEvents {
			if batch.FileEvents[i].AppID == "" {
				batch.FileEvents[i].AppID = batch.AppID
			}
			if batch.FileEvents[i].ID == "" {
				batch.FileEvents[i].ID = generateID()
			}
		}
		if err := dataStore.SaveFileAccessEvents(batch.FileEvents); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to save file events", err.Error())
			return
		}
		saved["file_events"] = len(batch.FileEvents)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ingested",
		"saved":  saved,
	})
}

func handleGetTelemetrySummary(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	summary, err := dataStore.GetTelemetrySummary(appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get telemetry summary", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func handleGetNetworkEvents(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	events, err := dataStore.GetNetworkEvents(appID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get network events", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

func handleGetSyscallEvents(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	events, err := dataStore.GetSyscallEvents(appID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get syscall events", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

func handleGetFileEvents(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	events, err := dataStore.GetFileAccessEvents(appID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get file events", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}
