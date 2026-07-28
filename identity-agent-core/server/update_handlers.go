package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/update"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountUpdateRoutes(r chi.Router) {
	if s.UpdateService == nil {
		return
	}
	r.Route("/updates", func(r chi.Router) {
		r.Get("/manifest", s.handleUpdatesManifest)
		r.Get("/status", s.handleUpdatesStatus)
		r.Post("/apply", s.handleUpdatesApply)
		r.Post("/check", s.handleUpdatesCheck)
		r.Get("/settings", s.handleUpdatesGetSettings)
		r.Put("/settings", s.handleUpdatesPutSettings)
	})
}

func (s *CoreServer) handleUpdatesManifest(w http.ResponseWriter, r *http.Request) {
	raw, ok := s.UpdateService.CachedManifestRaw()
	if !ok {
		writeError(w, http.StatusNotFound, "no verified manifest", "poll has not yet produced a valid cached manifest")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (s *CoreServer) handleUpdatesStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.UpdateService.Status())
}

func (s *CoreServer) handleUpdatesApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Component     string `json:"component"`
		Version       string `json:"version"`
		UserConfirmed bool   `json:"user_confirmed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.Component == "" {
		writeError(w, http.StatusBadRequest, "component required", "")
		return
	}
	result, err := s.UpdateService.Apply(req.Component, req.Version, req.UserConfirmed)
	if err != nil {
		switch err {
		case update.ErrBelowMinimumVersion:
			writeError(w, http.StatusConflict, "below_minimum_version", err.Error())
		case update.ErrChecksumMismatch:
			writeError(w, http.StatusBadRequest, "checksum_mismatch", err.Error())
		default:
			writeError(w, http.StatusBadRequest, "apply_failed", err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	s.UpdateService.CheckNow()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "check_scheduled"})
}

func (s *CoreServer) handleUpdatesGetSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.UpdateService.GetSettings())
}

func (s *CoreServer) handleUpdatesPutSettings(w http.ResponseWriter, r *http.Request) {
	var req update.Settings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	s.UpdateService.UpdateSettings(req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.UpdateService.GetSettings())
}
