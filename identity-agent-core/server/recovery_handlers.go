package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/recovery"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountRecoveryRoutes(r chi.Router) {
	r.Route("/recovery", func(r chi.Router) {
		r.Post("/verify", s.handleRecoveryVerify)
		r.Post("/start", s.handleRecoveryStart)
		r.Get("/sessions/{id}", s.handleRecoveryGetSession)
		r.Post("/sessions/{id}/rotation", s.handleRecoveryRotation)
		r.Post("/sessions/{id}/activate", s.handleRecoveryActivate)
		r.Post("/retrieve", s.handleRecoveryRetrieve)
		r.Post("/root-aid-rotation", s.handleRecoveryRootAIDRotation)
		r.Get("/root-aid-rotation/status", s.handleRecoveryRootAIDStatus)
	})
}

func (s *CoreServer) recoveryService() *recovery.Service {
	if s.RecoveryService == nil {
		s.RecoveryService = recovery.NewService(s.DataDir, s.DataStore, s.backupService())
	}
	return s.RecoveryService
}

func (s *CoreServer) handleRecoveryVerify(w http.ResponseWriter, r *http.Request) {
	var req recovery.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Mnemonic == "" {
		writeError(w, http.StatusBadRequest, "mnemonic required", "Provide seed phrase to decrypt archive")
		return
	}
	if req.ArchiveB64 == "" {
		writeError(w, http.StatusBadRequest, "archive_b64 required", "Provide encrypted .iab archive")
		return
	}

	result, err := s.recoveryService().Verify(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Verify failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleRecoveryStart(w http.ResponseWriter, r *http.Request) {
	var req recovery.StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Mnemonic == "" || req.ArchiveB64 == "" {
		writeError(w, http.StatusBadRequest, "Missing fields", "mnemonic and archive_b64 are required")
		return
	}

	sess, err := s.recoveryService().Start(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Start failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryGetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sess, err := s.recoveryService().GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Not found", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryRotation(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	var req recovery.RotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := recovery.ValidateRotationRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid rotation request", err.Error())
		return
	}

	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Use /api/rotation on desktop or Rust bridge on mobile, then record result here")
		return
	}

	result, err := s.KeriDriver.RotateAid(req.Name, req.NewPublicKey, req.NewNextPublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Rotation failed", err.Error())
		return
	}

	rotResult := recovery.RotationResult{
		AID:            result.AID,
		NewPublicKey:   result.NewPublicKey,
		SequenceNumber: result.SequenceNumber,
	}
	sess, err := s.recoveryService().RecordRotation(sessionID, rotResult)
	if err != nil {
		writeError(w, http.StatusNotFound, "Session not found", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session":         sess,
		"rotation_result": result,
	})
}

func (s *CoreServer) handleRecoveryActivate(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	sess, err := s.recoveryService().Activate(sessionID)
	if err != nil {
		switch err.(type) {
		case *recovery.ErrCancelWindowActive:
			writeError(w, http.StatusConflict, "Cancel window active", err.Error())
		case *recovery.ErrRotationMandatory:
			writeError(w, http.StatusPreconditionFailed, "Rotation required", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "Activate failed", err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryRetrieve(w http.ResponseWriter, r *http.Request) {
	var req recovery.RetrieveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	resp, err := s.recoveryService().Retrieve(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Retrieve failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleRecoveryRootAIDRotation(w http.ResponseWriter, r *http.Request) {
	var req recovery.RootAIDRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := recovery.RotateRootAID(req)
	if err != nil {
		writeError(w, http.StatusNotImplemented, "Not implemented", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleRecoveryRootAIDStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"available": recovery.RootAIDRotationAvailable(),
		"message":   "root-AID break-glass rotation is stubbed pending KERI research",
	})
}