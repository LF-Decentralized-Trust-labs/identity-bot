package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountWitnessRoutes(r chi.Router) {
	if s.WitnessService == nil {
		return
	}
	r.Post("/witness/event", s.handleWitnessEvent)
	r.Get("/witness/kel/{signer_aid}", s.handleWitnessKel)
	r.Get("/witness/status", s.handleWitnessStatus)
	r.Get("/witness/tel/{issuer_aid}", s.handleWitnessTELStub)
}

func (s *CoreServer) handleWitnessEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AID   string                 `json:"aid"`
		Event map[string]interface{} `json:"event"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.Event == nil {
		writeError(w, http.StatusBadRequest, "event required", "")
		return
	}
	result, err := s.WitnessService.ReceiveEvent(req.AID, req.Event)
	if err != nil {
		switch err.Error() {
		case "not_witnessing":
			writeError(w, http.StatusForbidden, "not_witnessing", "unknown signer or no active witness relationship")
		case "sequence_gap":
			writeError(w, http.StatusConflict, "sequence_gap", "sequence must be last_stored+1")
		case "duplicate_sequence":
			writeError(w, http.StatusConflict, "duplicate_sequence", "event already stored")
		default:
			if len(err.Error()) > 9 && err.Error()[:9] == "rejected:" {
				writeError(w, http.StatusBadRequest, "rejected", err.Error())
			} else {
				writeError(w, http.StatusBadRequest, "rejected", err.Error())
			}
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleWitnessKel(w http.ResponseWriter, r *http.Request) {
	signerAID := chi.URLParam(r, "signer_aid")
	kel, err := s.WitnessService.GetKelReplica(signerAID)
	if err != nil {
		writeError(w, http.StatusNotFound, "kel not found", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"aid": signerAID, "kel": kel, "count": len(kel),
	})
}

func (s *CoreServer) handleWitnessStatus(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		writeError(w, http.StatusForbidden, "localhost only", "IF5 internal route")
		return
	}
	st, err := s.WitnessService.BuildStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *CoreServer) handleWitnessTELStub(w http.ResponseWriter, r *http.Request) {
	issuerAID := chi.URLParam(r, "issuer_aid")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(s.WitnessService.ServeTELStub(issuerAID))
}

// handleWitnessRequest is IF2 — inbound witness enrollment from a remote agent.
func (s *CoreServer) handleWitnessRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequesterAID  string `json:"requester_aid"`
		RequesterOOBI string `json:"requester_oobi"`
		BackendType   string `json:"backend_type"`
		EventJSON     string `json:"event_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness request body", err.Error())
		return
	}
	if req.RequesterAID == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "requester_aid required")
		return
	}
	if s.WitnessService == nil {
		writeError(w, http.StatusServiceUnavailable, "witness service unavailable", "")
		return
	}
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	result := s.WitnessService.ProcessInboundRequest(ctx, witness.WitnessRequest{
		RequesterAID: req.RequesterAID, RequesterOOBI: req.RequesterOOBI, BackendType: req.BackendType,
	})
	status := "declined"
	if result.Accepted {
		status = "accepted"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": status, "reason": result.Reason, "task_id": result.TaskID,
	})
}

// handleWitnessAccept is IF3 — accept/decline POST-back from remote agent.
func (s *CoreServer) handleWitnessAccept(w http.ResponseWriter, r *http.Request) {
	var req witness.AcceptCallback
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness accept body", err.Error())
		return
	}
	if req.RequesterAID == "" || req.ResponderAID == "" || req.Decision == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields",
			"requester_aid, responder_aid, and decision are required")
		return
	}
	if s.WitnessService != nil {
		if err := s.WitnessService.ApplyAcceptCallback(req); err != nil {
			log.Printf("[witness] accept callback error: %v", err)
			writeError(w, http.StatusBadRequest, "accept_failed", err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received", "decision": req.Decision})
}

func (s *CoreServer) triggerWitnessBroadcast(signerAID string, event map[string]interface{}) {
	if s.WitnessService == nil || event == nil {
		return
	}
	ctx := s.AppCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.WitnessService.BroadcastEvent(ctx, signerAID, event); err != nil {
		log.Printf("[witness] broadcast failed: %v", err)
	}
}