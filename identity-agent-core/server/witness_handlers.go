package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"identity-agent-core/store"
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
	r.Post("/witness/endpoint", s.handleWitnessEndpointRecord)
	r.Get("/witness/endpoint/{controller_aid}", s.handleWitnessEndpointLookup)
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
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "internal route")
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

// handleWitnessRequest handles inbound witness enrollment from a remote agent.
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

// handleWitnessAccept handles the accept/decline POST-back from a remote agent.
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

// handleWitnessEndpointRecord accepts a controller's signed statement of where
// it currently is, and holds it on that controller's behalf.
//
// This is the half of the design that makes a changed address survivable. An
// OOBI handed to somebody persists in their store long after it stops working,
// so when a relay is left or an allocation expires, every counterparty holding
// that string is stranded. A witness is the natural place to keep the current
// answer, because it is already named in the KEL and is already the thing that
// does not change when infrastructure does.
func (s *CoreServer) handleWitnessEndpointRecord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AID    string                 `json:"aid"`
		Record map[string]interface{} `json:"record"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.AID == "" || req.Record == nil {
		writeError(w, http.StatusBadRequest, "aid and record required", "")
		return
	}

	said, _ := req.Record["d"].(string)
	route, _ := req.Record["r"].(string)
	if said == "" || route == "" {
		writeError(w, http.StatusBadRequest, "record must carry a SAID and a route", "")
		return
	}
	// Only endpoint statements belong here. A key event routed to this handler
	// would bypass the KEL's sequence and duplicity checks entirely, so the
	// route is checked rather than assumed.
	if route != "/end/role/add" && route != "/end/role/cut" && route != "/loc/scheme" {
		writeError(w, http.StatusBadRequest, "unsupported route",
			"expected /end/role/add, /end/role/cut or /loc/scheme")
		return
	}

	rec := store.EndpointRecord{
		SAID:       said,
		CID:        req.AID,
		Route:      route,
		Record:     req.Record,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if attrs, ok := req.Record["a"].(map[string]interface{}); ok {
		rec.EID, _ = attrs["eid"].(string)
		rec.Role, _ = attrs["role"].(string)
		rec.Scheme, _ = attrs["scheme"].(string)
		rec.URL, _ = attrs["url"].(string)
		// A /end/role record names the controller it speaks for. Trusting the
		// envelope's AID over the record's own cid would let one identity
		// publish endpoints under another's name.
		if cid, ok := attrs["cid"].(string); ok && cid != "" && cid != req.AID {
			writeError(w, http.StatusBadRequest, "cid mismatch",
				"the record names a different controller than the request")
			return
		}
	}
	if stamp, ok := req.Record["dt"].(string); ok {
		rec.Stamp = stamp
	}

	if err := s.DataStore.SaveEndpointRecord(rec); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store endpoint record", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"stored": true, "said": said, "route": route})
}

// handleWitnessEndpointLookup answers "where is this identity now" for somebody
// whose stored address has stopped working.
//
// Public on purpose. A counterparty holding a dead URL has, by definition, no
// authenticated channel left to ask through — requiring one would make this
// reachable only by people who do not need it. The records are individually
// signed by the controller, so serving them to anybody discloses nothing the
// controller did not choose to publish.
func (s *CoreServer) handleWitnessEndpointLookup(w http.ResponseWriter, r *http.Request) {
	cid := chi.URLParam(r, "controller_aid")
	if cid == "" {
		writeError(w, http.StatusBadRequest, "controller_aid required", "")
		return
	}
	records, err := s.DataStore.GetEndpointRecords(cid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint records", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"controller_aid": cid,
		"records":        records,
		"count":          len(records),
	})
}
