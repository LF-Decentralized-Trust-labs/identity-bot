package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// The two ends of standing down as a witness.
//
// A witness cannot remove itself: the designated set lives in the controller's
// key log and only a rotation amends it. So one side asks and the other
// confirms, and the confirmation carries the rotation so the asking side can
// check it rather than believe it.

func (s *CoreServer) withdrawalRoutes(r chi.Router) {
	r.Post("/witness/withdraw", s.handleWitnessWithdraw)
	r.Post("/witness/withdraw/confirm", s.handleWitnessWithdrawConfirm)
}

// handleWitnessWithdraw receives a witness saying it intends to stop.
func (s *CoreServer) handleWitnessWithdraw(w http.ResponseWriter, r *http.Request) {
	var req witness.WithdrawalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if s.WitnessService == nil {
		writeError(w, http.StatusServiceUnavailable, "no witness service", "")
		return
	}
	if err := s.WitnessService.ReceiveWithdrawalRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "withdrawal_not_accepted", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Acknowledged, not agreed. The witness keeps receipting until a rotation
	// cuts it, and saying so here is what stops it stopping early.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "acknowledged",
		"note": "keep witnessing until a rotation cuts you; you will be sent the event " +
			"that does it",
	})
}

// handleWitnessWithdrawConfirm receives a controller's proof that it has cut us.
func (s *CoreServer) handleWitnessWithdrawConfirm(w http.ResponseWriter, r *http.Request) {
	var c witness.WithdrawalConfirmation
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if s.WitnessService == nil {
		writeError(w, http.StatusServiceUnavailable, "no witness service", "")
		return
	}
	if err := s.WitnessService.ReceiveWithdrawalConfirmation(c, stillDesignatedIn); err != nil {
		writeError(w, http.StatusBadRequest, "confirmation_not_accepted", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// stillDesignatedIn reports whether a rotation leaves a witness designated.
//
// Read from the event rather than from what the controller says about it. A
// confirmation is a claim; the rotation is the evidence, and the two can
// disagree — by mistake or otherwise.
func stillDesignatedIn(rotationRawB64, witnessKey string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(rotationRawB64)
	if err != nil {
		return true, err
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return true, err
	}
	for _, cut := range ev.WitnessCut {
		if cut == witnessKey {
			return false, nil
		}
	}
	// Not cut by this event. Reported as still designated rather than as an
	// error: the event may be genuine and simply not the one that removes us.
	return true, nil
}
