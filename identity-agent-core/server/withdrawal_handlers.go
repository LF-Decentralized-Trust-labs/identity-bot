package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
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
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
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
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if s.WitnessService == nil {
		writeError(w, http.StatusServiceUnavailable, "no witness service", "")
		return
	}
	if err := s.WitnessService.ReceiveWithdrawalConfirmation(c, s.stillDesignatedIn(c.ControllerAID)); err != nil {
		writeError(w, http.StatusBadRequest, "confirmation_not_accepted", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// stillDesignatedIn returns the check that a rotation really cuts a witness
// from the given controller.
//
// A confirmation is a claim; the rotation is the evidence — but only if it is
// that controller's own rotation. Parsing the blob proves it is shaped like one
// and nothing else: anybody can write an event that names a witness in its cut
// list. So the event has to be one this witness already holds in the
// controller's key log, and that log is validated from the bytes it was
// published as, by the one validator the rest of the witness uses. That
// establishes, in a single pass, that the log derives the controller's own
// identifier, that every event in it (this rotation included) is signed by the
// key in force at that point, and that the chain holds.
//
// The witness is still enrolled until the confirmation is accepted, so it has
// been receiving this controller's events, the rotation among them. A rotation
// it does not hold is refused: it cannot be shown to be in the log.
func (s *CoreServer) stillDesignatedIn(controllerAID string) func(rotationRawB64, witnessKey string) (bool, error) {
	return func(rotationRawB64, witnessKey string) (bool, error) {
		raw, err := base64.StdEncoding.DecodeString(rotationRawB64)
		if err != nil {
			return true, err
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return true, err
		}
		if ev.Identifier != controllerAID {
			return true, fmt.Errorf("this rotation is for %s, not %s", ev.Identifier, controllerAID)
		}
		if ev.Ilk != "rot" && ev.Ilk != "drt" {
			return true, fmt.Errorf("the event is a %q, not a rotation", ev.Ilk)
		}
		if s.WitnessService == nil || s.WitnessService.Store == nil {
			return true, fmt.Errorf("no key log is held to check the rotation against")
		}
		held, err := s.WitnessService.Store.GetKelEvents(controllerAID)
		if err != nil {
			return true, err
		}
		in := drivers.ValidateKELInput{AID: controllerAID}
		inLog := false
		for _, e := range held {
			if e.RawBytesB64 == "" {
				return true, fmt.Errorf("the key log held for %s predates keeping published "+
					"bytes, so it cannot be verified", controllerAID)
			}
			b, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
			if err != nil {
				return true, fmt.Errorf("a stored event is unreadable: %w", err)
			}
			if bytes.Equal(b, raw) {
				inLog = true
			}
			in.RawEvents = append(in.RawEvents, b)
			in.CesrSignatures = append(in.CesrSignatures, e.CesrSignature)
		}
		if !inLog {
			return true, fmt.Errorf("this rotation is not in the key log held for %s", controllerAID)
		}
		res, err := drivers.ValidateKELFromBytes(in)
		if err != nil {
			return true, err
		}
		if !res.KelVerified {
			return true, fmt.Errorf("the key log held for %s is not verified: %s",
				controllerAID, strings.Join(res.ValidationErrors, "; "))
		}
		cut := false
		for _, c := range ev.WitnessCut {
			if sameWitness(c, witnessKey) {
				cut = true
			}
		}
		if !cut {
			// Genuine, but not the event that removes us.
			return true, nil
		}
		// Cut by this event; still designated if a later one added it back.
		//
		// What bounds a replay of an old cut: the rotation has to be one the
		// controller signed, already in the log this witness holds, and the
		// log is checked to its tip, so a re-add this witness holds is
		// honoured. The remaining case is a re-add this witness never
		// received (it is not sent events once cut, and the log it holds
		// cannot have a gap). Then replaying the old cut makes the witness
		// stand down from a controller that did once cut it and has since put
		// it back. The effect is limited to this witness ceasing to receipt
		// for that controller, which the controller can undo by enrolling it
		// again; nothing is recorded or attested, and nobody who does not hold
		// the controller's signed rotation can cause it. Refusing any cut older
		// than the newest event held would block a legitimate withdrawal
		// whenever the controller rotated again afterwards, so it is not done.
		for _, d := range res.Witnesses {
			if sameWitness(d, witnessKey) {
				return true, nil
			}
		}
		return false, nil
	}
}

// sameWitness compares by key, so two spellings of one witness agree.
func sameWitness(a, b string) bool {
	if a == b {
		return true
	}
	ka, oka := drivers.WitnessKey(a)
	kb, okb := drivers.WitnessKey(b)
	return oka && okb && ka == kb
}
