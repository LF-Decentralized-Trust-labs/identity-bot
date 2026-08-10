package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// Standing down as somebody's witness.
//
// Becoming a witness is an exchange: one party asks, the other agrees. Stopping
// has to be an exchange too, and for a sharper reason than symmetry.
//
// A witness set is named in the identity's key log. It is public, it is part of
// what the identifier is, and it can only be amended by a rotation — which only
// the controller can perform. So a witness cannot remove itself. If it simply
// stopped answering, the controller's log would go on designating it, verifiers
// would go on expecting receipts from it, and the threshold would quietly
// become unmeetable. The identity would look under-witnessed to everyone and
// nothing would say why.
//
// So withdrawal is a REQUEST, and the witness keeps working until the
// controller confirms. The confirmation is the rotation that cut it: the
// controller sends back the event, and the witness can see for itself that it
// is no longer designated rather than taking the claim on trust.
//
// WHAT IS NOT A WITHDRAWAL. Going offline for a while is not. A witness that is
// unreachable for minutes, hours or days has not stood down — it is
// unavailable, which is a different thing that the health checks already handle
// from the other side: a controller whose witness stays silent long enough may
// drop it and find another, without needing its permission. On return a witness
// catches up on the events it missed rather than announcing anything.
//
// Withdrawal is for the cases where coming back is not the plan: the operator
// is shutting down, or no longer has the resources to keep doing this.
//
// WATCHERS HAVE NO EQUIVALENT and need none. Nobody asks permission to watch an
// identity, and a watcher is chosen by the verifier rather than named by the
// subject — so there is no relationship to end, nothing published to amend, and
// nobody to notify. A watcher that stops simply stops.

// WithdrawalReason says why a witness is standing down. Recorded because the
// controller's response differs: an operator shutting down permanently needs
// replacing now, one short of resources may be worth waiting for.
type WithdrawalReason string

const (
	// WithdrawalShuttingDown — the operator is going away for good.
	WithdrawalShuttingDown WithdrawalReason = "shutting_down"
	// WithdrawalNoCapacity — still running, no longer able to take this on.
	WithdrawalNoCapacity WithdrawalReason = "no_capacity"
	// WithdrawalUnspecified — a reason was not given.
	WithdrawalUnspecified WithdrawalReason = ""
)

// WithdrawalRequest is a witness telling a controller it intends to stop.
type WithdrawalRequest struct {
	// WitnessAID identifies the agent standing down, and WitnessKey is the key
	// it was designated by — which is what the controller must cut, and is not
	// derivable from the AID.
	WitnessAID string           `json:"witness_aid"`
	WitnessKey string           `json:"witness_key"`
	Reason     WithdrawalReason `json:"reason,omitempty"`
	// EffectiveAfter is when the witness intends to stop, so a controller has
	// warning rather than an ultimatum. Advisory: the witness keeps working
	// until confirmation regardless, because stopping earlier would break the
	// threshold it is trying to let the controller repair.
	EffectiveAfter string `json:"effective_after,omitempty"`
	RequestedAt    string `json:"requested_at"`
}

// WithdrawalConfirmation is a controller telling a witness it has been removed.
type WithdrawalConfirmation struct {
	ControllerAID string `json:"controller_aid"`
	WitnessKey    string `json:"witness_key"`
	// RotationRawB64 is the event that cut this witness, so the witness can
	// check the claim rather than believe it. A confirmation without it is a
	// controller saying it has done something, which is exactly the kind of
	// assertion this system replaces with evidence.
	RotationRawB64 string `json:"rotation_raw_b64"`
	ConfirmedAt    string `json:"confirmed_at"`
}

// RequestWithdrawal tells a controller that this agent intends to stop
// witnessing for it.
//
// Sending it changes nothing about what this agent does. It keeps receipting
// until the controller confirms, because until the rotation happens the
// controller's log still designates it and the receipts are still needed.
func (s *Service) RequestWithdrawal(ctx context.Context, controllerAID string, reason WithdrawalReason) error {
	if controllerAID == "" {
		return fmt.Errorf("a withdrawal must name the identity it is about")
	}
	meta, _ := s.Store.GetContactMeta(controllerAID)
	if meta == nil || !meta.WitnessingFor {
		return fmt.Errorf("this agent does not witness for %s, so there is nothing to stand "+
			"down from", controllerAID)
	}
	key, _, err := s.WitnessKey()
	if err != nil {
		return fmt.Errorf("this agent cannot say which witness is standing down: %w", err)
	}
	contact, _ := s.Contacts.GetContact(controllerAID)
	if contact == nil || contact.OobiURL == "" {
		return fmt.Errorf("no address is known for %s, so it cannot be told", controllerAID)
	}

	body, err := json.Marshal(WithdrawalRequest{
		WitnessAID:  s.ourAID(),
		WitnessKey:  key,
		Reason:      reason,
		RequestedAt: NowRFC3339(),
	})
	if err != nil {
		return err
	}
	if _, err := s.PostEvent(ctx, withdrawalURL(contact.OobiURL), body); err != nil {
		// Worth reporting rather than swallowing: the controller has not been
		// told, so it is not going to rotate, so this agent is still on the
		// hook. Trying again later is the remedy, and it cannot be tried if
		// nobody knows it failed.
		return fmt.Errorf("could not tell %s that this witness is standing down: %w",
			controllerAID, err)
	}
	if s.OnEvent != nil {
		s.OnEvent("witness_withdrawal_requested", map[string]interface{}{
			"controller_aid": controllerAID, "reason": string(reason),
		})
	}
	return nil
}

// ReceiveWithdrawalRequest records that one of our witnesses intends to stop.
//
// Nothing is removed here. Removing a witness means rotating, which changes the
// identity's keys, and that is the controller's decision and possibly a
// deliberate ceremony — not something to do because an HTTP request arrived.
// What this does is make the request visible and find a replacement early, so
// the rotation when it comes can cut and add in one event.
func (s *Service) ReceiveWithdrawalRequest(req WithdrawalRequest) error {
	if req.WitnessKey == "" {
		return fmt.Errorf("a withdrawal must say which witness key is standing down; the " +
			"controller cuts a key, not a contact")
	}
	meta, _ := s.Store.GetContactMeta(req.WitnessAID)
	if meta == nil {
		return fmt.Errorf("%s is not a witness this agent knows about", req.WitnessAID)
	}

	log.Printf("[witness] %s intends to stop witnessing (%s). It keeps receipting until a "+
		"rotation cuts %s from the designated set.", req.WitnessAID, reasonText(req.Reason),
		req.WitnessKey)

	if s.OnEvent != nil {
		s.OnEvent("witness_withdrawal_received", map[string]interface{}{
			"witness_aid": req.WitnessAID,
			"witness_key": req.WitnessKey,
			"reason":      string(req.Reason),
			"remedy": "rotate to cut this witness, and add a replacement in the same " +
				"event so the threshold is never short",
		})
	}

	// Look for a replacement now rather than after the rotation, so the same
	// event can cut one and add the other and the identity is never briefly
	// below its own threshold.
	go s.trySelfHeal()
	return nil
}

// ConfirmWithdrawal tells a witness it has been cut, with the event that did it.
func (s *Service) ConfirmWithdrawal(ctx context.Context, witnessAID string, confirmation WithdrawalConfirmation) error {
	contact, _ := s.Contacts.GetContact(witnessAID)
	if contact == nil || contact.OobiURL == "" {
		return fmt.Errorf("no address is known for %s", witnessAID)
	}
	body, err := json.Marshal(confirmation)
	if err != nil {
		return err
	}
	_, err = s.PostEvent(ctx, withdrawalConfirmURL(contact.OobiURL), body)
	return err
}

// ReceiveWithdrawalConfirmation stops witnessing, once the evidence holds up.
//
// The rotation is checked rather than taken on faith. A confirmation that does
// not actually cut this witness would have it stop while the controller's log
// still designated it — the exact failure the whole exchange exists to avoid,
// arrived at by being too trusting instead of too hasty.
func (s *Service) ReceiveWithdrawalConfirmation(c WithdrawalConfirmation, stillDesignated func(rotationRawB64, witnessKey string) (bool, error)) error {
	if c.ControllerAID == "" || c.WitnessKey == "" {
		return fmt.Errorf("a confirmation must name the identity and the witness key it cut")
	}
	key, _, err := s.WitnessKey()
	if err != nil {
		return err
	}
	if c.WitnessKey != key {
		return fmt.Errorf("this confirmation cuts %s, which is not this agent's witness key",
			c.WitnessKey)
	}
	if c.RotationRawB64 == "" {
		return fmt.Errorf("a confirmation must carry the rotation that cut this witness; " +
			"without it this agent would be stopping on an assurance it cannot check")
	}
	if stillDesignated != nil {
		designated, err := stillDesignated(c.RotationRawB64, c.WitnessKey)
		if err != nil {
			return fmt.Errorf("the rotation in this confirmation could not be read: %w", err)
		}
		if designated {
			return fmt.Errorf("the rotation does not cut %s, so this agent is still designated "+
				"and stopping now would leave %s unable to meet its threshold",
				c.WitnessKey, c.ControllerAID)
		}
	}

	meta, _ := s.Store.GetContactMeta(c.ControllerAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: c.ControllerAID}
	}
	meta.WitnessingFor = false
	if err := s.Store.SaveContactMeta(*meta); err != nil {
		return err
	}
	log.Printf("[witness] stopped witnessing for %s; the rotation cutting this witness has "+
		"been checked", c.ControllerAID)
	if s.OnEvent != nil {
		s.OnEvent("witness_withdrawal_confirmed", map[string]interface{}{
			"controller_aid": c.ControllerAID,
		})
	}
	return nil
}

func reasonText(r WithdrawalReason) string {
	switch r {
	case WithdrawalShuttingDown:
		return "the operator is shutting down"
	case WithdrawalNoCapacity:
		return "it no longer has the capacity"
	default:
		return "no reason given"
	}
}

// witnessBase is the address an agent serves its witness routes under, taken
// from the OOBI it published.
func witnessBase(oobi string) string {
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		return strings.TrimRight(oobi[:idx], "/")
	}
	return strings.TrimRight(oobi, "/")
}

func withdrawalURL(oobi string) string { return witnessBase(oobi) + "/api/witness/withdraw" }
func withdrawalConfirmURL(oobi string) string {
	return witnessBase(oobi) + "/api/witness/withdraw/confirm"
}
