package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"identity-agent-core/store"
)

// WitnessRequest is the inbound enrollment-request body.
type WitnessRequest struct {
	RequesterAID  string
	RequesterOOBI string
	BackendType   string
}

// AcceptCallback is the accept POST-back body.
type AcceptCallback struct {
	RequesterAID string `json:"requester_aid"`
	ResponderAID string `json:"responder_aid"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	BackendType  string `json:"backend_type,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
}

// InboundResult is the outcome of evaluating an inbound enrollment request.
type InboundResult struct {
	Accepted bool
	Reason   string
	TaskID   string
}

// EvaluateInboundRequest applies C7 rules for accepting witnessing FOR the requester.
func (s *Service) EvaluateInboundRequest(req WitnessRequest) (bool, string) {
	if req.RequesterAID == "" {
		return false, "missing_requester"
	}
	contact, _ := s.Contacts.GetContact(req.RequesterAID)
	if contact == nil {
		return false, "unknown_contact"
	}
	if contact.Status != "accepted" {
		return false, "contact_not_accepted"
	}
	if !IsContactWitnessEligible(*contact) {
		return false, "contact_ineligible"
	}
	switch contact.ContactCategory {
	case "trusted", "professional":
	default:
		return false, "contact_category_ineligible"
	}
	if req.BackendType == BackendMobile || strings.EqualFold(req.BackendType, "phone") {
		return false, "mobile_backend"
	}
	if !IsBackendEligible(s.BackendType) {
		return false, "local_backend_ineligible"
	}
	outgoing, _ := s.Store.CountWitnessingFor()
	if outgoing >= MaxOutgoingWitnessing {
		return false, "capacity_full"
	}
	if !s.localWitnessCapacityOK() {
		return false, "local_unhealthy"
	}
	return true, ""
}

func (s *Service) localWitnessCapacityOK() bool {
	outgoing, _ := s.Store.CountWitnessingFor()
	return outgoing < MaxOutgoingWitnessing && IsBackendEligible(s.BackendType)
}

// ProcessInboundRequest handles the inbound enrollment request: evaluate, enroll as witnessing-for, task, POST-back, reciprocal.
func (s *Service) ProcessInboundRequest(ctx context.Context, req WitnessRequest) InboundResult {
	accept, reason := s.EvaluateInboundRequest(req)
	taskID := fmt.Sprintf("witness-recv-%s-%d", req.RequesterAID, time.Now().Unix())
	now := NowRFC3339()
	taskStatus := "failed"
	detail := fmt.Sprintf("Declined: %s", reason)

	if accept {
		if err := s.enrollWitnessingFor(req.RequesterAID, req.BackendType); err != nil {
			accept = false
			reason = "enroll_failed"
			detail = err.Error()
		} else {
			taskStatus = "completed"
			detail = fmt.Sprintf("Now witnessing key events for %s", req.RequesterAID[:12])
		}
	}

	_ = s.Contacts.SaveTask(store.TaskRecord{
		ID: taskID, Type: "witness_request_received", Status: taskStatus,
		ContactAID: req.RequesterAID, Detail: detail, CreatedAt: now, UpdatedAt: now,
	})

	responder := s.ourAID()
	decision := "declined"
	if accept {
		decision = "accepted"
	}
	cb := AcceptCallback{
		RequesterAID: req.RequesterAID, ResponderAID: responder,
		Decision: decision, Reason: reason, BackendType: s.BackendType, TaskID: taskID,
	}
	if req.RequesterOOBI != "" {
		go func() {
			if err := s.SendAcceptCallback(context.Background(), req.RequesterOOBI, cb); err != nil {
				log.Printf("[witness] accept POST-back failed: %v", err)
			}
		}()
	}

	if accept {
		go s.maybeReciprocalRequest(context.Background(), req)
	}

	return InboundResult{Accepted: accept, Reason: reason, TaskID: taskID}
}

// enrollWitnessingFor records that we witness FOR requester (outgoing direction).
func (s *Service) enrollWitnessingFor(requesterAID, backendType string) error {
	if backendType == "" {
		backendType = BackendDesktop
	}
	now := NowRFC3339()
	meta, _ := s.Store.GetContactMeta(requesterAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: requesterAID}
	}
	meta.BackendType = backendType
	meta.WitnessStatus = StatusOnline
	meta.WitnessingFor = true
	meta.EnrolledAt = now
	meta.LastHealthCheck = now
	if err := s.Store.SaveContactMeta(*meta); err != nil {
		return err
	}
	c, _ := s.Contacts.GetContact(requesterAID)
	if c != nil {
		return nil
	}
	return s.Contacts.SaveContact(store.ContactRecord{
		AID: requesterAID, Alias: requesterAID[:12] + "…", Status: "accepted",
		ContactCategory: "general", ContactSource: ContactSourceManual,
	})
}

// SendAcceptCallback sends the accept POST-back to the requester's agent.
func (s *Service) SendAcceptCallback(ctx context.Context, requesterOOBI string, cb AcceptCallback) error {
	if requesterOOBI == "" {
		return fmt.Errorf("missing requester oobi")
	}
	if cb.ResponderAID == "" {
		cb.ResponderAID = s.ourAID()
	}
	body, err := json.Marshal(cb)
	if err != nil {
		return err
	}
	url := witnessAcceptURL(requesterOOBI)
	_, err = s.PostEvent(ctx, url, body)
	return err
}

// ApplyAcceptCallback handles the accept POST-back on the original requester after the remote POST-back.
func (s *Service) ApplyAcceptCallback(cb AcceptCallback) error {
	if cb.RequesterAID == "" || cb.ResponderAID == "" {
		return fmt.Errorf("missing aids")
	}
	ourAID := s.ourAID()
	if cb.RequesterAID != ourAID {
		return fmt.Errorf("requester_aid mismatch")
	}
	accepted := cb.Decision == "accepted"
	now := NowRFC3339()

	if accepted {
		if err := s.enrollWitnessForUs(cb.ResponderAID, cb.BackendType); err != nil {
			return err
		}
		_ = s.completePendingSentTask(cb.ResponderAID, "completed",
			fmt.Sprintf("Witness enrollment accepted by %s", cb.ResponderAID[:12]))
		_ = s.refreshMutual(cb.ResponderAID)
	} else {
		_ = s.completePendingSentTask(cb.ResponderAID, "failed",
			fmt.Sprintf("Declined: %s", cb.Reason))
	}
	if s.OnEvent != nil {
		s.OnEvent("witness_accept_received", map[string]interface{}{
			"responder_aid": cb.ResponderAID, "decision": cb.Decision, "reason": cb.Reason,
		})
	}
	_ = now
	return nil
}

// enrollWitnessForUs marks responder as a witness FOR our AID (broadcast pool).
func (s *Service) enrollWitnessForUs(responderAID, backendType string) error {
	c, err := s.Contacts.GetContact(responderAID)
	if err != nil {
		return err
	}
	if c == nil {
		c = &store.ContactRecord{
			AID: responderAID, Alias: responderAID[:12] + "…", Status: "accepted",
			ContactCategory: "trusted", ContactSource: ContactSourceManual,
		}
	}
	c.IsWitness = true
	if err := s.Contacts.SaveContact(*c); err != nil {
		return err
	}
	if backendType == "" {
		backendType = BackendDesktop
	}
	now := NowRFC3339()
	meta, _ := s.Store.GetContactMeta(responderAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: responderAID}
	}
	meta.BackendType = backendType
	meta.WitnessStatus = StatusOnline
	meta.EnrolledAt = now
	meta.LastHealthCheck = now
	return s.Store.SaveContactMeta(*meta)
}

func (s *Service) completePendingSentTask(contactAID, status, detail string) error {
	tasks, err := s.Contacts.GetTasks()
	if err != nil {
		return err
	}
	for i := range tasks {
		t := tasks[i]
		if t.Type != "witness_request_sent" || t.ContactAID != contactAID || t.Status != "pending" {
			continue
		}
		t.Status = status
		t.Detail = detail
		t.UpdatedAt = NowRFC3339()
		return s.Contacts.SaveTask(t)
	}
	return nil
}

func (s *Service) refreshMutual(contactAID string) error {
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil || !c.IsWitness {
		return nil
	}
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil || !meta.WitnessingFor {
		return nil
	}
	meta.IsMutual = true
	return s.Store.SaveContactMeta(*meta)
}

func (s *Service) maybeReciprocalRequest(ctx context.Context, req WitnessRequest) {
	if s.ActiveWitnessCount() >= TargetContactWitnesses {
		return
	}
	if !IsBackendEligible(req.BackendType) && req.BackendType != "" {
		return
	}
	c, _ := s.Contacts.GetContact(req.RequesterAID)
	if c == nil || c.IsWitness {
		return
	}
	if c.ContactCategory != "trusted" && c.ContactCategory != "professional" {
		return
	}
	_ = s.SendWitnessRequest(ctx, req.RequesterAID)
}

func witnessAcceptURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/") + "/api/witness/accept"
}
