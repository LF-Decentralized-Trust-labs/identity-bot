package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// WitnessRequest is the inbound enrollment-request body.
type WitnessRequest struct {
	RequesterAID  string
	RequesterOOBI string
	BackendType   string
	// CoversDelegates asks the witness to witness the identities the
	// requester delegates too. Not assumed: a request that does not ask
	// covers none.
	CoversDelegates bool
	// Stamp and Signature are the requester's signature, by its current key,
	// over who it is, whether it covers its delegates, and when it asked
	// (RequestStatement). Coverage is changed, either way, only by a request
	// that carries one that holds and is fresh: the route is open, and
	// anybody could otherwise switch it on or off for anyone.
	Stamp     string
	Signature string
}

// RequestStatement is what a requester signs in a witness request: who it
// is, which witness it asks, whether it covers its delegates, and when. Naming
// the witness keeps a request signed for one from being replayed to another.
func RequestStatement(requester, witnessAID string, covers bool, stamp string) string {
	return fmt.Sprintf("witness-request/v2\n%s\n%s\n%v\n%s", requester, witnessAID, covers, stamp)
}

// configRequestStamps is, by requester, the stamp of the last signed request
// that changed its coverage: an older or equal one is a replay.
const configRequestStamps = "witness.request_stamps"

// requestFreshness is how far a signed witness request's stamp may be from
// now.
const requestFreshness = 5 * time.Minute

// signedByRequester reports whether req carries the requester's own fresh
// signature, checked against its current key: the newest establishment event
// this witness holds for it, or else the key its contact record resolved.
func (s *Service) signedByRequester(req WitnessRequest) bool {
	if req.Signature == "" || req.Stamp == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, req.Stamp)
	if err != nil || time.Since(at) > requestFreshness || time.Until(at) > requestFreshness {
		return false
	}
	if !s.signedBy(req.RequesterAID, RequestStatement(req.RequesterAID, s.ourAID(), req.CoversDelegates, req.Stamp), req.Signature) {
		return false
	}
	// Newer than the last one acted on for this requester, or a replay.
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	stamps := map[string]string{}
	if raw, err := s.Store.GetConfig(configRequestStamps); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &stamps)
	}
	if last, err := time.Parse(time.RFC3339Nano, stamps[req.RequesterAID]); err == nil && !at.After(last) {
		return false
	}
	stamps[req.RequesterAID] = req.Stamp
	raw, _ := json.Marshal(stamps)
	_ = s.Store.SetConfig(configRequestStamps, string(raw))
	return true
}

// currentKeyOf is the key aid signs with now: the newest establishment event
// this agent holds for it, or else the key its contact record resolved.
func (s *Service) currentKeyOf(aid string) string {
	key := ""
	if held, err := s.Store.GetKelEvents(aid); err == nil {
		for _, e := range held {
			var ev map[string]interface{}
			if json.Unmarshal([]byte(e.EventJSON), &ev) != nil {
				continue
			}
			switch ev["t"] {
			case "icp", "rot", "dip", "drt":
				if keys, ok := ev["k"].([]interface{}); ok && len(keys) > 0 {
					key, _ = keys[0].(string)
				}
			}
		}
	}
	if key == "" {
		if c, _ := s.Contacts.GetContact(aid); c != nil {
			key = c.PublicKey
		}
	}
	return key
}

// signedBy reports whether signature is aid's, by its current key, over
// statement.
func (s *Service) signedBy(aid, statement, signature string) bool {
	if signature == "" {
		return false
	}
	key := s.currentKeyOf(aid)
	if key == "" {
		return false
	}
	pub, err := login.DecodeVerkey(key)
	if err != nil {
		return false
	}
	ok, err := login.VerifyString(statement, signature, pub)
	return err == nil && ok
}

// AcceptCallback is the accept POST-back body: a witness's answer to a
// request to witness for the requester.
//
// It is signed by the responder, with its current key, over who asked, who
// answers, the answer and when (AcceptStatement). The route it arrives on is
// open, and acting on it makes the responder a witness for the requester, so
// an answer nobody can show the responder gave changes nothing.
type AcceptCallback struct {
	RequesterAID string `json:"requester_aid"`
	ResponderAID string `json:"responder_aid"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	BackendType  string `json:"backend_type,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	Stamp        string `json:"stamp,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// AcceptStatement is what a responder signs in its answer to a witness
// request: who asked, who answers, the answer, the backend it answers from,
// and when. Naming the requester keeps an answer to one from being replayed to
// another.
func AcceptStatement(requester, responder, decision, backendType, stamp string) string {
	return fmt.Sprintf("witness-accept/v1\n%s\n%s\n%s\n%s\n%s", requester, responder, decision, backendType, stamp)
}

// configAcceptStamps is, by responder, the stamp of the last signed answer
// acted on: an older or equal one is a replay.
const configAcceptStamps = "witness.accept_stamps"

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
	// One already witnessed for, asking again, takes no more capacity.
	if meta, _ := s.Store.GetContactMeta(req.RequesterAID); meta != nil && meta.WitnessingFor {
		return true, ""
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
			if s.signedByRequester(req) {
				s.agreeToDelegates(req.RequesterAID, req.CoversDelegates)
			}
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
	// An unsigned answer is refused by the requester, so one that cannot be
	// signed here is not sent.
	if s.SignAsRequester == nil {
		return fmt.Errorf("this agent cannot sign as its identity, so it cannot answer")
	}
	cb.Stamp = time.Now().UTC().Format(time.RFC3339Nano)
	sig, err := s.SignAsRequester(AcceptStatement(cb.RequesterAID, cb.ResponderAID, cb.Decision, cb.BackendType, cb.Stamp))
	if err != nil {
		return fmt.Errorf("sign the answer: %w", err)
	}
	cb.Signature = sig
	body, err := json.Marshal(cb)
	if err != nil {
		return err
	}
	url := witnessAcceptURL(requesterOOBI)
	_, err = s.PostEvent(ctx, url, body)
	return err
}

// ApplyAcceptCallback acts on a witness's answer to a request this agent sent.
//
// Before anything is written, the answer must be signed by the responder's
// current key, fresh, newer than the last answer acted on from it, and answer
// a request still pending to that responder. An answer nobody asked for, or
// one that cannot be shown to be the responder's, changes nothing: acting on
// it would make whoever sent it a witness this identity never chose.
func (s *Service) ApplyAcceptCallback(cb AcceptCallback) error {
	if cb.RequesterAID == "" || cb.ResponderAID == "" {
		return fmt.Errorf("missing aids")
	}
	if cb.RequesterAID != s.ourAID() {
		return fmt.Errorf("requester_aid mismatch")
	}
	if cb.Decision != "accepted" && cb.Decision != "declined" {
		return fmt.Errorf("an answer is accepted or declined, not %q", cb.Decision)
	}
	at, err := time.Parse(time.RFC3339Nano, cb.Stamp)
	if err != nil || time.Since(at) > requestFreshness || time.Until(at) > requestFreshness {
		return fmt.Errorf("the answer carries no fresh stamp")
	}
	if !s.signedBy(cb.ResponderAID, AcceptStatement(cb.RequesterAID, cb.ResponderAID, cb.Decision, cb.BackendType, cb.Stamp), cb.Signature) {
		return fmt.Errorf("the answer is not signed by %s", cb.ResponderAID)
	}

	s.acceptMu.Lock()
	defer s.acceptMu.Unlock()
	stamps := map[string]string{}
	if raw, err := s.Store.GetConfig(configAcceptStamps); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &stamps)
	}
	if last, err := time.Parse(time.RFC3339Nano, stamps[cb.ResponderAID]); err == nil && !at.After(last) {
		return fmt.Errorf("the answer has already been acted on")
	}
	task, err := s.pendingSentTask(cb.ResponderAID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("no witness request to %s is waiting for an answer", cb.ResponderAID)
	}

	accepted := cb.Decision == "accepted"
	if accepted {
		if err := s.enrollWitnessForUs(cb.ResponderAID, cb.BackendType); err != nil {
			return err
		}
	}
	stamps[cb.ResponderAID] = cb.Stamp
	raw, _ := json.Marshal(stamps)
	if err := s.Store.SetConfig(configAcceptStamps, string(raw)); err != nil {
		return err
	}
	if accepted {
		if err := s.completeTask(*task, "completed",
			fmt.Sprintf("Witness enrollment accepted by %s", cb.ResponderAID[:12])); err != nil {
			return err
		}
		_ = s.refreshMutual(cb.ResponderAID)
	} else {
		if err := s.completeTask(*task, "failed", fmt.Sprintf("Declined: %s", cb.Reason)); err != nil {
			return err
		}
	}
	if s.OnEvent != nil {
		s.OnEvent("witness_accept_received", map[string]interface{}{
			"responder_aid": cb.ResponderAID, "decision": cb.Decision, "reason": cb.Reason,
		})
	}
	return nil
}

// enrollWitnessForUs marks responder as a witness FOR our AID (broadcast pool).
func (s *Service) enrollWitnessForUs(responderAID, backendType string) error {
	c, err := s.Contacts.GetContact(responderAID)
	if err != nil {
		return err
	}
	// A request is only ever sent to a contact, so an answer from anybody
	// else is not one to act on, and is never a reason to make them a contact.
	if c == nil {
		return fmt.Errorf("%s is not a contact", responderAID)
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

// pendingSentTask is the witness request to contactAID still waiting for an
// answer, or nil.
func (s *Service) pendingSentTask(contactAID string) (*store.TaskRecord, error) {
	tasks, err := s.Contacts.GetTasks()
	if err != nil {
		return nil, err
	}
	for i := range tasks {
		t := tasks[i]
		if t.Type == "witness_request_sent" && t.ContactAID == contactAID && t.Status == "pending" {
			return &t, nil
		}
	}
	return nil, nil
}

func (s *Service) completeTask(t store.TaskRecord, status, detail string) error {
	t.Status = status
	t.Detail = detail
	t.UpdatedAt = NowRFC3339()
	return s.Contacts.SaveTask(t)
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
