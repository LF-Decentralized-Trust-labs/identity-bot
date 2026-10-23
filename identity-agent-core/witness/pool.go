package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/store"
)

// SendWitnessRequest implements outbound enrollment.
func (s *Service) SendWitnessRequest(ctx context.Context, contactAID string) error {
	c, err := s.Contacts.GetContact(contactAID)
	if err != nil || c == nil {
		return fmt.Errorf("contact not found")
	}
	if !IsContactWitnessEligible(*c) {
		return fmt.Errorf("contact ineligible")
	}
	if s.ActiveWitnessCount() >= TargetContactWitnesses {
		return fmt.Errorf("witness pool full")
	}
	covers := s.AskToCoverDelegates != nil && s.AskToCoverDelegates()
	if _, err := s.postWitnessRequest(ctx, c, covers); err != nil {
		return err
	}
	return s.Contacts.SaveTask(store.TaskRecord{
		ID:   fmt.Sprintf("witness-req-%s-%d", contactAID, time.Now().Unix()),
		Type: "witness_request_sent", Status: "pending", ContactAID: contactAID,
		Detail: "Witness enrollment request sent", CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
	})
}

// postWitnessRequest sends a witness request, signed by this agent's
// identity where it can sign, and returns the witness's answer.
func (s *Service) postWitnessRequest(ctx context.Context, c *store.ContactRecord, covers bool) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"requester_aid":  s.ourAID(),
		"requester_oobi": s.ourOOBI(),
		"backend_type":   s.BackendType,
		// Whether this identity asks for the identities it delegates to be
		// witnessed too.
		"covers_delegates": covers,
	}
	if s.SignAsRequester != nil {
		stamp := time.Now().UTC().Format(time.RFC3339)
		if sig, err := s.SignAsRequester(RequestStatement(s.ourAID(), covers, stamp)); err == nil {
			req["stamp"], req["signature"] = stamp, sig
		}
	}
	body, _ := json.Marshal(req)
	return s.PostEvent(ctx, witnessRequestURL(c.OobiURL), body)
}

// AskToCoverDelegatesOf asks each of these witnesses, by the ordinary signed
// request, to witness the identities this one delegates too, and returns the
// ones that declined, with their reasons. A witness reached as a bootstrap
// service has no agreement to change and is not asked.
func (s *Service) AskToCoverDelegatesOf(ctx context.Context, designated []string) map[string]string {
	declined := map[string]string{}
	known := s.designatedTargets(designated)
	for _, key := range designated {
		w, ok := known[key]
		if !ok || w.Commercial {
			continue
		}
		c, _ := s.Contacts.GetContact(w.AID)
		if c == nil {
			declined[key] = "no contact to ask"
			continue
		}
		out, err := s.postWitnessRequest(ctx, c, true)
		if err != nil {
			declined[key] = err.Error()
			continue
		}
		switch {
		case out["status"] != "accepted":
			reason, _ := out["reason"].(string)
			if reason == "" {
				reason = "declined"
			}
			declined[key] = reason
		case out["covers_delegates"] != true:
			declined[key] = "agreed to witness this identity, but not the identities it delegates"
		}
	}
	return declined
}

func (s *Service) ourAID() string {
	if s.OurAID != nil {
		return s.OurAID()
	}
	return ""
}

func (s *Service) ourOOBI() string {
	if s.OurOOBI != nil {
		return s.OurOOBI()
	}
	return ""
}

// HandleInboundRequest is deprecated; use EvaluateInboundRequest / ProcessInboundRequest.
func (s *Service) HandleInboundRequest(reqAID, reqOOBI, reqBackend string) (bool, string) {
	return s.EvaluateInboundRequest(WitnessRequest{
		RequesterAID: reqAID, RequesterOOBI: reqOOBI, BackendType: reqBackend,
	})
}

func witnessRequestURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/") + "/api/witness/request"
}
