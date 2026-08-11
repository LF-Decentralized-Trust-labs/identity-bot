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
	body, _ := json.Marshal(map[string]interface{}{
		"requester_aid":  s.ourAID(),
		"requester_oobi": s.ourOOBI(),
		"backend_type":   s.BackendType,
	})
	url := witnessRequestURL(c.OobiURL)
	_, err = s.PostEvent(ctx, url, body)
	if err != nil {
		return err
	}
	return s.Contacts.SaveTask(store.TaskRecord{
		ID:   fmt.Sprintf("witness-req-%s-%d", contactAID, time.Now().Unix()),
		Type: "witness_request_sent", Status: "pending", ContactAID: contactAID,
		Detail: "Witness enrollment request sent", CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
	})
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
