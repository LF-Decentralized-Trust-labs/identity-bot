package endpointclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AgentProvision is the result of provisioning an AI agent on an Identity Agent.
type AgentProvision struct {
	AgentName    string   `json:"agent_name"`
	AssetID      string   `json:"asset_id"`
	AgentAID     string   `json:"agent_aid"`
	DelegatorAID string   `json:"delegator_aid"`
	GrantSAID    string   `json:"grant_said"`
	GrantIssued  bool     `json:"grant_issued"`
	Capabilities []string `json:"capabilities"`
	Token        string   `json:"token"`
}

// ProvisionAgent provisions an ai_agent on the Identity Agent at baseURL (a
// local-owner call) and returns its delegated AID plus a bound bearer token. This
// is the setup step an operator or Identity Agent runs; the returned Token is what
// the agent then uses with New(). resourceConstraints is optional
// (capabilityID -> {argKey: [allowedValues]}).
func ProvisionAgent(ctx context.Context, baseURL, name string, capabilities []string, resourceConstraints map[string]interface{}, httpc *http.Client) (*AgentProvision, error) {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	payload := map[string]interface{}{
		"name":         name,
		"capabilities": capabilities,
	}
	if len(resourceConstraints) > 0 {
		payload["resource_constraints"] = resourceConstraints
	}
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/mcp/agents", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("provision failed (%d): %s", resp.StatusCode, string(raw))
	}
	var out AgentProvision
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode provision response: %w", err)
	}
	return &out, nil
}
