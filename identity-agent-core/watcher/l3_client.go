package watcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/witness"
	"net/http"
	"strings"
	"time"
)

// L3Client performs peer cross-check via /public/kel-check.
type L3Client struct {
	HTTPClient *http.Client
	// AllowLocal says whether a peer's address may be a local one: only where
	// the owner recorded it. Left nil, none may. A peer's name is held to the
	// address actually dialled either way, so a contact whose name was pointed
	// at an internal service after it was recorded is not called.
	AllowLocal func(peerBaseURL string) bool
}

func NewL3Client() *L3Client {
	return &L3Client{HTTPClient: witness.GuardedClient(5*time.Second, false)}
}

func (c *L3Client) CrossCheck(ctx context.Context, peerBaseURL string, req KelCheckRequest) (*KelCheckResponse, error) {
	base := strings.TrimRight(peerBaseURL, "/")
	u := base + "/public/kel-check"
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if c.AllowLocal != nil && c.AllowLocal(peerBaseURL) {
		client = witness.GuardedClient(5*time.Second, true)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := boundedread.All(resp.Body, boundedread.Document)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("L3 check %s: HTTP %d", u, resp.StatusCode)
	}
	var out KelCheckResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Tip asks a peer how much of an identity's key history it holds, via
// /public/kel-tip.
func (c *L3Client) Tip(ctx context.Context, peerBaseURL string, req KelTipRequest) (*KelTipResponse, error) {
	base := strings.TrimRight(peerBaseURL, "/")
	u := base + "/public/kel-tip"
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if c.AllowLocal != nil && c.AllowLocal(peerBaseURL) {
		client = witness.GuardedClient(5*time.Second, true)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := boundedread.All(resp.Body, boundedread.Document)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("L3 tip %s: HTTP %d", u, resp.StatusCode)
	}
	var out KelTipResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
