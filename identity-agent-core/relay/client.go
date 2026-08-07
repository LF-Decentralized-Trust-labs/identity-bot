package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Signer interface {
	SignCanonical(enrollmentAID string, body map[string]interface{}) (signature string, err error)
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Signer     Signer
	Token      string
}

func NewClient(baseURL string, token string, signer Signer) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		Signer:  signer,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) FetchDescriptor(ctx context.Context) (*ServiceDescriptor, error) {
	url := c.BaseURL + "/.well-known/url-relay-service.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descriptor %d", resp.StatusCode)
	}
	var d ServiceDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	if d.ProtocolVersion == "" || d.ProtocolVersion[0:1] != "1" {
		return nil, fmt.Errorf("unsupported protocol_version %s", d.ProtocolVersion)
	}
	return &d, nil
}

func (c *Client) Enroll(ctx context.Context, enrollmentAID, oobiURL string, publicKeyB64 string) (*EnrollResponse, error) {
	body := map[string]interface{}{
		"v": JSONVersion, "enrollment_aid": enrollmentAID, "oobi": oobiURL,
		"root_aid_enrollment": false, "public_key_b64": publicKeyB64,
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/enroll", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll %d: %s", resp.StatusCode, string(b))
	}
	var out EnrollResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	c.Token = out.EnrollmentToken
	return &out, nil
}

func (c *Client) Allocate(ctx context.Context, enrollmentAID, raid string) (*AllocateResponse, error) {
	body := map[string]interface{}{
		"v": JSONVersion, "raid": raid, "intent": "serve-didwebs-artifacts",
		"ttl_hint": "persistent", "signed_by": enrollmentAID,
	}
	sig, err := c.Signer.SignCanonical(enrollmentAID, body)
	if err != nil {
		return nil, err
	}
	body["signature"] = sig
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/allocate", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		var existing map[string]interface{}
		_ = json.Unmarshal(b, &existing)
		return &AllocateResponse{
			PublicHostname: str(existing["public_hostname"]),
			PublicURL:      str(existing["public_url"]),
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("allocate %d: %s", resp.StatusCode, string(b))
	}
	var out AllocateResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Release(ctx context.Context, enrollmentAID, allocationToken string) error {
	body := map[string]interface{}{
		"v": JSONVersion, "allocation_token": allocationToken, "signed_by": enrollmentAID,
	}
	sig, err := c.Signer.SignCanonical(enrollmentAID, body)
	if err != nil {
		return err
	}
	body["signature"] = sig
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/release", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.Token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("release %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}