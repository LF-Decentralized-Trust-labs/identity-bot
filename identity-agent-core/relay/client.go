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
		BaseURL:    baseURL,
		Token:      token,
		Signer:     signer,
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

// Allocation lifetime values.
const (
	LifetimePermanent = "permanent"
	LifetimeEphemeral = "ephemeral"
)

// Allocation scope values — what the allocated URL is for. A per-relationship
// URL is bound to one Pairwise AID, an identity URL is shared across a persona,
// a per-transaction URL lives only for one transaction, an agent-endpoint URL is
// an owner's own device-reachable endpoint, and a controller-relationship URL is
// a black box's authenticated controller relationship.
const (
	ScopePerRelationship        = "per-relationship"
	ScopeIdentity               = "identity"
	ScopePerTransaction         = "per-transaction"
	ScopeAgentEndpoint          = "agent-endpoint"
	ScopeControllerRelationship = "controller-relationship"
)

// Allocation naming values — how the public hostname is chosen.
const (
	NamingOpaque = "opaque" // a CSPRNG subdomain — the default, unlinkable
	NamingStable = "stable" // a chosen, human-meaningful name — public personas only
)

// AllocateOptions carries the optional lifetime/scope/naming parameters of the
// allocate request.
//
// The zero value means "unset", and it is load-bearing: an allocate call made
// with the zero value puts NOTHING new on the wire. The request is then
// byte-for-byte the fixed opaque/persistent request that shipped before these
// fields existed, so an operator that does not understand them is unaffected and
// every existing caller keeps working. A field is added to the wire body only
// when it is set, which is what keeps the extension backward-compatible.
type AllocateOptions struct {
	// Lifetime is LifetimePermanent or LifetimeEphemeral. Empty leaves it
	// unset, which an operator treats as the historical persistent default.
	Lifetime string

	// TTLSeconds is the requested lifetime in seconds, meaningful only when
	// Lifetime is LifetimeEphemeral. It is omitted from the wire otherwise, and
	// when zero.
	TTLSeconds int

	// Scope is one of the Scope* values. Empty leaves it unset.
	Scope string

	// Naming is NamingOpaque or NamingStable. Empty leaves it unset, which an
	// operator treats as opaque — the historical default.
	Naming string
}

// applyAllocateOptions adds a field to the request body only when the
// corresponding option is set, so an unset AllocateOptions changes nothing about
// the request. ttl accompanies an ephemeral lifetime and is dropped otherwise.
func applyAllocateOptions(body map[string]interface{}, opts AllocateOptions) {
	if opts.Lifetime != "" {
		body["lifetime"] = opts.Lifetime
	}
	if opts.Lifetime == LifetimeEphemeral && opts.TTLSeconds > 0 {
		body["ttl"] = opts.TTLSeconds
	}
	if opts.Scope != "" {
		body["scope"] = opts.Scope
	}
	if opts.Naming != "" {
		body["naming"] = opts.Naming
	}
}

// Allocate requests a public URL for raid with the default semantics
// (opaque naming, persistent lifetime). It is preserved unchanged for existing
// callers; AllocateWithOptions is the same call with the lifetime/scope/naming
// parameters exposed.
func (c *Client) Allocate(ctx context.Context, enrollmentAID, raid string) (*AllocateResponse, error) {
	return c.AllocateWithOptions(ctx, enrollmentAID, raid, AllocateOptions{})
}

// AllocateWithOptions requests a public URL for raid, carrying the optional
// lifetime/scope/naming parameters when they are set. With the zero-value
// AllocateOptions it is identical on the wire to Allocate.
func (c *Client) AllocateWithOptions(ctx context.Context, enrollmentAID, raid string, opts AllocateOptions) (*AllocateResponse, error) {
	body := map[string]interface{}{
		"v": JSONVersion, "raid": raid, "intent": "serve-didwebs-artifacts",
		"ttl_hint": "persistent", "signed_by": enrollmentAID,
	}
	applyAllocateOptions(body, opts)
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
