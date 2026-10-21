package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// Signer signs a control request with the enrolment key, over CanonicalBody.
type Signer interface {
	SignCanonical(enrollmentAID string, body map[string]interface{}) (signature string, err error)
}

// Client makes the control requests an Identity Agent sends a relay beside its
// session. None carries a token: each is signed by the enrolment identifier's
// current key, and the relay accepts it only while that identifier holds a live
// session (ADR-048 §8).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Signer     Signer
	// Descriptor is the relay's, once fetched; its service name goes in every
	// request and its endpoints say where each op is sent.
	Descriptor *ServiceDescriptor
}

// NewClient returns a client for the relay at baseURL.
func NewClient(baseURL string, signer Signer) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Signer:     signer,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// maxAnswer bounds what is read from a relay's answer. A relay is not trusted
// to keep its answers small.
const maxAnswer = 64 << 10

// FetchDescriptor reads the relay's discovery descriptor and keeps it.
func (c *Client) FetchDescriptor(ctx context.Context) (*ServiceDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/.well-known/url-relay-service.json", nil)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(&d); err != nil {
		return nil, err
	}
	if d.Protocol != relayproto.ProtocolVersion {
		return nil, fmt.Errorf("the relay speaks %q; this Identity Agent speaks %q", d.Protocol, relayproto.ProtocolVersion)
	}
	if !strings.HasPrefix(d.TunnelEndpoint, "wss://") || d.Service == "" {
		return nil, fmt.Errorf("the relay's descriptor names no service or no wss:// session endpoint")
	}
	c.Descriptor = &d
	return &d, nil
}

// NewSecret makes the secret a private address is held by, and the commitment
// the relay stores in its place: base64url SHA-256 of the secret.
func NewSecret() (secret, commitment string) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("relay: no randomness: " + err.Error())
	}
	return b64.EncodeToString(raw), Commitment(raw)
}

// Commitment is what a relay stores for a private address's secret.
func Commitment(secret []byte) string {
	sum := sha256.Sum256(secret)
	return b64.EncodeToString(sum[:])
}

// Allocate makes a private address held by the secret behind commitment.
func (c *Client) Allocate(ctx context.Context, aid, commitment string) (label, url string, err error) {
	var out struct {
		Allocation string `json:"allocation"`
		PublicURL  string `json:"public_url"`
	}
	if err := c.control(ctx, OpAllocate, aid, map[string]string{"commitment": commitment}, &out); err != nil {
		return "", "", err
	}
	if out.Allocation == "" || out.PublicURL == "" {
		return "", "", fmt.Errorf("allocate: the relay named no address")
	}
	return out.Allocation, strings.TrimRight(out.PublicURL, "/"), nil
}

// Bind attaches a private address to this Identity Agent's session, proving it
// is the holder by the secret. It is sent for every address after every
// admission: a relay keeps which session serves which address only in memory.
func (c *Client) Bind(ctx context.Context, aid, label, secret string) error {
	return c.control(ctx, OpBind, aid, map[string]string{"allocation": label, "secret": secret}, nil)
}

// Release ends a private address for good.
func (c *Client) Release(ctx context.Context, aid, label, secret string) error {
	return c.control(ctx, OpRelease, aid, map[string]string{"allocation": label, "secret": secret}, nil)
}

// ClaimName claims a public name. Claiming a name already held is harmless.
func (c *Client) ClaimName(ctx context.Context, aid, name string) (url string, err error) {
	var out struct {
		PublicURL string `json:"public_url"`
	}
	if err := c.control(ctx, OpClaimName, aid, map[string]string{"name": name}, &out); err != nil {
		return "", err
	}
	if out.PublicURL == "" {
		return "", fmt.Errorf("claim-name: the relay named no address")
	}
	return strings.TrimRight(out.PublicURL, "/"), nil
}

// ReleaseName gives up a public name.
func (c *Client) ReleaseName(ctx context.Context, aid, name string) error {
	return c.control(ctx, OpReleaseName, aid, map[string]string{"name": name}, nil)
}

// RequestDomain asks to serve a custom domain, and returns the DNS record that
// proves it is this identity's.
func (c *Client) RequestDomain(ctx context.Context, aid, domain string) (*DomainProof, error) {
	var out DomainProof
	if err := c.control(ctx, OpRequestDomain, aid, map[string]string{"domain": domain}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyDomain asks the relay to check the DNS record and, once it holds,
// serve the domain.
func (c *Client) VerifyDomain(ctx context.Context, aid, domain string) (url string, err error) {
	var out struct {
		PublicURL string `json:"public_url"`
	}
	if err := c.control(ctx, OpVerifyDomain, aid, map[string]string{"domain": domain}, &out); err != nil {
		return "", err
	}
	return strings.TrimRight(out.PublicURL, "/"), nil
}

// ReleaseDomain stops serving a custom domain.
func (c *Client) ReleaseDomain(ctx context.Context, aid, domain string) error {
	return c.control(ctx, OpReleaseDomain, aid, map[string]string{"domain": domain}, nil)
}

// control signs and sends one control request. Every field is a string; the
// request names its op, the relay it is for, a fresh time and a nonce, so it
// can be used once, for one thing, at one relay.
func (c *Client) control(ctx context.Context, op, aid string, fields map[string]string, out interface{}) error {
	if c.Descriptor == nil {
		if _, err := c.FetchDescriptor(ctx); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	body := map[string]interface{}{
		"op": op, "relay": c.Descriptor.Service, "signed_by": aid,
		"t": time.Now().UTC().Format(time.RFC3339), "nonce": b64.EncodeToString(nonce),
	}
	for k, v := range fields {
		body[k] = v
	}
	sig, err := c.Signer.SignCanonical(aid, body)
	if err != nil {
		return err
	}
	body["signature"] = sig
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := c.Descriptor.Endpoints[op]
	if endpoint == "" {
		endpoint = c.BaseURL + defaultPaths[op]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode != http.StatusOK {
		return &RefusedError{Op: op, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// RefusedError is a control request the relay answered with an error.
type RefusedError struct {
	Op     string
	Status int
	Body   string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("%s: %d: %s", e.Op, e.Status, e.Body) }

var b64 = base64.RawURLEncoding
