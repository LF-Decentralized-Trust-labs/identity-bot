package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/internal/boundedread"
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
	raw, err := boundedread.All(resp.Body, maxAnswer)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d.Protocol != relayproto.ProtocolVersion {
		return nil, fmt.Errorf("the relay speaks %q; this Identity Agent speaks %q", d.Protocol, relayproto.ProtocolVersion)
	}
	if d.Service == "" {
		return nil, fmt.Errorf("the relay's descriptor names no service")
	}
	if err := CheckConnectHost(c.BaseURL, &d); err != nil {
		return nil, err
	}
	if err := c.checkParentCallerHost(ctx, &d); err != nil {
		return nil, err
	}
	c.Descriptor = &d
	return &d, nil
}

// CheckConnectHost holds the descriptor to one connect host under the relay's
// own name, and every endpoint to it.
//
// The descriptor may arrive through a proxy in front of the relay's callers.
// A proxy that rewrote it to send this Identity Agent somewhere else would
// have it admitted, and its addresses served, by whoever answers there. So the
// connect host must be the relay's own host or a name under it, and the
// session and control endpoints must all be at that host.
func CheckConnectHost(baseURL string, d *ServiceDescriptor) error {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" {
		return fmt.Errorf("the relay %q is not a URL", baseURL)
	}
	// The descriptor named the connect host itself, and it is the host this
	// client was pointed at: the relay is being reached at its connect host.
	namedConnect := d.ConnectHost != "" && hostName(d.ConnectHost) == strings.ToLower(base.Hostname())
	if d.ConnectHost == "" {
		d.ConnectHost = base.Host
	}
	if d.CallerHost != "" {
		// The caller host is the relay's own name or a name under it. A client
		// pointed at the connect host may also be given the connect host's
		// immediate parent (the apex, with connect.<apex> as the connect host),
		// and no other ancestor: example.com or com are somebody else's.
		caller := strings.ToLower(d.CallerHost)
		callerName := hostName(caller)
		bn := strings.ToLower(base.Hostname())
		parent := ""
		if namedConnect {
			if i := strings.Index(bn, "."); i > 0 {
				parent = bn[i+1:]
			}
		}
		if callerName != bn && !strings.HasSuffix(callerName, "."+bn) && (parent == "" || callerName != parent) {
			return fmt.Errorf("the relay at %s names %s as its caller host, which is not under its own name", bn, caller)
		}
	}
	connect := strings.ToLower(d.ConnectHost)
	connectName := connect
	if h, _, err := net.SplitHostPort(connect); err == nil {
		connectName = h
	}
	baseName := strings.ToLower(base.Hostname())
	if connectName != baseName && !strings.HasSuffix(connectName, "."+baseName) {
		return fmt.Errorf("the relay at %s names %s as its connect host, which is not under its own name", baseName, connect)
	}
	at := func(raw, scheme string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == scheme && strings.ToLower(u.Host) == connect
	}
	if !at(d.TunnelEndpoint, "wss") {
		return fmt.Errorf("the relay's session endpoint %q is not at its connect host %s", d.TunnelEndpoint, connect)
	}
	for op, ep := range d.Endpoints {
		if !at(ep, "https") {
			return fmt.Errorf("the relay's %s endpoint %q is not at its connect host %s", op, ep, connect)
		}
	}
	return nil
}

// checkParentCallerHost holds a caller host above the relay's own name to the
// parent's own word. A host can name itself as connect host and so have its
// parent accepted (alice.herokuapp.com could claim herokuapp.com), so the
// parent must itself publish a descriptor for the same service.
func (c *Client) checkParentCallerHost(ctx context.Context, d *ServiceDescriptor) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil || d.CallerHost == "" {
		return err
	}
	bn := strings.ToLower(base.Hostname())
	callerName := hostName(d.CallerHost)
	if callerName == bn || strings.HasSuffix(callerName, "."+bn) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.Scheme+"://"+d.CallerHost+"/.well-known/url-relay-service.json", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("the caller host %s could not be asked whether it is this relay: %w", d.CallerHost, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the caller host %s does not serve this relay's descriptor (%d)", d.CallerHost, resp.StatusCode)
	}
	raw, err := boundedread.All(resp.Body, maxAnswer)
	if err != nil {
		return fmt.Errorf("the caller host %s serves no readable descriptor: %w", d.CallerHost, err)
	}
	var parent ServiceDescriptor
	if err := json.Unmarshal(raw, &parent); err != nil {
		return fmt.Errorf("the caller host %s serves no readable descriptor: %w", d.CallerHost, err)
	}
	if parent.Service == "" || parent.Service != d.Service {
		return fmt.Errorf("the caller host %s is a different service (%q), not %q", d.CallerHost, parent.Service, d.Service)
	}
	return nil
}

// hostName is a host without its port, lowercased.
func hostName(hostport string) string {
	h := strings.ToLower(hostport)
	if n, _, err := net.SplitHostPort(h); err == nil {
		return n
	}
	return h
}

// sameHost reports whether two hosts are one, with the scheme's default port
// the same as no port: relay.example:443 is relay.example for https.
func sameHost(scheme, a, b string) bool {
	norm := func(h string) string {
		h = strings.ToLower(h)
		if n, p, err := net.SplitHostPort(h); err == nil {
			if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
				return n
			}
		}
		return h
	}
	return norm(a) == norm(b)
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
func (c *Client) Allocate(ctx context.Context, aid, commitment string) (label, address string, err error) {
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
	if err := relayproto.CheckPrivateURL(out.PublicURL, out.Allocation); err != nil {
		return "", "", fmt.Errorf("allocate: %w", err)
	}
	// One host for every relationship: the relay's own, which this client was
	// pointed at. A host of its own per identity would still show each one in
	// the TLS handshake, whatever the label.
	// The relay's own host is the descriptor's caller host: a client pointed at
	// the connect host is given addresses at the caller-facing one. Without a
	// descriptor naming one, it is the host this client was pointed at.
	base, berr := url.Parse(c.BaseURL)
	got, gerr := url.Parse(out.PublicURL)
	if berr != nil || gerr != nil {
		return "", "", fmt.Errorf("allocate: the relay gave an address at %q, not at its own host %q", out.PublicURL, c.BaseURL)
	}
	callerHost := base.Host
	if c.Descriptor != nil && c.Descriptor.CallerHost != "" {
		callerHost = c.Descriptor.CallerHost
	}
	if !sameHost(got.Scheme, got.Host, callerHost) {
		return "", "", fmt.Errorf("allocate: the relay gave an address at %q, not at its own host %q", out.PublicURL, callerHost)
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
		endpoint = "https://" + c.Descriptor.ConnectHost + defaultPaths[op]
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
	b, err := boundedread.All(resp.Body, maxAnswer)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if resp.StatusCode != http.StatusOK {
		refused := &RefusedError{Op: op, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
		var e struct {
			Code    string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &e) == nil {
			refused.Code, refused.Message = e.Code, e.Message
		}
		return refused
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// RefusedError is a control request the relay answered with an error. Code
// and Message are the relay's own, when it gave them: "taken", "reserved",
// "quota", "invalid_name", "unproven" and so on.
type RefusedError struct {
	Op      string
	Status  int
	Body    string
	Code    string
	Message string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("%s: %d: %s", e.Op, e.Status, e.Body) }

var b64 = base64.RawURLEncoding
