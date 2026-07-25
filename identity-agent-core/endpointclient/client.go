package endpointclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client calls an Identity Agent capability endpoint. Zero value is not usable —
// build with New. Safe for concurrent use.
type Client struct {
	baseURL string
	token   string
	signer  Signer
	http    *http.Client
	now     func() time.Time // injectable for tests
}

// Option configures a Client.
type Option func(*Client)

// WithSigner attaches a Signer so each Invoke carries a signed-request envelope.
func WithSigner(s Signer) Option { return func(c *Client) { c.signer = s } }

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New builds a Client for baseURL (e.g. "http://127.0.0.1:5050") authenticating
// with the given bearer token.
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
		now:     time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// InvokeResult is a capability invocation's outcome as returned by the endpoint.
type InvokeResult struct {
	Status       int             `json:"status"`
	Body         json.RawMessage `json:"body,omitempty"`
	AuditEventID int64           `json:"audit_event_id,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// Invoke calls one capability through the endpoint's `execute` meta-tool. When the
// client has a Signer, the request carries a signed envelope; otherwise it is a
// plain bearer-token call. args may be nil.
func (c *Client) Invoke(ctx context.Context, capabilityID string, args map[string]interface{}) (*InvokeResult, error) {
	if args == nil {
		args = map[string]interface{}{}
	}
	// Marshal params ONCE; the exact bytes are used for both the body and the
	// signature so they cannot drift.
	params, err := json.Marshal(map[string]interface{}{
		"name": "execute",
		"arguments": map[string]interface{}{
			"capability_id": capabilityID,
			"args":          args,
		},
	})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(params),
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/mcp", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.signer != nil {
		if err := c.attachEnvelope(req, "tools/call", params); err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var rpc struct {
		Result *struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &rpc); err != nil {
		return nil, fmt.Errorf("decode response (%d): %s", resp.StatusCode, string(raw))
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("endpoint error: %s", rpc.Error.Message)
	}
	if rpc.Result == nil || len(rpc.Result.Content) == 0 {
		return nil, fmt.Errorf("empty result")
	}
	text := rpc.Result.Content[0].Text
	if rpc.Result.IsError {
		return &InvokeResult{Error: text}, fmt.Errorf("%s", text)
	}
	var out InvokeResult
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		// Not the wrapped shape — return the raw text as the body.
		return &InvokeResult{Status: resp.StatusCode, Body: json.RawMessage(text)}, nil
	}
	return &out, nil
}

// attachEnvelope signs the canonical request payload and sets the envelope headers.
func (c *Client) attachEnvelope(req *http.Request, method string, params []byte) error {
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(c.now().Unix(), 10)
	sig, err := c.signer.Sign([]byte(CanonicalPayload(method, params, nonce, ts)))
	if err != nil {
		return err
	}
	req.Header.Set("X-IA-Signature", sig)
	req.Header.Set("X-IA-Nonce", nonce)
	req.Header.Set("X-IA-Timestamp", ts)
	if aid := c.signer.AID(); aid != "" {
		req.Header.Set("X-IA-Signer-AID", aid)
	}
	return nil
}

// CanonicalPayload is the exact string signed for a request envelope: the method, a
// hex sha256 of the raw params bytes, the nonce, and the timestamp, newline-joined.
// It MUST match the endpoint's verifier byte-for-byte.
func CanonicalPayload(method string, params []byte, nonce, ts string) string {
	h := sha256.Sum256(params)
	return method + "\n" + hex.EncodeToString(h[:]) + "\n" + nonce + "\n" + ts
}

func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
