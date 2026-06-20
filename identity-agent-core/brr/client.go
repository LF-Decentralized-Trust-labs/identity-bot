package brr

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the IA-side BRR HTTP client (issuer push + verifier fetch).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	IssuerAID  string
	IssuerPub  ed25519.PublicKey
	IssuerPriv ed25519.PrivateKey
}

func NewClient(baseURL string, issuerPriv ed25519.PrivateKey) *Client {
	pub := issuerPriv.Public().(ed25519.PublicKey)
	aid := "E" + base64.RawURLEncoding.EncodeToString(pub)[:43]
	return &Client{
		BaseURL: baseURL, IssuerAID: aid,
		IssuerPub: pub, IssuerPriv: issuerPriv,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type EnrollRequest struct {
	RegistryPrefix  string `json:"registry_prefix"`
	IssuerAID       string `json:"issuer_aid"`
	IssuerPubKeyB64 string `json:"issuer_public_key_b64"`
	Signature       string `json:"signature"`
}

func (c *Client) Enroll(registryPrefix string) error {
	body := EnrollRequest{
		RegistryPrefix:  registryPrefix,
		IssuerAID:       c.IssuerAID,
		IssuerPubKeyB64: base64.StdEncoding.EncodeToString(c.IssuerPub),
	}
	canonical, _ := json.Marshal(map[string]string{
		"registry_prefix": body.RegistryPrefix,
		"issuer_aid":      body.IssuerAID,
		"issuer_public_key_b64": body.IssuerPubKeyB64,
	})
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.IssuerPriv, canonical))
	b, _ := json.Marshal(body)
	resp, err := c.HTTPClient.Post(c.BaseURL+"/registry/enroll", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enroll %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

type EventRequest struct {
	BlindedID      string `json:"blinded_id"`
	EventType      string `json:"event_type"`
	SequenceNumber int    `json:"sequence_number"`
	Signature      string `json:"signature"`
}

// PushBlindedEvent sends a blinded iss/rev event (issuer never sends plaintext SAID).
func (c *Client) PushBlindedEvent(registryPrefix, blindedID, eventType string, seq int) error {
	req := EventRequest{BlindedID: blindedID, EventType: eventType, SequenceNumber: seq}
	canonical, _ := json.Marshal(map[string]interface{}{
		"registry_prefix": registryPrefix,
		"blinded_id":      blindedID,
		"event_type":      eventType,
		"sequence_number": seq,
	})
	req.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.IssuerPriv, canonical))
	b, _ := json.Marshal(req)
	url := fmt.Sprintf("%s/registry/%s/event", trimSlash(c.BaseURL), registryPrefix)
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("event %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

type bulkProofResponse struct {
	Proof         BulkProof `json:"proof"`
	BRRSignature  string    `json:"brr_signature"`
	SignedBy      string    `json:"signed_by"`
}

// FetchBulkProof retrieves a herd-privacy subtree for local verification (C9 path).
func (c *Client) FetchBulkProof(registryPrefix, bucketHint string) (BulkProof, error) {
	url := fmt.Sprintf("%s/registry/%s/bulk-proof?bucket_hint=%s",
		trimSlash(c.BaseURL), registryPrefix, bucketHint)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return BulkProof{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return BulkProof{}, fmt.Errorf("bulk-proof %d: %s", resp.StatusCode, string(msg))
	}
	var out bulkProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return BulkProof{}, err
	}
	return out.Proof, nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}