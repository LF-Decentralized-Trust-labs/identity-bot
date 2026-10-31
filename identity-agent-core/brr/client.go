package brr

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// Client is the IA-side BRR HTTP client (issuer push + verifier fetch).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	IssuerAID  string
	IssuerPub  ed25519.PublicKey
	IssuerPriv ed25519.PrivateKey
}

// NewClient is a client for the registry at baseURL, enrolling and pushing as
// the issuer issuerAID, whose current signing key is issuerPriv.
//
// The identifier is given, never made from the key. An issuer's identifier is
// the prefix of its key log, which names its first key but is not that key
// spelled differently, and after a rotation names a different key altogether.
// A string built from the key alone looks like an identifier and belongs to
// nobody, so the registry would hold the issuer's events under a name no key
// log answers to. So issuerAID must be an identifier in canonical qb64.
//
// That check does not tell the old key-derived strings apart: "E" and 43
// characters of a key's base64url pass it whenever the key's first byte is
// below 64, so that the character after the E has its two lead bits zero:
// about one time in four. What makes the issuer
// real is that the registry checks its key event log derives it (Enroll).
func NewClient(baseURL, issuerAID string, issuerPriv ed25519.PrivateKey) (*Client, error) {
	if !iacrypto.IsIdentifierQB64(issuerAID) {
		return nil, fmt.Errorf("the issuer %q is not an identifier in qb64", issuerAID)
	}
	if len(issuerPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the issuer's signing key is not an Ed25519 private key")
	}
	return &Client{
		BaseURL: baseURL, IssuerAID: issuerAID,
		IssuerPub: issuerPriv.Public().(ed25519.PublicKey), IssuerPriv: issuerPriv,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// EnrollRequest is the revocation registry's enrolment: the issuer proves
// both that the registry is its own and that the key it signs with is its
// current one, because whoever holds a registry's enrolled key can revoke
// every credential in it.
type EnrollRequest struct {
	RegistryPrefix  string `json:"registry_prefix"`
	IssuerAID       string `json:"issuer_aid"`
	IssuerPubKeyB64 string `json:"issuer_public_key_b64"`
	// KEL is the issuer's signed key event log, a CESR stream in unpadded
	// base64url. It must derive IssuerAID and name IssuerPubKeyB64 as the
	// current signing key.
	KEL string `json:"kel"`
	// RegistryInception is the registry's inception event (vcp) in unpadded
	// base64url. It must digest to RegistryPrefix and name IssuerAID as the
	// registry's issuer.
	RegistryInception string `json:"registry_inception"`
	Signature         string `json:"signature"`
}

// ErrRefused is a refusal by the registry to enrol, answered with 409: the
// registry is enrolled to another issuer, the key event log presented forks
// from the one it holds, or it holds a newer log naming a different key.
// Sending the same enrolment again does not change the answer; the issuer has
// to present its current log.
var ErrRefused = errors.New("the registry refused the enrolment")

// Enroll enrols the registry that registryInception founds, as this client's
// issuer, and returns the registry's prefix.
//
// kel is the issuer's signed key event log as a CESR stream, the bytes a KERI
// engine exports, and registryInception the registry's inception event (vcp)
// as its raw bytes. Both are signed with the rest of the enrolment. The prefix
// is read from the inception, so the two cannot disagree. The log is checked
// here first, with the rule the registry applies (relayproto.CurrentKey), so an
// issuer holding a key its log has rotated away from learns that without a
// round trip; whether the registry is the issuer's is the registry's to judge.
func (c *Client) Enroll(kel, registryInception []byte) (string, error) {
	current, err := relayproto.CurrentKey(c.IssuerAID, kel)
	if err != nil {
		return "", fmt.Errorf("the issuer's key event log: %w", err)
	}
	if !current.Equal(c.IssuerPub) {
		return "", fmt.Errorf("the issuer's key event log names a different current key than the one this client signs with")
	}
	ev, err := keri.VerifyTELEvent(registryInception)
	if err != nil {
		return "", fmt.Errorf("the registry inception: %w", err)
	}
	if ev.Ilk != "vcp" {
		return "", fmt.Errorf("a %s event is not a registry inception", ev.Ilk)
	}
	body := EnrollRequest{
		RegistryPrefix:    ev.SAID,
		IssuerAID:         c.IssuerAID,
		IssuerPubKeyB64:   base64.StdEncoding.EncodeToString(c.IssuerPub),
		KEL:               base64.RawURLEncoding.EncodeToString(kel),
		RegistryInception: base64.RawURLEncoding.EncodeToString(registryInception),
	}
	canonical, err := EnrollCanonical(body)
	if err != nil {
		return "", err
	}
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.IssuerPriv, canonical))
	b, _ := json.Marshal(body)
	resp, err := c.HTTPClient.Post(trimSlash(c.BaseURL)+"/registry/enroll", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusConflict:
		return "", fmt.Errorf("%w: %s", ErrRefused, msg)
	case resp.StatusCode >= 300:
		return "", fmt.Errorf("enroll %d: %s", resp.StatusCode, msg)
	}
	return ev.SAID, nil
}

// EnrollCanonical is the bytes an enrolment is signed over: every field but
// the signature, in the one form every service-provider request is signed in
// (relayproto.CanonicalBody).
func EnrollCanonical(req EnrollRequest) ([]byte, error) {
	return relayproto.CanonicalBody(map[string]any{
		"registry_prefix":       req.RegistryPrefix,
		"issuer_aid":            req.IssuerAID,
		"issuer_public_key_b64": req.IssuerPubKeyB64,
		"kel":                   req.KEL,
		"registry_inception":    req.RegistryInception,
	})
}

type EventRequest struct {
	BlindedID string `json:"blinded_id"`
	EventType string `json:"event_type"`
	// SequenceNumber is a decimal string: every signed field is a string
	// (ADR-049).
	SequenceNumber string `json:"sequence_number"`
	Signature      string `json:"signature"`
}

// PushBlindedEvent sends a blinded iss/rev event (issuer never sends plaintext SAID).
func (c *Client) PushBlindedEvent(registryPrefix, blindedID, eventType string, seq int) error {
	req := EventRequest{BlindedID: blindedID, EventType: eventType, SequenceNumber: strconv.Itoa(seq)}
	// The registry prefix travels in the path, and is signed with the body so
	// an event cannot be replayed into another registry.
	canonical, err := relayproto.CanonicalBody(map[string]any{
		"registry_prefix": registryPrefix,
		"blinded_id":      blindedID,
		"event_type":      eventType,
		"sequence_number": req.SequenceNumber,
	})
	if err != nil {
		return err
	}
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
	Proof        BulkProof `json:"proof"`
	BRRSignature string    `json:"brr_signature"`
	SignedBy     string    `json:"signed_by"`
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
