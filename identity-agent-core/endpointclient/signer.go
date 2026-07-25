// Package endpointclient is a client for the Identity Agent's governed capability
// endpoint. It handles bearer-token authentication and, optionally, signed-request
// envelopes — signing each call so the endpoint can prove the caller signed THIS
// request (per-request authority), on top of the token.
//
// The presentation model: an Identity Agent provisions an AI agent (ProvisionAgent,
// a local-owner call) and hands back a bearer token; the agent then invokes
// capabilities with that token, optionally attaching a signed envelope. Who holds
// the signing key is a deployment choice — a Signer is an interface, so it can be a
// local key (LocalKeySigner) or a remote call to the Identity Agent that signs on
// the agent's behalf (the IA-mediated model).
package endpointclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"identity-agent-core/iacrypto"
)

// Signer produces a detached signature over the canonical request bytes, returned
// as a CESR "0B" qb64 string (the form the endpoint verifies). Implementations may
// sign locally or delegate to a remote signing service.
type Signer interface {
	// Sign returns the detached signature over payload as a CESR "0B" qb64 string.
	Sign(payload []byte) (sigQB64 string, err error)
	// AID is the signer's identifier (used as X-IA-Signer-AID). May be "" when the
	// caller's authenticated AID is used instead.
	AID() string
}

// LocalKeySigner signs with a local Ed25519 key. The seed is the agent's signing
// seed — in the IA-mediated model the Identity Agent derives it from the owner root
// seed and issues it to the agent as a session key; the agent's public key must be
// resolvable by the endpoint for the AID given.
type LocalKeySigner struct {
	priv ed25519.PrivateKey
	aid  string
}

// NewLocalKeySigner builds a signer from a 32-byte Ed25519 seed and the signer AID.
func NewLocalKeySigner(seed []byte, aid string) (*LocalKeySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &LocalKeySigner{priv: ed25519.NewKeyFromSeed(seed), aid: aid}, nil
}

// Sign implements Signer: an Ed25519 signature encoded as CESR "0B".
func (s *LocalKeySigner) Sign(payload []byte) (string, error) {
	sig := ed25519.Sign(s.priv, payload)
	return iacrypto.MatterFixedQB64("0B", sig)
}

// AID implements Signer.
func (s *LocalKeySigner) AID() string { return s.aid }

// PublicKeyB64 returns the signer's base64url Ed25519 public key — the value the
// endpoint must resolve for the signer AID to verify envelopes (e.g. registered via
// the agent's asset, or the pairwise-key registration path).
func (s *LocalKeySigner) PublicKeyB64() string {
	pub := s.priv.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(pub)
}
