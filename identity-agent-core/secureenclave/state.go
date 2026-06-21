package secureenclave

import "time"

const PayloadVersion = 1

// AttestationPayload is signed by the platform enclave key.
type AttestationPayload struct {
	Version    int               `json:"version"`
	Timestamp  string            `json:"timestamp"`
	Platform   string            `json:"platform"`
	Signer     string            `json:"signer"`
	Components map[string]string `json:"components"`
	ChainHash  string            `json:"chain_hash"`
}

// AttestationRecord is the persisted self-attestation artifact.
type AttestationRecord struct {
	Payload   AttestationPayload `json:"payload"`
	Signature string             `json:"signature"`
	PublicKey string             `json:"public_key"`
	SignedAt  time.Time          `json:"signed_at"`
}

// FreshnessAxis reports whether the enclave self-attestation is within cadence.
type FreshnessAxis struct {
	Status         string `json:"status"` // fresh | stale | failed | unknown
	LastAttestedAt string `json:"last_attested_at,omitempty"`
	NextDueAt      string `json:"next_due_at,omitempty"`
	CadenceHours   int    `json:"cadence_hours,omitempty"`
	Message        string `json:"message,omitempty"`
}

// EnclaveGenuinenessAxis reports hardware-backed chain attestation.
type EnclaveGenuinenessAxis struct {
	Status        string `json:"status"` // verified | mismatch | failed | unknown
	ChainHash     string `json:"chain_hash,omitempty"`
	SignedChain   string `json:"signed_chain_hash,omitempty"`
	SignerPlatform string `json:"signer_platform,omitempty"`
	Message       string `json:"message,omitempty"`
}