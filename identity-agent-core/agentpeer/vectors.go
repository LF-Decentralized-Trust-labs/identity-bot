package agentpeer

import (
	_ "embed"
	"encoding/json"
)

// peerVectors are messages worked through from fixed keys: the exchange message
// an Identity Agent signs (the whole signed message, byte for byte), the salt and
// fingerprint of its words, both signatures, the keys that checked them, and
// the messages that must be refused, each with a stable code and the key it
// would have to be checked against. It is the file another implementation tests
// itself against; it ships inside this module so a Go implementation reads the
// same file instead of keeping a copy.
//
//go:embed peer-vectors.json
var peerVectors []byte

// VectorSet is the published set.
type VectorSet struct {
	About string `json:"about"`
	// Keys are the two Identity Agents' messaging keys, from published seeds:
	// Ed25519 from its 32-byte seed (RFC 8032) and ML-DSA-65 from its 32-byte
	// seed (FIPS 204). Each Identity Agent's identifier is the identifier its
	// contacts know it by; its key log vouches for these keys (ADR-085).
	Keys    map[string]VectorKeys `json:"keys"`
	Signed  []SignedCase          `json:"signed"`
	Refused []RefusedCase         `json:"refused"`
	// Directories are a contact's offered AI agents: ones a receiver keeps, and
	// ones it refuses because they cannot be shown as they stand (Directory.Check).
	Directories []DirectoryCase `json:"directories"`
	// Grants are what an AI agent's grant lets it message (CheckPeerGrant).
	Grants []GrantCase `json:"grants"`
}

// VectorKeys is one Identity Agent's identifier and messaging keys.
type VectorKeys struct {
	AID        string `json:"aid"`
	EdSeedHex  string `json:"ed25519_seed_hex"`
	EdPublic   string `json:"ed25519_public_b64url"`
	DsaSeedHex string `json:"mldsa65_seed_hex"`
	DsaPublic  string `json:"mldsa65_public_b64url"`
	// SenderIdentifier is the Ed25519 key as a non-transferable identifier (CESR
	// code B), which is the `i` of every exchange message the Identity Agent sends.
	SenderIdentifier string `json:"sender_identifier"`
}

// SignedCase is one message that must be taken: the statement it says, the
// words and salt, and the exact signed message.
type SignedCase struct {
	Name string `json:"name"`
	// From names the signing Identity Agent in Keys, and To the receiver.
	From      string    `json:"from"`
	To        string    `json:"to"`
	Statement Statement `json:"statement"`
	Words     string    `json:"words"`
	// Salt is the fingerprint's salt in unpadded base64url.
	Salt string `json:"salt"`
	// Said is the exchange message's identifier (`d`).
	Said string `json:"said"`
	// Raw is the exchange message exactly, which both signatures cover (the
	// ML-DSA one with the domain tag in front).
	Raw string `json:"exchange_message"`
	// Exn is the signed message: Raw followed by one non-transferable couple of
	// the sender and its Ed25519 signature, as keripy reads it.
	Exn   string `json:"exn"`
	PQSig string `json:"pq_sig"`
	// Now is the receiver's clock when it takes the message.
	Now string `json:"now"`
}

// RefusedCase is one message that must be refused, and why.
type RefusedCase struct {
	Name string `json:"name"`
	// Signer names whose keys it is checked against, SentBy who the envelope
	// said sent it, Self who is taking it.
	Signer  string  `json:"signer"`
	SentBy  string  `json:"sent_by"`
	Self    string  `json:"self"`
	Now     string  `json:"now"`
	Message Message `json:"message"`
	// Code is the refusal's stable name, and Refuse its text (not to be matched).
	Code   string `json:"code"`
	Refuse string `json:"refuse"`
}

// DirectoryCase is one directory, and the refusal's text when it must be refused.
type DirectoryCase struct {
	Name      string    `json:"name"`
	Directory Directory `json:"directory"`
	// Refuse is the refusal's text, empty for a directory that is kept.
	Refuse string `json:"refuse,omitempty"`
}

// GrantCase is one grant's limits, the contact and AI agent asked for, and
// whether the grant lets it.
type GrantCase struct {
	Name    string                 `json:"name"`
	Limits  map[string]interface{} `json:"limits"`
	Contact string                 `json:"contact"`
	Agent   string                 `json:"agent"`
	Allow   bool                   `json:"allow"`
}

// Vectors is the published set, read from the embedded file.
func Vectors() (VectorSet, error) {
	var v VectorSet
	err := json.Unmarshal(peerVectors, &v)
	return v, err
}
