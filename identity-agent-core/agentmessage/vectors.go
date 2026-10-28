package agentmessage

import (
	_ "embed"
	"encoding/json"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/fixedkeys"
)

// messageVectors are statements a body signs, and a short conversation as the
// Identity Agent countersigned and chained it, worked through from fixed
// inputs and fixed keys: the file another implementation of a body, or of a
// verifier of a conversation, tests itself against. It ships inside this
// module so a Go implementation reads the same file instead of keeping a copy.
//
//go:embed message-vectors.json
var messageVectors []byte

// MessageVectorSet is the published set of message vectors.
type MessageVectorSet struct {
	About string `json:"about"`

	// The body's Ed25519 machine key, from a fixed seed.
	SeedHex string `json:"seed_hex"`
	Host    string `json:"host"`
	Verkey  string `json:"verkey"`

	Statements []struct {
		Name      string    `json:"name"`
		Statement Statement `json:"statement"`
		// Body is the words; BodyHash in the statement is their digest.
		Body      string `json:"body"`
		Signed    string `json:"signed"`
		Signature string `json:"signature"`
	} `json:"statements"`
	RefusedStatements []struct {
		Name      string    `json:"name"`
		Statement Statement `json:"statement"`
	} `json:"refused_statements"`

	// Countersigner is the messaging keys, from these seeds, of the AI agent
	// every entry below is from, which countersigns them.
	CountersignerSeeds fixedkeys.Seeds `json:"countersigner_seeds"`
	Countersigner      didcomm.DID     `json:"countersigner"`

	// Conversation is entries in order. Every value is reproducible: the
	// body's statement and signature, the record, the countersigned envelope
	// (Ed25519 and ML-DSA-65 both sign deterministically) and the hash each
	// entry is chained by.
	Conversation []struct {
		Body     string            `json:"body"`
		Record   Record            `json:"record"`
		Envelope *didcomm.Envelope `json:"envelope"`
		Hash     string            `json:"hash"`
	} `json:"conversation"`

	// RefusedEntries are countersigned by the right keys and still refused.
	RefusedEntries []struct {
		Name     string            `json:"name"`
		Envelope *didcomm.Envelope `json:"envelope"`
	} `json:"refused_entries"`
}

// MessageVectors returns the published message vectors.
func MessageVectors() (MessageVectorSet, error) {
	var v MessageVectorSet
	err := json.Unmarshal(messageVectors, &v)
	return v, err
}
