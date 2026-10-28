package agentmessage

import (
	_ "embed"
	"encoding/json"

	"identity-agent-core/didcomm"
)

// messageVectors are statements a body signs, worked through from fixed
// inputs and a fixed key, and a short conversation as the Identity Agent
// countersigned and chained it: the file another implementation of a body, or
// of a verifier of a conversation, tests itself against. It ships inside this
// module so a Go implementation reads the same file instead of keeping a copy.
//
//go:embed message-vectors.json
var messageVectors []byte

// MessageVectorSet is the published set of message vectors.
type MessageVectorSet struct {
	About string `json:"about"`

	// The body's Ed25519 machine key, from a fixed seed, so every statement
	// signature below is exactly reproducible.
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

	// Conversation is entries countersigned by the AI agent each is from,
	// whose messaging keys are Countersigner. Each entry's record names the
	// hash of the one before it. Countersignatures use ML-DSA, which is not
	// reproducible, so the envelopes are given; their records and hashes are
	// derived from them.
	Countersigner didcomm.DID `json:"countersigner"`
	Conversation  []struct {
		Envelope *didcomm.Envelope `json:"envelope"`
		Record   Record            `json:"record"`
		Hash     string            `json:"hash"`
	} `json:"conversation"`
}

// MessageVectors returns the published message vectors.
func MessageVectors() (MessageVectorSet, error) {
	var v MessageVectorSet
	err := json.Unmarshal(messageVectors, &v)
	return v, err
}
