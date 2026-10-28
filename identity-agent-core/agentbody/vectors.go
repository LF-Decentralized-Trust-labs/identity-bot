package agentbody

import (
	_ "embed"
	"encoding/json"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/fixedkeys"
)

// bodyVectors are the enrolment strings, the enrolment request, the strings a
// body signs, the six words and the grades, worked through from fixed inputs
// and fixed keys: the file another implementation of a body, or of the
// Identity Agent's side of one, tests itself against. It ships inside this
// module so a Go implementation reads the same file instead of keeping a copy.
//
//go:embed body-vectors.json
var bodyVectors []byte

// BodyVectorSet is the published set of body vectors.
type BodyVectorSet struct {
	About string `json:"about"`

	// The body's signing key K, an Ed25519 key from a fixed seed, so every
	// signature by it below is exactly reproducible.
	SeedHex string `json:"seed_hex"`
	Host    string `json:"host"`
	Verkey  string `json:"verkey"`

	// The body's sealing keys come from these seeds, and Keys is the whole of
	// its public key material, with the digest that binds the sealing keys to K.
	SealingSeeds fixedkeys.Seeds `json:"sealing_seeds"`
	Keys         Keys            `json:"keys"`
	KeysDigest   string          `json:"keys_digest"`

	// The Identity Agent the body enrols with: its identifier is the one the
	// enrolments name, and its messaging keys, from these seeds, are the keys
	// the enrolment is sealed to.
	IdentityAgentSeeds fixedkeys.Seeds `json:"identity_agent_seeds"`
	IdentityAgentKeys  didcomm.DID     `json:"identity_agent_keys"`

	Enrolments []struct {
		Name    string    `json:"name"`
		Fields  Enrolment `json:"fields"`
		Encoded string    `json:"encoded"`
	} `json:"enrolments"`
	RefusedEnrolments []struct {
		Name    string `json:"name"`
		Encoded string `json:"encoded"`
	} `json:"refused_enrolments"`

	// EnrolRequests answer the first enrolment: the string K signs, and the
	// request the machine sends, carrying K's signature over it.
	EnrolRequests []struct {
		Name         string       `json:"name"`
		Nonce        string       `json:"nonce"`
		ClaimedGrade string       `json:"claimed_grade"`
		Platform     string       `json:"platform"`
		Placement    string       `json:"placement"`
		Signed       string       `json:"signed"`
		Request      EnrolRequest `json:"request"`
	} `json:"enrol_requests"`

	// SealedEnrolment is the first enrol request as it is sent, sealed to the
	// Identity Agent from the body's sealing keys. Sealing draws fresh
	// randomness, so this one is given: it opens with the Identity Agent's
	// keys to a body-enrolment message whose id is the request's nonce and
	// whose body is the request.
	SealedEnrolment SealedEnrolment `json:"sealed_enrolment"`

	SignedRequests []struct {
		Name string `json:"name"`
		// The headers the request carries, and its body exactly as sent.
		Headers map[string]string `json:"headers"`
		Method  string            `json:"method"`
		Target  string            `json:"target"`
		Body    string            `json:"body"`
		Signed  string            `json:"signed"`
	} `json:"signed_requests"`

	// RefusedNonces are too short for an enrolment or a signed request.
	RefusedNonces []string `json:"refused_nonces"`

	Words []struct {
		Host  string   `json:"host"`
		Words []string `json:"words"`
	} `json:"words"`

	Grades []struct {
		Claimed string `json:"claimed"`
		Grade   string `json:"grade"`
		Clamped bool   `json:"clamped"`
	} `json:"grades"`

	// P256 is a body whose key is in secure hardware. ECDSA signatures are not
	// reproducible, so this one is given: it verifies, and the same signature
	// with s replaced by n-s, which ECDSA would also accept, is refused.
	P256 struct {
		Host             string `json:"host"`
		Verkey           string `json:"verkey"`
		Signed           string `json:"signed"`
		Signature        string `json:"signature"`
		RefusedSignature string `json:"refused_signature"`
	} `json:"p256"`
}

// BodyVectors returns the published body vectors.
func BodyVectors() (BodyVectorSet, error) {
	var v BodyVectorSet
	err := json.Unmarshal(bodyVectors, &v)
	return v, err
}
