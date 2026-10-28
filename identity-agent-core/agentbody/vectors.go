package agentbody

import (
	_ "embed"
	"encoding/json"
)

// bodyVectors are the enrolment strings, the strings a body signs, the six
// words and the grades, worked through from fixed inputs and fixed keys: the
// file another implementation of a body, or of the Identity Agent's side of
// one, tests itself against. It ships inside this module so a Go
// implementation reads the same file instead of keeping a copy.
//
//go:embed body-vectors.json
var bodyVectors []byte

// BodyVectorSet is the published set of body vectors.
type BodyVectorSet struct {
	About string `json:"about"`

	// An Ed25519 machine key from a fixed seed, so every signature below is
	// exactly reproducible.
	SeedHex string `json:"seed_hex"`
	Host    string `json:"host"`
	Verkey  string `json:"verkey"`

	// The body's public keys, and the digest that binds its sealing keys to
	// its signing key. The sealing keys are opaque to the digest: it covers
	// the strings as given.
	Keys       Keys   `json:"keys"`
	KeysDigest string `json:"keys_digest"`

	Enrolments []struct {
		Name    string    `json:"name"`
		Fields  Enrolment `json:"fields"`
		Encoded string    `json:"encoded"`
	} `json:"enrolments"`
	RefusedEnrolments []struct {
		Name    string `json:"name"`
		Encoded string `json:"encoded"`
	} `json:"refused_enrolments"`

	// EnrolProofs are made over the first enrolment and Keys.
	EnrolProofs []struct {
		Name         string `json:"name"`
		Nonce        string `json:"nonce"`
		ClaimedGrade string `json:"claimed_grade"`
		Platform     string `json:"platform"`
		Placement    string `json:"placement"`
		Signed       string `json:"signed"`
		Signature    string `json:"signature"`
	} `json:"enrol_proofs"`

	SignedRequests []struct {
		Name string `json:"name"`
		// The headers the request carries, and its body exactly as sent.
		Headers map[string]string `json:"headers"`
		Method  string            `json:"method"`
		Target  string            `json:"target"`
		Body    string            `json:"body"`
		Signed  string            `json:"signed"`
	} `json:"signed_requests"`

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
