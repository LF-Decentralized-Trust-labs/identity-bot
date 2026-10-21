package relayproto

import (
	_ "embed"
	"encoding/json"
)

// signingVectors are the bytes CanonicalBody produces for a set of requests,
// and an Ed25519 signature over each from a fixed key: the file another
// implementation, in any language, tests itself against. It ships inside this
// module so a Go implementation reads the same file instead of keeping a copy.
//
//go:embed signing-vectors.json
var signingVectors []byte

// SigningVectorSet is the published set of signing vectors.
type SigningVectorSet struct {
	SeedHex   string `json:"seed_hex"`
	PublicKey string `json:"public_key"`
	Vectors   []struct {
		Name      string            `json:"name"`
		Fields    map[string]string `json:"fields"`
		Canonical string            `json:"canonical"`
		Signature string            `json:"signature"`
	} `json:"vectors"`
	Refused []struct {
		Name   string         `json:"name"`
		Fields map[string]any `json:"fields"`
	} `json:"refused"`
}

// SigningVectors returns the published signing vectors.
func SigningVectors() (SigningVectorSet, error) {
	var v SigningVectorSet
	err := json.Unmarshal(signingVectors, &v)
	return v, err
}
