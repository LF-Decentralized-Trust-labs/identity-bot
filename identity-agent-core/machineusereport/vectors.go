package machineusereport

import (
	_ "embed"
	"encoding/json"
)

//go:embed machine-usage-vectors.json
var vectors []byte

// VectorSet is the published set: a box key from a fixed seed, one report signed by it, and
// reports that must be refused, each with the reason. An implementation of the box or of a
// checker tests itself against the file; a Go one reads it from here instead of copying it.
type VectorSet struct {
	About        string `json:"about"`
	SeedHex      string `json:"seed_hex"`
	Identity     string `json:"identity"`
	PublicKeyHex string `json:"public_key_hex"`
	Nonce        string `json:"nonce"`
	Valid        Signed `json:"valid"`
	Refused      []struct {
		Why            string `json:"why"`
		ExpectIdentity string `json:"expect_identity,omitempty"`
		ExpectNonce    string `json:"expect_nonce,omitempty"`
		Report         Signed `json:"report"`
	} `json:"refused"`
}

// Vectors is the published vector set.
func Vectors() (VectorSet, error) {
	var v VectorSet
	err := json.Unmarshal(vectors, &v)
	return v, err
}
