package brr

import (
	"encoding/hex"

	"github.com/zeebo/blake3"
)

// BlindedID computes BLAKE3(credential_said || registry_salt).
// Must match blind-revocation-registry/internal/blind/blind.go exactly.
func BlindedID(credentialSAID, registrySalt string) string {
	h := blake3.Sum256(append([]byte(credentialSAID), []byte(registrySalt)...))
	return hex.EncodeToString(h[:])
}