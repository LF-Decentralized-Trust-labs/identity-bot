package login

import (
	"crypto/ed25519"
	"fmt"

	"identity-agent-core/iacrypto"
)

func ed25519SigQB64(sig []byte) (string, error) {
	return iacrypto.MatterFixedQB64("0B", sig)
}

func ed25519VerkeyQB64(pub []byte) (string, error) {
	return iacrypto.MatterFixedQB64("D", pub)
}

func signUTF8(body string, seed []byte) (string, []byte, error) {
	if len(seed) != ed25519.SeedSize {
		return "", nil, fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(body))
	sigQB64, err := ed25519SigQB64(sig)
	if err != nil {
		return "", nil, err
	}
	return sigQB64, priv.Public().(ed25519.PublicKey), nil
}

// VerifyDetachedSig verifies a detached Ed25519 signature (CESR "0B" code) over
// body using the given raw public key. Exported for reuse by callers outside the
// login package (e.g. signed-request-envelope verification at the endpoint).
func VerifyDetachedSig(body, sigQB64 string, pub []byte) (bool, error) {
	return verifyUTF8(body, sigQB64, pub)
}

func verifyUTF8(body, sigQB64 string, pub []byte) (bool, error) {
	if !hasPrefix(sigQB64, "0B") {
		return false, fmt.Errorf("expected Ed25519 sig code 0B")
	}
	raw, err := iacrypto.DecodeEd25519SignatureQB64(sigQB64)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, []byte(body), raw), nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
