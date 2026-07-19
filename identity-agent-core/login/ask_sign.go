package login

import "encoding/json"

// Generic, transaction-type-agnostic Ask signing for the universal base layer. Unlike the
// login-specific canonicalChallengeBody/canonicalAssertionBody (fixed field lists), these
// operate on the raw Ask JSON, so they work for ANY action `t`. The signing primitive is the
// same proven Go-native Ed25519 (signUTF8/verifyUTF8) the login flow already uses — the
// signer is the asker's PAIRWISE key (or an org's public asset key), never the root key.

// CanonicalAskBody is the deterministic body signed/verified for an Ask: the JSON object with
// the "sig" field removed. Go's encoding/json marshals map keys in sorted order, so this is
// stable across encoders.
func CanonicalAskBody(askBytes []byte) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(askBytes, &m); err != nil {
		return nil, err
	}
	delete(m, "sig")
	return json.Marshal(m)
}

// SignAsk signs an Ask's canonical body with a 32-byte Ed25519 seed, returning the qb64 sig.
func SignAsk(askBytes []byte, seed []byte) (string, error) {
	body, err := CanonicalAskBody(askBytes)
	if err != nil {
		return "", err
	}
	sig, _, err := signUTF8(string(body), seed)
	return sig, err
}

// VerifyAsk verifies an Ask's qb64 signature against a raw Ed25519 public key.
func VerifyAsk(askBytes []byte, sig string, pub []byte) (bool, error) {
	body, err := CanonicalAskBody(askBytes)
	if err != nil {
		return false, err
	}
	return verifyUTF8(string(body), sig, pub)
}
