package login

// SignChallengeForAsset signs the canonical challenge body Go-native with the asset's
// Ed25519 signing seed (re-derived by the caller from the controller root + the asset's
// SigningIndex) and attaches the qb64 signature to the bundle.
//
// Pointer receiver so the signature actually reaches the caller's bundle (the prior
// by-value version assigned to a copy and dropped the sig). Signing is local Go-native
// ed25519 — no Python driver round-trip (the driver holds no private keys by design,
// ADR-014). Mirrors how the per-user flow signs assertions (login/crypto.go signUTF8).
func SignChallengeForAsset(bundle *ChallengeBundle, seed []byte) error {
	body := canonicalChallengeBody(*bundle)
	sig, _, err := signUTF8(body, seed)
	if err != nil {
		return err
	}
	bundle.Sig = sig
	return nil
}
