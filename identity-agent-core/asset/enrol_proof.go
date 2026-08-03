package asset

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"identity-agent-core/login"
)

// Proving the enrolling machine holds the key it is presenting.
//
// Without this the token is the whole of the authentication — and a token
// authenticates whoever is holding the string, not a machine. Anyone who read
// it out of a terminal, a config file or a chat message could enrol ANY public
// key: one they generated themselves, or the published key of the machine the
// token was actually meant for. The delegated identity the owner then anchors
// in their own KEL would be over a key the owner never intended, and the KEL
// would say the owner meant it.
//
// The signature closes that. Enrolment now needs the token AND the private half
// of the key being enrolled. The token still matters, but on its own it is no
// longer enough.
//
// The token doubles as the nonce. It is single-use and time-bounded, so a
// captured signature cannot be replayed: the second attempt is refused for the
// token being spent, before the signature is looked at.

// enrolProofContext prefixes the signed bytes so a signature made for an
// enrolment can never be mistaken for one made anywhere else. Every signing
// surface here uses its own prefix for the same reason — without one, a
// signature harvested from another flow over coincidentally similar bytes would
// verify.
const enrolProofContext = "IA-ENROL-POP-V1"

// EnrolProofPayload is what an enrolling machine signs. Exported so the
// enrolling side can produce it without reimplementing the format — two
// independent spellings of the same canonical string is a bug waiting to
// happen, and it would present as an unexplainable signature mismatch.
//
// It covers the token and BOTH keys. Covering the next key matters as much as
// the current one: the next key is the pre-rotation commitment, so substituting
// it while leaving the current key alone would hand an attacker the only key
// that can ever succeed this identity.
func EnrolProofPayload(token, publicKey, nextPublicKey string) string {
	return strings.Join([]string{enrolProofContext, token, publicKey, nextPublicKey}, "\n")
}

// verifyEnrolProof checks that whoever sent this enrolment holds the private
// half of publicKey.
func verifyEnrolProof(token, publicKey, nextPublicKey, signature string) error {
	if strings.TrimSpace(signature) == "" {
		return fmt.Errorf("an enrolment must be signed by the key being enrolled")
	}
	pub, err := login.DecodeVerkey(publicKey)
	if err != nil {
		return fmt.Errorf("public_key: %w", err)
	}
	payload := EnrolProofPayload(token, publicKey, nextPublicKey)

	// CESR-qualified first, since that is what our own tooling emits.
	if ok, verr := login.VerifyString(payload, strings.TrimSpace(signature), pub); verr == nil {
		if ok {
			return nil
		}
		return errProofMismatch()
	}

	// Otherwise a bare 64-byte signature in whichever encoding the enrolling
	// machine reached for. A daemon written in Go, a shell script and our own
	// SDK do not naturally agree on an alphabet, and refusing over that would be
	// a protocol detail masquerading as a security check.
	raw, err := decodeEnrolSig(signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(payload), raw) {
		return errProofMismatch()
	}
	return nil
}

func errProofMismatch() error {
	return fmt.Errorf("the signature does not match the key being enrolled — this enrolment " +
		"did not come from the machine that generated that key")
}

func decodeEnrolSig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if raw, err := dec(s); err == nil && len(raw) == ed25519.SignatureSize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not a recognisable Ed25519 signature (want %d bytes, CESR-qualified, "+
		"base64 or hex)", ed25519.SignatureSize)
}
