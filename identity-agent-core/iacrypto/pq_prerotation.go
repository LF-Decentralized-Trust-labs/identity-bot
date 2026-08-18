package iacrypto

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// mldsa65SeedBytes is the seed width ML-DSA-65 key generation consumes.
const mldsa65SeedBytes = mldsa65.SeedSize

// Committing a post-quantum key an identity cannot yet publish.
//
// An identity is founded with one classical signing key, because a post-quantum
// key cannot go in `k` yet: CESR has no assigned code for one, so any validator
// but ours fails to build its verifier set and rejects the identity outright.
//
// What CAN go in the founding event is a pre-rotation commitment to one. `n`
// holds DIGESTS, and a digest of a 1952-byte ML-DSA key is 44 characters like
// any other — the code question never arises, because nothing is encoded until
// the key is revealed at a rotation. So the identity commits to a post-quantum
// key on the day it is founded, stays readable by every KERI implementation,
// and reveals the key when the codes exist.
//
// This is the migration KERI's own strategy describes: keep post-quantum
// signatures out of key event logs for now, and swap the algorithms in at a
// later rotation. Without a commitment made at founding there is no later
// swap — pre-rotation binds an identity to the key set it committed to, and a
// key never committed can never be revealed.
//
// THE COMMITMENT IS A BET ON A CODE THAT IS NOT FINAL. The digest is taken over
// the key's qb64 text, which includes its CESR code, so it can only be computed
// against the code the key will eventually carry. `2AAE` below is what the
// specification's open pull request proposes. If the assigned code differs, the
// digest will not match the key we hold and this half of the commitment is
// spent. That is survivable and deliberately so — see the threshold note in the
// server's inception handler — but it is the reason this is a bet rather than a
// certainty.

// ProposedMLDSA65Verkey is the CESR code for an ML-DSA-65 public verification
// key, as proposed for the specification's next minor version.
//
// It is four characters in the `2` table because that is not a choice: the
// table follows from the raw size modulo 3, since the encoding has to land on a
// 24-bit boundary. 1952 mod 3 is 2, which needs one lead byte, which is what
// the `2` selector means. Encoding it in the `1` table instead produces a body
// that is not a whole number of base64 quadruples, and a conforming parser then
// mis-frames the value and loses its place in the rest of the stream.
const ProposedMLDSA65Verkey = "2AAE"

// MLDSA65VerkeyQB64 encodes an ML-DSA-65 public key as CESR.
//
// Deliberately not EncodeLargeFixed, which concatenates the code with raw
// base64 and omits lead bytes entirely. That is correct only when the raw size
// divides by 3 and silently malformed when it does not — which is the case
// here.
func MLDSA65VerkeyQB64(pub []byte) (string, error) {
	if len(pub) != MLDSA65VerkeyBytes {
		return "", fmt.Errorf("an ML-DSA-65 public key is %d bytes, got %d",
			MLDSA65VerkeyBytes, len(pub))
	}
	qb64, err := MatterFixedQB64(ProposedMLDSA65Verkey, pub)
	if err != nil {
		return "", err
	}
	// The specification states 2608 for this primitive. Checked rather than
	// trusted, because the failure it guards against is silent: a wrong width
	// still looks like a key, and only shows up as a rotation that can never
	// be verified.
	if len(qb64) != MLDSA65VerkeyQB64Chars {
		return "", fmt.Errorf("encoded ML-DSA-65 key is %d characters, expected %d",
			len(qb64), MLDSA65VerkeyQB64Chars)
	}
	return qb64, nil
}

// MLDSA65VerkeyQB64Chars is the encoded width of an ML-DSA-65 verification key:
// four code characters plus 2604 of body, from 1953 bytes once the lead byte is
// counted.
const MLDSA65VerkeyQB64Chars = 2608

// PostQuantumNextKey is a committed-but-unpublished post-quantum signing key.
type PostQuantumNextKey struct {
	// Digest is what goes in the founding event's `n`, alongside the classical
	// next key's digest.
	Digest string
	// Verkey is the qb64 the digest was taken over. Kept so a rotation can
	// prove it still reproduces the commitment before publishing anything.
	Verkey string
	// Seed is the private half. Losing it costs the post-quantum half of the
	// commitment; it does not cost the identity, which can still rotate on its
	// classical key.
	Seed []byte
}

// PostQuantumNextKeyFromSeed derives the post-quantum key an identity commits
// to at founding and reveals at a later rotation.
//
// Derived from the root seed rather than drawn at random, and from a fixed
// branch rather than an allocated one, because both are what make it survive a
// restore. A random key would live only in whatever file it was written to: an
// owner who rebuilt from their recovery phrase would hold an identity carrying
// a commitment they could no longer satisfy, and the post-quantum rotation
// would be gone with no way to tell from the outside. A fixed branch means the
// phrase alone is enough — nothing else has to be backed up or found again.
func PostQuantumNextKeyFromSeed(seed32 []byte) (PostQuantumNextKey, error) {
	if len(seed32) < mldsa65SeedBytes {
		return PostQuantumNextKey{}, fmt.Errorf(
			"deriving the post-quantum key needs %d bytes of seed, got %d",
			mldsa65SeedBytes, len(seed32))
	}
	pub, seed, err := newMLDSA65(bytes.NewReader(seed32[:mldsa65SeedBytes]))
	if err != nil {
		return PostQuantumNextKey{}, fmt.Errorf("could not derive the post-quantum key this identity commits to: %w", err)
	}
	verkey, err := MLDSA65VerkeyQB64(pub)
	if err != nil {
		return PostQuantumNextKey{}, err
	}
	// Digested over the qb64 TEXT, not the raw bytes, because that is what a
	// validator recomputes when the key is revealed. Digesting the raw bytes
	// would produce a commitment nothing could ever satisfy.
	digest, err := Blake3QB64([]byte(verkey))
	if err != nil {
		return PostQuantumNextKey{}, err
	}
	return PostQuantumNextKey{Digest: digest, Verkey: verkey, Seed: seed}, nil
}

// NextKeyDigest is the pre-rotation commitment to a classical next key.
//
// The digest is over the key's qb64 text. Passing raw key bytes here instead
// publishes the next public key with a digest prefix rather than committing to
// it, which reads correctly and cannot be rotated against by anything.
//
// The key is normalised first, and that is not cosmetic. Callers supply a next
// key either already CESR-encoded or as plain base64 of the raw bytes, and the
// engine accepts both — it normalises to canonical qb64 and commits to THAT. A
// commitment taken over the text as supplied therefore agrees with the engine
// for one of those two forms and silently disagrees for the other, producing an
// identity whose classical commitment no key can satisfy. Nothing detects it
// until somebody tries to rotate, which may be years later, and by then the
// event cannot be amended.
func NextKeyDigest(nextVerkey string) (string, error) {
	canonical, err := CanonicalVerkeyQB64(nextVerkey)
	if err != nil {
		return "", err
	}
	return Blake3QB64([]byte(canonical))
}

// CanonicalVerkeyQB64 puts an Ed25519 public key into the single form a
// pre-rotation commitment is taken over, accepting either form a caller may
// hold it in.
func CanonicalVerkeyQB64(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("a next key is required to commit to")
	}
	raw, err := rawEd25519From(key)
	if err != nil {
		return "", err
	}
	// Always the transferable code, matching what the engine does with either
	// input form. A non-transferable key normalises to the same commitment,
	// because what is committed to is the key, not how it arrived.
	return VerkeyQB64(raw), nil
}

func rawEd25519From(key string) ([]byte, error) {
	if len(key) > 1 && (key[0] == 'D' || key[0] == 'B') {
		raw, err := KeyFromVerkeyQB64(key)
		if err != nil {
			return nil, fmt.Errorf("could not read the next key: %w", err)
		}
		if len(raw) != Ed25519PubkeyBytes {
			return nil, fmt.Errorf("a next key is %d bytes, got %d", Ed25519PubkeyBytes, len(raw))
		}
		return raw, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("the next key is neither CESR-encoded nor base64: %w", err)
	}
	if len(raw) != Ed25519PubkeyBytes {
		return nil, fmt.Errorf("a next key is %d bytes, got %d", Ed25519PubkeyBytes, len(raw))
	}
	return raw, nil
}
