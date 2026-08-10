package iacrypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	keri "github.com/grapeid/keri-go"
)

// Keeping a hybrid identity's secrets, so it can sign after a restart.
//
// Generating real post-quantum keys is only half of it. A hybrid identity that
// cannot persist its secrets is an identity that can be founded and never used,
// and its pre-rotation commitment is a promise it cannot keep — the next keys
// exist only in the memory of the process that made them.
//
// The secrets live in the KERI package's store rather than a store of our own.
// That store already solves encryption at rest, refusing to overwrite, file
// permissions and flushing to disk before reporting success; a second store here
// would be a second chance to get each of those wrong. It holds bytes and has no
// opinion about what they are, which is exactly the arrangement needed for
// material it does not implement.

// hybridSecretNames are the fixed slots a hybrid identity occupies in a store.
//
// Deriving them from a label rather than letting callers choose keeps two
// identities from colliding, and keeps a caller from storing the next key under
// a name that reads like the current one.
func hybridSecretNames(label string) map[string]string {
	return map[string]string{
		"ed25519":     label + "/hybrid/ed25519",
		"mldsa65":     label + "/hybrid/mldsa65",
		"x25519":      label + "/hybrid/x25519",
		"mlkem768":    label + "/hybrid/mlkem768",
		"nextEd25519": label + "/hybrid/next/ed25519",
		"nextMLDSA65": label + "/hybrid/next/mldsa65",
	}
}

// StoreHybridSecrets persists a hybrid identity's private material.
//
// Every secret is written or none is. A partial write leaves an identity that
// can sign with one algorithm and not the other, or that has lost only its
// pre-rotation keys — the second being the failure that cannot be recovered
// from, because the commitment is already published.
func StoreHybridSecrets(store keri.SecretStore, label string, s HybridSecrets) error {
	if store == nil {
		return fmt.Errorf("no store was supplied; a hybrid identity whose secrets are " +
			"not persisted cannot sign after a restart and cannot ever rotate")
	}
	if label == "" {
		return fmt.Errorf("a hybrid identity needs a label to store its secrets under")
	}
	names := hybridSecretNames(label)
	values := map[string][]byte{
		"ed25519":     s.Ed25519Seed,
		"mldsa65":     s.MLDSA65Seed,
		"x25519":      s.X25519Private,
		"mlkem768":    s.MLKEM768Decap,
		"nextEd25519": s.NextEd25519Seed,
		"nextMLDSA65": s.NextMLDSA65Seed,
	}
	// Check everything is present before writing anything. The store refuses to
	// overwrite, so a half-written identity cannot be repaired by trying again.
	for slot, v := range values {
		if len(v) == 0 {
			return fmt.Errorf("the %s secret is missing; refusing to store a partial "+
				"identity that could not be completed later", slot)
		}
	}
	for slot, v := range values {
		if err := store.PutSecret(names[slot], v); err != nil {
			return fmt.Errorf("storing the %s secret: %w", slot, err)
		}
	}
	return nil
}

// LoadHybridSecrets recovers a hybrid identity's private material.
func LoadHybridSecrets(store keri.SecretStore, label string) (HybridSecrets, error) {
	var out HybridSecrets
	if store == nil || label == "" {
		return out, fmt.Errorf("a store and a label are needed to find an identity's secrets")
	}
	names := hybridSecretNames(label)
	read := func(slot string) ([]byte, error) {
		v, err := store.Secret(names[slot])
		if err != nil {
			return nil, fmt.Errorf("the %s secret is not in the store: %w", slot, err)
		}
		return v, nil
	}
	var err error
	if out.Ed25519Seed, err = read("ed25519"); err != nil {
		return HybridSecrets{}, err
	}
	if out.MLDSA65Seed, err = read("mldsa65"); err != nil {
		return HybridSecrets{}, err
	}
	if out.X25519Private, err = read("x25519"); err != nil {
		return HybridSecrets{}, err
	}
	if out.MLKEM768Decap, err = read("mlkem768"); err != nil {
		return HybridSecrets{}, err
	}
	// The pre-rotation secrets are read last and their absence is reported for
	// what it is: an identity that can still sign and can never rotate.
	if out.NextEd25519Seed, err = read("nextEd25519"); err != nil {
		return HybridSecrets{}, fmt.Errorf("%w — this identity has published a commitment "+
			"it can no longer satisfy, so it can never rotate", err)
	}
	if out.NextMLDSA65Seed, err = read("nextMLDSA65"); err != nil {
		return HybridSecrets{}, fmt.Errorf("%w — this identity has published a commitment "+
			"it can no longer satisfy, so it can never rotate", err)
	}
	return out, nil
}

// SignHybrid produces a composite signature over a message with a stored
// identity's current keys.
//
// Both halves are produced and both must later verify. A caller receiving only
// one half would have a signature that a classical verifier accepts and that
// offers no post-quantum protection at all, which is the outcome the whole
// cipher suite exists to avoid.
func SignHybrid(s HybridSecrets, message []byte) (string, error) {
	if len(message) == 0 {
		return "", fmt.Errorf("refusing to sign an empty message")
	}
	if len(s.Ed25519Seed) != ed25519.SeedSize {
		return "", fmt.Errorf("the classical seed is %d bytes, expected %d",
			len(s.Ed25519Seed), ed25519.SeedSize)
	}
	if len(s.MLDSA65Seed) != mldsa65.SeedSize {
		return "", fmt.Errorf("the post-quantum seed is %d bytes, expected %d",
			len(s.MLDSA65Seed), mldsa65.SeedSize)
	}

	edSig := ed25519.Sign(ed25519.NewKeyFromSeed(s.Ed25519Seed), message)
	edWire, err := MatterIndexedSigQB64("B", 0, edSig, 88)
	if err != nil {
		return "", fmt.Errorf("encoding the classical signature: %w", err)
	}

	var seed [mldsa65.SeedSize]byte
	copy(seed[:], s.MLDSA65Seed)
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	pqSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, message, nil, false, pqSig); err != nil {
		return "", fmt.Errorf("signing with the post-quantum key: %w", err)
	}
	pqWire, err := EncodeIndexedMLDSASig(0, pqSig)
	if err != nil {
		return "", fmt.Errorf("encoding the post-quantum signature: %w", err)
	}

	return composeHybridSignature(edWire, pqWire), nil
}
