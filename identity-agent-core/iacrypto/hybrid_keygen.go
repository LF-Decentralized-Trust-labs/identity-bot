package iacrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/curve25519"
)

// Generating real key material for a hybrid identity.
//
// Until now nothing could. The synthetic path fills every field with a counting
// pattern, which is right for conformance vectors and useless for an identity.
// The Python driver's "generate" path says what it is in its own docstring —
// "placeholder PQC material (PQC bytes filled for structure)" — and fills the
// post-quantum fields with random bytes. Random bytes are not a public key:
// there is no private half, so nothing can ever sign with them, and an identity
// founded on one has a post-quantum key it can never use.
//
// So a hybrid identity has never actually been creatable. This makes it so,
// in-process, with no subprocess and no placeholder.

// HybridSecrets holds the private halves that HybridKeyMaterial does not.
//
// Kept separate from the public material on purpose: the material goes into an
// event that is published, and a struct that carried both would eventually have
// its secret half serialised by someone doing the obvious thing.
type HybridSecrets struct {
	// Ed25519Seed is the 32-byte seed, from which the private key is derived.
	Ed25519Seed []byte
	// MLDSA65Seed is the seed for the post-quantum signing key.
	MLDSA65Seed []byte
	// X25519Private and MLKEM768Decap are the key-agreement halves.
	X25519Private []byte
	MLKEM768Decap []byte
	// Next* are the pre-rotation secrets — the keys the identity has committed
	// to rotate to. These must be kept and must NOT be published: the whole
	// value of pre-rotation is that an attacker holding the current keys still
	// cannot produce a rotation.
	NextEd25519Seed []byte
	NextMLDSA65Seed []byte
}

// GenerateHybridKeyMaterial creates a real hybrid key set: classical and
// post-quantum, current and next.
//
// Returns the public material that goes into the inception event, and the
// secrets the caller must store. Losing the secrets loses the identity; losing
// only the Next* secrets loses the ability to ever rotate it.
func GenerateHybridKeyMaterial() (HybridKeyMaterial, HybridSecrets, error) {
	return generateHybridKeyMaterial(rand.Reader)
}

// generateHybridKeyMaterial takes its randomness as an argument so a test can
// be deterministic without the production path ever accepting a source that
// might not be random.
func generateHybridKeyMaterial(r io.Reader) (HybridKeyMaterial, HybridSecrets, error) {
	var m HybridKeyMaterial
	var s HybridSecrets

	// Classical signing, current and next.
	edPub, edSeed, err := newEd25519(r)
	if err != nil {
		return m, s, fmt.Errorf("classical signing key: %w", err)
	}
	nextEdPub, nextEdSeed, err := newEd25519(r)
	if err != nil {
		return m, s, fmt.Errorf("next classical signing key: %w", err)
	}

	// Post-quantum signing, current and next. Generated from a seed rather than
	// by the library's own keygen so the seed alone can reconstruct the key —
	// which is what makes the secret storable and the key recoverable.
	mldsaPub, mldsaSeed, err := newMLDSA65(r)
	if err != nil {
		return m, s, fmt.Errorf("post-quantum signing key: %w", err)
	}
	nextMLDSAPub, nextMLDSASeed, err := newMLDSA65(r)
	if err != nil {
		return m, s, fmt.Errorf("next post-quantum signing key: %w", err)
	}

	// Key agreement: classical and post-quantum, so a session key survives
	// either one being broken.
	x25519Pub, x25519Priv, err := newX25519(r)
	if err != nil {
		return m, s, fmt.Errorf("classical agreement key: %w", err)
	}
	kemPub, kemPriv, err := mlkem768.GenerateKeyPair(r)
	if err != nil {
		return m, s, fmt.Errorf("post-quantum agreement key: %w", err)
	}
	kemPubRaw, err := kemPub.MarshalBinary()
	if err != nil {
		return m, s, fmt.Errorf("post-quantum agreement key is not encodable: %w", err)
	}
	kemPrivRaw, err := kemPriv.MarshalBinary()
	if err != nil {
		return m, s, fmt.Errorf("post-quantum agreement secret is not encodable: %w", err)
	}

	m = HybridKeyMaterial{
		Ed25519SigningRaw:     edPub,
		MLDSA65SigningRaw:     mldsaPub,
		X25519AgreementRaw:    x25519Pub,
		MLKEM768EncapRaw:      kemPubRaw,
		NextEd25519SigningRaw: nextEdPub,
		NextMLDSA65SigningRaw: nextMLDSAPub,
	}
	s = HybridSecrets{
		Ed25519Seed:     edSeed,
		MLDSA65Seed:     mldsaSeed,
		X25519Private:   x25519Priv,
		MLKEM768Decap:   kemPrivRaw,
		NextEd25519Seed: nextEdSeed,
		NextMLDSA65Seed: nextMLDSASeed,
	}

	// Every field the event format declares a width for must be that width. A
	// key of the wrong length produces an event that encodes without complaint
	// and that no other implementation can read.
	if err := checkHybridWidths(m); err != nil {
		return HybridKeyMaterial{}, HybridSecrets{}, err
	}
	return m, s, nil
}

func newEd25519(r io.Reader) (pub, seed []byte, err error) {
	seed = make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), seed, nil
}

func newMLDSA65(r io.Reader) (pub, seed []byte, err error) {
	var s [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(r, s[:]); err != nil {
		return nil, nil, err
	}
	p, _ := mldsa65.NewKeyFromSeed(&s)
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return raw, s[:], nil
}

// newX25519 generates an agreement keypair.
//
// The private scalar is clamped the way X25519 requires. Skipping that produces
// a key that appears to work and is weaker than it looks.
func newX25519(r io.Reader) (pub, priv []byte, err error) {
	priv = make([]byte, X25519PubkeyBytes)
	if _, err := io.ReadFull(r, priv); err != nil {
		return nil, nil, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func checkHybridWidths(m HybridKeyMaterial) error {
	for _, f := range []struct {
		name string
		got  int
		want int
	}{
		{"Ed25519 signing key", len(m.Ed25519SigningRaw), Ed25519PubkeyBytes},
		{"ML-DSA-65 signing key", len(m.MLDSA65SigningRaw), MLDSA65VerkeyBytes},
		{"X25519 agreement key", len(m.X25519AgreementRaw), X25519PubkeyBytes},
		{"ML-KEM-768 encapsulation key", len(m.MLKEM768EncapRaw), MLKEM768EncapBytes},
		{"next Ed25519 signing key", len(m.NextEd25519SigningRaw), Ed25519PubkeyBytes},
		{"next ML-DSA-65 signing key", len(m.NextMLDSA65SigningRaw), MLDSA65VerkeyBytes},
	} {
		if f.got != f.want {
			return fmt.Errorf("%s is %d bytes, the format declares %d", f.name, f.got, f.want)
		}
	}
	return nil
}
