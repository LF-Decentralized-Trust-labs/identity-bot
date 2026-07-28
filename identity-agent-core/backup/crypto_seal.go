package backup

// Sealing a backup key to a public key, so the machine making the backup never
// needs the secret that recovers it.
//
// Every other slot type here derives its key-encryption key from something the
// owner knows or holds: the seed phrase, a passphrase, a guardian group. That
// works, but it forces the owner to hand that secret to whatever is doing the
// backing up — and when the thing doing the backing up is a rented computer in
// somebody else's building, handing it the seed phrase gives away the identity
// itself, permanently and irrevocably. A backup should not cost more than what
// it protects.
//
// So the direction is reversed. The owner's device publishes a public key once.
// The machine generates a random backup key, seals it to that public key, and
// keeps nothing. It can write backups forever and can never read one back. The
// seed phrase still recovers everything, because the private half is derived
// from the same seed the phrase produces — it simply never leaves the owner.
//
// Two properties are worth being explicit about, because they are the reason
// this shape was chosen over a shared secret:
//
// The archive carries no hint of who a slot is for. An archive sealed to
// several owners is a list of anonymous slots, and opening it means trying
// each one. Naming the recipients would publish an organisation's ownership to
// anyone holding a copy of its backup, which is exactly the wrong place for
// that to leak. Trying a handful of slots costs nothing.
//
// One slot per recipient, any of which opens the archive. For an organisation
// that means every owner can restore the company's data alone. That is
// deliberate: they are already entitled to the data, and requiring a quorum to
// read it would only add a way to lose it. Acting *as* the organisation is a
// different question, answered by the signing threshold, not by this file.

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// SealSaltV1 and SealInfoV1 domain-separate the sealing keypair from the
	// backup KEK and the vault KEK, which are derived from the same seed.
	SealSaltV1 = "identity-agent-backup-seal-salt-v1"
	SealInfoV1 = "identity-agent-backup-seal-v1"

	// SealSharedInfoV1 labels the HKDF that turns a Diffie-Hellman result into
	// the key that actually wraps the backup key.
	SealSharedInfoV1 = "identity-agent-backup-seal-shared-v1"

	// X25519KeyLen is the length of both halves of an X25519 keypair.
	X25519KeyLen = 32
)

// DeriveSealKeypair derives the X25519 keypair used to seal backup keys to an
// owner, from the same BIP39 seed their phrase produces.
//
// Derived rather than random so that recovery needs nothing but the phrase. A
// randomly generated sealing key would be one more thing to back up, and a
// backup key that has to be backed up is not a solution.
//
// It is deliberately NOT the identity's signing key. Reusing a signing key for
// encryption is a well-known way to weaken both, and here it would also mean
// that rotating the identity's keys silently broke every existing archive.
func DeriveSealKeypair(bip39Seed []byte) (private, public []byte, err error) {
	if len(bip39Seed) < 32 {
		return nil, nil, fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	r := hkdf.New(sha256.New, bip39Seed, []byte(SealSaltV1), []byte(SealInfoV1))
	priv := make([]byte, X25519KeyLen)
	if _, err := r.Read(priv); err != nil {
		return nil, nil, fmt.Errorf("hkdf seal key: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive seal public key: %w", err)
	}
	return priv, pub, nil
}

// DeriveSealPublicKey returns only the public half — what an agent is given so
// it can write backups it cannot read.
func DeriveSealPublicKey(bip39Seed []byte) ([]byte, error) {
	_, pub, err := DeriveSealKeypair(bip39Seed)
	return pub, err
}

// sealSharedKEK turns an X25519 shared secret into a wrapping key.
//
// Both public keys are mixed into the derivation, not just the shared secret.
// Without that, the same wrapping key could be reached by more than one pairing
// of keys, and slots would stop being bound to the exchange that produced them.
func sealSharedKEK(shared, ephemeralPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephemeralPub)+len(recipientPub))
	salt = append(salt, ephemeralPub...)
	salt = append(salt, recipientPub...)

	r := hkdf.New(sha256.New, shared, salt, []byte(SealSharedInfoV1))
	kek := make([]byte, 32)
	if _, err := r.Read(kek); err != nil {
		return nil, fmt.Errorf("hkdf seal shared: %w", err)
	}
	return kek, nil
}

// SealBEK seals a backup key to a recipient's public key.
//
// The ephemeral keypair is generated per slot and its private half is dropped
// immediately. That is what stops the machine reopening its own archives: after
// this returns, nothing on it can reconstruct the shared secret.
func SealBEK(recipientPub, bek []byte) (ephemeralPub, wrapped, nonce []byte, err error) {
	if len(recipientPub) != X25519KeyLen {
		return nil, nil, nil, fmt.Errorf("recipient public key must be %d bytes, got %d", X25519KeyLen, len(recipientPub))
	}
	if len(bek) != BEKLen {
		return nil, nil, nil, fmt.Errorf("bek must be %d bytes", BEKLen)
	}

	ephPriv, err := randomBytes(X25519KeyLen)
	if err != nil {
		return nil, nil, nil, err
	}
	ephemeralPub, err = curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ephemeral public key: %w", err)
	}

	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		// X25519 rejects low-order points, which is the case worth catching:
		// a public key chosen to force a predictable shared secret.
		return nil, nil, nil, fmt.Errorf("seal to recipient: %w", err)
	}

	kek, err := sealSharedKEK(shared, ephemeralPub, recipientPub)
	if err != nil {
		return nil, nil, nil, err
	}
	wrapped, nonce, err = WrapBEK(kek, bek)
	if err != nil {
		return nil, nil, nil, err
	}
	return ephemeralPub, wrapped, nonce, nil
}

// UnsealBEK recovers a backup key from a sealed slot.
//
// A wrong private key fails here rather than producing garbage, because the
// wrap is authenticated. That is what makes trying every slot in turn a safe
// way to find the right one.
func UnsealBEK(recipientPriv, ephemeralPub, wrapped, nonce []byte) ([]byte, error) {
	if len(recipientPriv) != X25519KeyLen {
		return nil, fmt.Errorf("recipient private key must be %d bytes", X25519KeyLen)
	}
	if len(ephemeralPub) != X25519KeyLen {
		return nil, fmt.Errorf("ephemeral public key must be %d bytes", X25519KeyLen)
	}

	recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive recipient public key: %w", err)
	}
	shared, err := curve25519.X25519(recipientPriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	kek, err := sealSharedKEK(shared, ephemeralPub, recipientPub)
	if err != nil {
		return nil, err
	}
	return UnwrapBEK(kek, wrapped, nonce)
}
