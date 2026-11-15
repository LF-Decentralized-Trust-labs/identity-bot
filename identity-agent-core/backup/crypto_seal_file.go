package backup

// A sealed slot that is bound to the file it is in (`sealed_x25519_v2`), for a backup whose body
// authenticates only a fixed preamble and the file's identifier, not its slots (ADR-029, amendment).
//
// A `sealed_x25519_v1` slot (SealBEK) wraps the backup key with no authenticated data, so the same slot
// can be put in any file made under that key, and a file whose body authenticates its whole header
// cannot take a new slot at all. A v2 slot wraps the key with the file's random 16-byte identifier as
// the AES-GCM authenticated data, and uses its own HKDF label, so:
//
//   - a slot lifted out of one file does not open in another;
//   - a v2 slot is never readable as a v1 slot, or the other way round;
//   - a body authenticated against the preamble and the file identifier only can have a slot added by
//     whoever holds the backup key, and nothing else about the file changes.
//
// It is the same X25519 and HKDF mechanics as SealBEK, the same slot layout (ephemeral public key,
// nonce, wrapped key with its tag), and a different label. The committed vectors in
// testdata/seal-slot-vectors.json are the vectors other implementations check their slots against; they
// are checked here, byte for byte.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// SealSharedInfoV2 labels the HKDF that turns a Diffie-Hellman result into the key that wraps the
	// backup key in a file-bound slot. It is not SealSharedInfoV1, so the two kinds never open each other.
	SealSharedInfoV2 = "identity-agent-backup-seal-shared-v2"

	// FileIDLen is the length of the random identifier a file-bound slot is bound to.
	FileIDLen = 16
)

func sealSharedKEKV2(shared, ephemeralPub, recipientPub []byte) ([]byte, error) {
	salt := append(append([]byte{}, ephemeralPub...), recipientPub...)
	kek := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, salt, []byte(SealSharedInfoV2)).Read(kek); err != nil {
		return nil, fmt.Errorf("hkdf seal shared v2: %w", err)
	}
	return kek, nil
}

func gcmFor(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealBEKForFile seals a backup key to a recipient's public key, bound to fileID. The ephemeral private
// half is dropped as in SealBEK, so the machine writing the file cannot reopen it. It is not exported: the core
// publishes the format, its vectors and its checker (UnsealBEKForFile), and nothing in the core writes these slots.
func sealBEKForFile(recipientPub, bek, fileID []byte) (ephemeralPub, wrapped, nonce []byte, err error) {
	ephPriv, err := randomBytes(X25519KeyLen)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	return sealBEKForFileWith(recipientPub, bek, fileID, ephPriv, nonce)
}

// sealBEKForFileWith is sealBEKForFile with the two random values given, so the committed vector can be
// reproduced byte for byte. Nothing outside the tests passes them.
func sealBEKForFileWith(recipientPub, bek, fileID, ephPriv, nonce []byte) (ephemeralPub, wrapped, _ []byte, err error) {
	if len(recipientPub) != X25519KeyLen {
		return nil, nil, nil, fmt.Errorf("recipient public key must be %d bytes, got %d", X25519KeyLen, len(recipientPub))
	}
	if len(bek) != BEKLen {
		return nil, nil, nil, fmt.Errorf("bek must be %d bytes", BEKLen)
	}
	if len(fileID) != FileIDLen {
		return nil, nil, nil, fmt.Errorf("file id must be %d bytes", FileIDLen)
	}
	ephemeralPub, err = curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ephemeral public key: %w", err)
	}
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("seal to recipient: %w", err)
	}
	kek, err := sealSharedKEKV2(shared, ephemeralPub, recipientPub)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := gcmFor(kek)
	if err != nil {
		return nil, nil, nil, err
	}
	return ephemeralPub, gcm.Seal(nil, nonce, bek, fileID), nonce, nil
}

// UnsealBEKForFile recovers the backup key from a file-bound slot. A slot for another file, another
// recipient, or a v1 slot fails here: the wrap is authenticated, which is what makes trying every slot
// in turn safe.
func UnsealBEKForFile(recipientPriv, ephemeralPub, wrapped, nonce, fileID []byte) ([]byte, error) {
	if len(recipientPriv) != X25519KeyLen || len(ephemeralPub) != X25519KeyLen {
		return nil, fmt.Errorf("keys must be %d bytes", X25519KeyLen)
	}
	if len(nonce) != GCMNonceLen {
		return nil, fmt.Errorf("nonce must be %d bytes", GCMNonceLen)
	}
	if len(fileID) != FileIDLen {
		return nil, fmt.Errorf("file id must be %d bytes", FileIDLen)
	}
	recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive recipient public key: %w", err)
	}
	shared, err := curve25519.X25519(recipientPriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	kek, err := sealSharedKEKV2(shared, ephemeralPub, recipientPub)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(kek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, wrapped, fileID)
	if err != nil || len(plain) != BEKLen {
		return nil, fmt.Errorf("bek unwrap failed")
	}
	return plain, nil
}
