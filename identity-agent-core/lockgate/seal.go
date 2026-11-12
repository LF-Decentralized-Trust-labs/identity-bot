package lockgate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyLen is the length of GK.
const KeyLen = 32

// GK is the key the gate releases. A value of this type is a secret: it is never
// logged, never written outside a sealed copy, and is Zero()ed when a lock fires.
type GK []byte

// NewGK mints a fresh random GK.
func NewGK() (GK, error) {
	k := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("mint a gate key: %w", err)
	}
	return k, nil
}

// Zero overwrites the key. Best effort, as ADR-074 section 5 says: Go may have
// copied the value and the operating system may have paged it. It reduces
// exposure; it is not a guarantee.
func (k GK) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// Valid reports whether k has the length of a GK.
func (k GK) Valid() bool { return len(k) == KeyLen }

// ErrWrongProfileOrKey is what Open answers to bytes that do not open under this
// key for this profile: the wrong GK, the wrong profile, or a damaged envelope.
// Deliberately one answer, so it does not say which.
var ErrWrongProfileOrKey = errors.New("these bytes do not open under this key for this profile")

func sealKey(gk GK, profileID string) ([]byte, error) {
	if !gk.Valid() {
		return nil, fmt.Errorf("a gate key is %d bytes, got %d", KeyLen, len(gk))
	}
	if profileID == "" {
		return nil, errors.New("a sealed secret is for a profile, and none was named")
	}
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, gk, nil, []byte("identity-agent gate seal v1|"+profileID)), k); err != nil {
		return nil, err
	}
	return k, nil
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Seal encrypts plain under HKDF(gk, profileID) with AES-256-GCM. The profile id
// is also the additional data, so an envelope for profile A does not open under
// profile B even if both profiles were somehow given the same GK.
func Seal(gk GK, profileID string, plain []byte) ([]byte, error) {
	key, err := sealKey(gk, profileID)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	aead, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(profileID)), nil
}

// Open reverses Seal.
func Open(gk GK, profileID string, sealed []byte) ([]byte, error) {
	key, err := sealKey(gk, profileID)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	aead, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrWrongProfileOrKey
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, sealed[:n], sealed[n:], []byte(profileID))
	if err != nil {
		return nil, ErrWrongProfileOrKey
	}
	return plain, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
