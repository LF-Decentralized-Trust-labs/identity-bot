package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	BackupKEKInfoV1   = "identity-agent-backup-kek-v1"
	PairwiseHDInfoV1  = "identity-agent-pairwise-v1"
	Argon2MemoryKiB   = 64 * 1024 // 64 MiB — OWASP minimum class
	Argon2Iterations  = 3
	Argon2Parallelism = 4
	Argon2SaltLen     = 16
	GCMNonceLen       = 12
	BEKLen            = 32
)

// DefaultArgon2Params returns pinned Argon2id parameters stored in the archive manifest.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		MemoryKiB:   Argon2MemoryKiB,
		Iterations:  Argon2Iterations,
		Parallelism: Argon2Parallelism,
		SaltLen:     Argon2SaltLen,
	}
}

// DeriveBackupKEK derives the 256-bit backup KEK from a BIP39 seed (64 bytes).
// Uses HKDF-SHA256 (current implementation).
//
// Build/test note (2026-06-23): the HD-derivation pin in the backup-recovery architecture specifies a BIP32/SLIP-0010 path for pairwise seeds.
// Current Go uses HKDF (interops with own recovery tests + .iab roundtrips).
// Cross-engine (keripy/Rust) BIP32 vs HKDF golden interop test is required before recovery is final; result will be written back to the backup-recovery architecture per deviation rule.
// HKDF chosen for this align pass because it is the proven working code; no overwrite.
func DeriveBackupKEK(bip39Seed []byte) ([]byte, error) {
	if len(bip39Seed) < 32 {
		return nil, fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	r := hkdf.New(sha256.New, bip39Seed, []byte("identity-agent-backup-salt-v1"), []byte(BackupKEKInfoV1))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf backup kek: %w", err)
	}
	return out, nil
}

// DerivePairwiseSeed derives an Ed25519 seed for a contact index (HD path by index).
// (See DeriveBackupKEK header for the HD-derivation pin in the backup-recovery architecture interop test note.)
func DerivePairwiseSeed(bip39Seed []byte, contactIndex, keyIndex int) ([]byte, error) {
	if len(bip39Seed) < 32 {
		return nil, fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	info := fmt.Sprintf("%s/%d/%d", PairwiseHDInfoV1, contactIndex, keyIndex)
	r := hkdf.New(sha256.New, bip39Seed, []byte("identity-agent-pairwise-salt-v1"), []byte(info))
	out := make([]byte, ed25519.SeedSize)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf pairwise seed: %w", err)
	}
	return out, nil
}

// PairwisePublicKey returns the Ed25519 public key for a derived pairwise seed.
func PairwisePublicKey(seed []byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// DerivePassphraseKEK stretches a user passphrase with Argon2id.
func DerivePassphraseKEK(passphrase string, salt []byte, params Argon2Params) ([]byte, error) {
	if len(salt) < 8 {
		return nil, fmt.Errorf("argon2 salt too short")
	}
	key := argon2.IDKey([]byte(passphrase), salt, params.Iterations, params.MemoryKiB, params.Parallelism, 32)
	return key, nil
}

// NewBEK returns a random 256-bit Backup Encryption Key.
func NewBEK() ([]byte, error) {
	bek := make([]byte, BEKLen)
	if _, err := rand.Read(bek); err != nil {
		return nil, err
	}
	return bek, nil
}

// WrapBEK encrypts the BEK under a KEK using AES-256-GCM.
func WrapBEK(kek, bek []byte) (ciphertext, nonce []byte, err error) {
	if len(kek) != 32 || len(bek) != 32 {
		return nil, nil, fmt.Errorf("kek and bek must be 32 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, bek, nil), nonce, nil
}

// UnwrapBEK decrypts a wrapped BEK.
func UnwrapBEK(kek, wrapped, nonce []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("bek unwrap failed: %w", err)
	}
	if len(plain) != 32 {
		return nil, fmt.Errorf("unexpected bek length %d", len(plain))
	}
	return plain, nil
}

// EncryptPayload seals plaintext under the BEK with AES-256-GCM.
func EncryptPayload(bek, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if len(bek) != 32 {
		return nil, nil, fmt.Errorf("bek must be 32 bytes")
	}
	block, err := aes.NewCipher(bek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// DecryptPayload opens AES-256-GCM ciphertext.
func DecryptPayload(bek, ciphertext, nonce []byte) ([]byte, error) {
	if len(bek) != 32 {
		return nil, fmt.Errorf("bek must be 32 bytes")
	}
	block, err := aes.NewCipher(bek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("payload decrypt failed: %w", err)
	}
	return plain, nil
}

// MnemonicToBIP39Seed converts a space-separated mnemonic to the standard BIP39 seed.
// Mirrors the Flutter Bip39.mnemonicToSeed implementation (PBKDF2-HMAC-SHA512).
func MnemonicToBIP39Seed(mnemonic string, passphrase string) ([]byte, error) {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	if len(words) < 12 {
		return nil, fmt.Errorf("mnemonic must have at least 12 words")
	}
	return bip39PBKDF2(strings.Join(words, " "), passphrase)
}

// SeedKEKFromMnemonic derives the backup KEK from a mnemonic phrase.
func SeedKEKFromMnemonic(mnemonic string) ([]byte, error) {
	seed, err := MnemonicToBIP39Seed(mnemonic, "")
	if err != nil {
		return nil, err
	}
	return DeriveBackupKEK(seed)
}

// SeedKEKFromBIP39 derives the backup KEK from raw BIP39 seed bytes.
func SeedKEKFromBIP39(bip39Seed []byte) ([]byte, error) {
	return DeriveBackupKEK(bip39Seed)
}

// HMACBlake3Placeholder — delta state integrity uses Blake3 in manifest; local HMAC for delta file.
func DeltaStateHMAC(key, deltaJSON []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(deltaJSON)
	return mac.Sum(nil)
}

// EncodeB64 standard base64 without padding (for API transport).
func EncodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeB64 decodes standard base64.
func DecodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}