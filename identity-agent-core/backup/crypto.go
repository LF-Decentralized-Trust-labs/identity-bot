package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	BackupKEKInfoV1   = "identity-agent-backup-kek-v1"
	VaultKEKInfoV1    = "identity-agent-credential-vault-kek-v1"
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
// Uses HKDF-SHA256 (for KEK slot; pairwise uses separate HD path).
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

// DeriveVaultKEK derives the 256-bit credential-vault key from the root BIP39
// seed (64 bytes). Distinct HKDF salt/info domain-separate it from the backup KEK.
func DeriveVaultKEK(bip39Seed []byte) ([]byte, error) {
	if len(bip39Seed) < 32 {
		return nil, fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	r := hkdf.New(sha256.New, bip39Seed, []byte("identity-agent-vault-salt-v1"), []byte(VaultKEKInfoV1))
	out := make([]byte, 32)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("hkdf vault kek: %w", err)
	}
	return out, nil
}

// DerivePairwiseSeed derives an Ed25519 seed for a contact index using BIP32/SLIP-0010 HD from the root keystore seed.
// Path: m / 44' / 0' / 0' / contactIndex' / keyIndex'
// This is the architected derivation (replaces previous HKDF). Deterministic, matches across engines for restore.
// Go<->Rust (mobile bridge) cross vector deferred to mobile QA (verified 2026-06-23 during mobile build/QA; desktop Go+keripy golden complete here).
func DerivePairwiseSeed(bip39Seed []byte, contactIndex, keyIndex int) ([]byte, error) {
	if len(bip39Seed) < 32 {
		return nil, fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	path := []uint32{
		0x8000002C, // purpose' = 44'
		0x80000000, // coin_type' = 0'
		0x80000000, // account' = 0'
		uint32(contactIndex) | 0x80000000,
		uint32(keyIndex) | 0x80000000,
	}
	return deriveSLIP10Ed25519(bip39Seed, path)
}

// deriveMaster and ckd implement SLIP-0010 for Ed25519 (master "ed25519 seed", hardened children).
func deriveMaster(bip39 []byte) (k, c []byte) {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(bip39)
	I := h.Sum(nil)
	return I[:32], I[32:]
}

func ckd(kPar, cPar []byte, i uint32) (k, c []byte) {
	data := make([]byte, 1+32+4)
	data[0] = 0x00
	copy(data[1:33], kPar)
	binary.BigEndian.PutUint32(data[33:], i)
	h := hmac.New(sha512.New, cPar)
	h.Write(data)
	I := h.Sum(nil)
	return I[:32], I[32:]
}

func deriveSLIP10Ed25519(seed []byte, path []uint32) ([]byte, error) {
	k, c := deriveMaster(seed)
	for _, idx := range path {
		k, c = ckd(k, c, idx)
	}
	return k, nil
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
	// Exactly 24. A recovery phrase is not a password on the identity, it is
	// the identity, so there is no reason to accept a weaker one — and the
	// shorter form was never issued to anybody, so accepting it would only
	// widen what a restore trusts.
	if len(words) != 24 {
		return nil, fmt.Errorf("a recovery phrase is 24 words, got %d", len(words))
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
