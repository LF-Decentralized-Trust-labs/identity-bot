package secureenclave

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// The key a machine signs its own backups with.
//
// A paired computer writes backups of its data and seals them to its owner, so
// that it can write what it cannot read. Sealing proves an archive was
// encrypted TO the owner and nothing about who encrypted it — and sealing needs
// only a public key, which is public. So without this, anybody could write an
// archive addressed to the owner, and restoring it writes their files, contacts
// and credentials into the agent. The realistic route is whoever controls a
// destination swapping one archive for another.
//
// Hence a key of the machine's own, whose public half its owner records when
// they pair it. Then a backup can be attributed, and one that cannot be is
// visible as such.
//
// DERIVED, NOT STORED. It comes from the machine's root seed, which already
// never leaves it, rather than being minted and written down beside it. One
// fewer secret to keep, to back up, or to lose — and it survives anything that
// preserves the root seed, which is the thing the machine cannot function
// without anyway.
//
// Its own HKDF domain, so a key for signing backups is not a key used for
// anything else. Reusing one key across two purposes is fine until somebody
// finds an interaction between them, and then it is a rewrite.
func BackupSigningKey(dataDir string) (ed25519.PrivateKey, error) {
	seed, err := LoadRootSeed(dataDir)
	if err != nil {
		return nil, fmt.Errorf("this machine has no root seed to derive a signing key from: %w", err)
	}
	return backupSigningKeyFromSeed(seed)
}

// BackupSigningPublicKey is the half a machine publishes when it is paired.
func BackupSigningPublicKey(dataDir string) (ed25519.PublicKey, error) {
	priv, err := BackupSigningKey(dataDir)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func backupSigningKeyFromSeed(rootSeed []byte) (ed25519.PrivateKey, error) {
	if len(rootSeed) < 32 {
		return nil, fmt.Errorf("a root seed must be at least 32 bytes, got %d", len(rootSeed))
	}
	r := hkdf.New(sha256.New, rootSeed,
		[]byte("identity-agent-backup-signing-salt-v1"),
		[]byte("identity-agent/machine-backup-signing/v1"))
	material := make([]byte, ed25519.SeedSize)
	if _, err := r.Read(material); err != nil {
		return nil, fmt.Errorf("derive this machine's backup signing key: %w", err)
	}
	return ed25519.NewKeyFromSeed(material), nil
}

// Where a machine's root seed came from.
//
// Two machines hold a root seed and they are not the same thing. On a device
// its owner carries, it is derived from the recovery words, so those words
// reproduce it. On a paired machine it is minted on the spot and random —
// ensureRootSeed says so plainly: "there is no phrase for it".
//
// Both are 64 bytes and neither says which it is, which is how every scheduled
// backup a paired machine took came to be marked as though the owner's words
// had written it. It verified, it went to every destination, and the owner
// could never restore it, because a wrong mark cannot be waved through the way
// a missing one can. Nobody would have learned that until the day it mattered.
//
// So a machine writes down which it has. One line, beside the seed.
const (
	// SeedFromPhrase means the recovery words reproduce this seed, so an
	// archive marked with it can be checked by whoever holds them.
	SeedFromPhrase = "phrase"
	// SeedIsDeviceLocal means this seed was minted here and belongs to no
	// identity. Nobody's words reproduce it.
	SeedIsDeviceLocal = "device"
)

func seedOriginPath(dataDir string) string {
	return filepath.Join(dataDir, "secureenclave", "root_seed.origin")
}

// RecordSeedOrigin writes down where this machine's root seed came from.
func RecordSeedOrigin(dataDir, origin string) error {
	if origin != SeedFromPhrase && origin != SeedIsDeviceLocal {
		return fmt.Errorf("a seed origin is %q or %q, not %q",
			SeedFromPhrase, SeedIsDeviceLocal, origin)
	}
	if err := os.MkdirAll(filepath.Dir(seedOriginPath(dataDir)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(seedOriginPath(dataDir), []byte(origin), 0o600)
}

// SeedCameFromAPhrase reports whether the recovery words reproduce this
// machine's root seed.
//
// An unrecorded origin answers false, and that direction is deliberate. A
// machine that seed-marks its archives wrongly produces backups its owner can
// never restore and cannot be told about; a machine that machine-marks them
// wrongly produces backups that need the machine's key, which its owner has
// recorded and can supply. Of the two ways to be wrong, only one is
// recoverable, so the unknown case takes it.
func SeedCameFromAPhrase(dataDir string) bool {
	raw, err := os.ReadFile(seedOriginPath(dataDir))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == SeedFromPhrase
}
