package secureenclave

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

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
