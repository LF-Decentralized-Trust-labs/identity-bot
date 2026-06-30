package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"hash/crc32"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

// assetIndexBase keeps asset HD indices in a high namespace, separate from the low
// sequential indices used by per-user login relationships, so the two never collide.
const assetIndexBase = 0x40000000

// signingIndexForID derives a stable HD index for an asset from its immutable ID.
// Deterministic + stable (survives restarts), unique per asset for any realistic count.
func signingIndexForID(id string) int {
	return assetIndexBase + int(crc32.ChecksumIEEE([]byte(id))&0x0FFFFFFF)
}

// ensureRootSeed loads the controller root seed from secure storage, bootstrapping it if
// absent — mirrors the per-user login flow (getOrCreateRelationship).
func ensureRootSeed(dataDir string) ([]byte, error) {
	root, err := secureenclave.LoadRootSeed(dataDir)
	if err == nil {
		return root, nil
	}
	root = make([]byte, 64)
	if _, re := rand.Read(root); re != nil {
		return nil, re
	}
	if serr := secureenclave.StoreRootSeed(dataDir, root); serr != nil {
		return nil, serr
	}
	return root, nil
}

// AssetSigningSeed re-derives an asset's Ed25519 signing seed from the controller root seed
// (secure storage) and the asset's persisted SigningIndex. The raw seed is never
// stored — only the root (in the enclave) and the index (on the asset record).
func AssetSigningSeed(dataDir string, signingIndex int) ([]byte, error) {
	root, err := secureenclave.LoadRootSeed(dataDir)
	if err != nil {
		return nil, err
	}
	return backup.DerivePairwiseSeed(root, signingIndex, 0)
}

// deriveAssetKeypair derives the current + next Ed25519 public keys for an asset at the
// given signing index, used at inception so the asset's KEL key == the key it signs with.
func deriveAssetKeypair(dataDir string, signingIndex int) (pub, nextPub ed25519.PublicKey, err error) {
	root, err := ensureRootSeed(dataDir)
	if err != nil {
		return nil, nil, err
	}
	seed, err := backup.DerivePairwiseSeed(root, signingIndex, 0)
	if err != nil {
		return nil, nil, err
	}
	nextSeed, err := backup.DerivePairwiseSeed(root, signingIndex, 1)
	if err != nil {
		return nil, nil, err
	}
	pub = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub = ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
	return pub, nextPub, nil
}
