package server

import (
	"crypto/ed25519"
	"fmt"

	"identity-agent-core/asset"
	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An add-on signs as an identity this Identity Agent holds, an AI agent or
// the governance log's signer, without being given the key: the core hands
// it a signer that holds the key and signs on request.

// heldKey is one key the core holds, as a signer.
type heldKey struct {
	seed []byte
	pub  string
}

func heldKeyOf(seed []byte) heldKey {
	return heldKey{seed: seed, pub: iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))}
}

func (k heldKey) PublicKey() string                         { return k.pub }
func (k heldKey) SignString(message string) (string, error) { return login.SignString(message, k.seed) }
func (k heldKey) SignEvent(raw []byte) (string, error)      { return signEventBytes(raw, k.seed) }

// assetSigner signs as the asset this Identity Agent holds whose identifier
// is aid, such as one of its AI agents.
func (s *CoreServer) assetSigner(aid string) (coretypes.KeySigner, error) {
	if s.assetHandler == nil || aid == "" {
		return nil, fmt.Errorf("%s is not an asset held here", aid)
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.PairwiseAID == aid {
			seed, err := asset.AssetSigningSeed(s.DataDir, a.SigningIndex)
			if err != nil {
				return nil, fmt.Errorf("the signing key of %s is unavailable: %w", aid, err)
			}
			return heldKeyOf(seed), nil
		}
	}
	return nil, fmt.Errorf("%s is not an asset held here", aid)
}

// logSigner signs as the identity that signs the governance log, and gives
// the public half of its next key, which its inception commits to. rec is
// that identity as recorded in the data directory.
func (s *CoreServer) logSigner() (signer coretypes.KeySigner, nextPublicKey string, rec coretypes.LogSignerRecord, err error) {
	rec, found, err := readInvocationSignerRecord(s.DataDir)
	if err != nil || !found {
		return nil, "", rec, fmt.Errorf("no governance log signer is on record: %v", err)
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, "", rec, fmt.Errorf("the log signer's key cannot be had: %v", err)
	}
	seed, err := backup.DerivePairwiseSeed(root, rec.Index, 0)
	if err != nil {
		return nil, "", rec, err
	}
	next, err := backup.DerivePairwiseSeed(root, rec.Index, 1)
	if err != nil {
		return nil, "", rec, err
	}
	return heldKeyOf(seed), heldKeyOf(next).pub, rec, nil
}
