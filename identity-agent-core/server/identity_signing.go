package server

import (
	"crypto/ed25519"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
)

// The agent's own signing key, where it can derive one.
//
// This is all that remains of the exchange-signing layer. Introductions used to
// be signed as the identity and posted as plaintext, and the signing could not
// work: the identity's key belongs to the owner's device and never reaches the
// agent, so the signature was absent and the far side refused it. Introductions
// now ride the envelope, which is authenticated by the messaging keys the agent
// does hold.
//
// What is left is the weaker vouching for a published keyset — used only by
// identities whose keys this agent derived, and which an identifier that
// commits to its keys does not need at all.
// identitySigningSeed recovers the seed for this agent's current signing key.
//
// Re-derived rather than stored: an identity records the branch its key came
// from and how far along it, precisely so it can be found again. The result is
// checked against the public key the identity actually published, so a wrong
// index fails here rather than producing signatures nobody can verify.
func (s *CoreServer) identitySigningSeed() ([]byte, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, fmt.Errorf("this agent has no identity to sign as")
	}
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("no key material to sign with: %w", err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, identity.DerivationIndex, identity.KeyGeneration)
	if err != nil {
		return nil, fmt.Errorf("could not derive this identity's signing key: %w", err)
	}
	derived := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if identity.PublicKey != "" && derived != identity.PublicKey {
		return nil, fmt.Errorf("the derived key is not the one this identity published, so it was not used")
	}
	return seed, nil
}
