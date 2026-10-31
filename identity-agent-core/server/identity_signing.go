package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
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
	// Two different failures, told apart because they call for different
	// things. A seed stored here that cannot be read right now (a keychain or
	// enclave not available to this process) is a fault to report, and the
	// key is still this machine's. A seed that derives some other key than the
	// one this identity published, such as a machine's own device-local seed,
	// means the key is held on another device.
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyUnavailable, err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, identity.DerivationIndex, identity.KeyGeneration)
	if err != nil {
		return nil, fmt.Errorf("%w: could not derive this identity's signing key: %v", errKeyUnavailable, err)
	}
	derived := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if identity.PublicKey != "" && derived != identity.PublicKey {
		return nil, errKeyElsewhere
	}
	return seed, nil
}

// errKeyUnavailable is the identity's key held here and not readable right
// now. Nothing waits for another device on it: there is none.
var errKeyUnavailable = errors.New("this machine holds the identity's key and cannot read it right now")

// keyCanSign says whether this Identity Agent can sign as its identity now:
// nil, errKeyElsewhere where the key is held on another device, or
// errKeyUnavailable where it is held here and cannot be read.
func (s *CoreServer) keyCanSign() error {
	_, err := s.identitySigningSeed()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errKeyElsewhere):
		return errKeyElsewhere
	case errors.Is(err, errKeyUnavailable):
		return err
	}
	return fmt.Errorf("%w: %v", errKeyUnavailable, err)
}

// keyIsElsewhere reports whether the identity's key is genuinely held on
// another device.
func (s *CoreServer) keyIsElsewhere() bool {
	return errors.Is(s.keyCanSign(), errKeyElsewhere)
}

// foundingKeyIsOurs says whether publicKey, offered as the key an identity is
// to be founded with, is the key this agent derives itself for a new identity:
// generation 0 on branch 0 of the root seed it holds, the key
// identitySigningSeed would find for the identity once founded. False where
// no root seed is held or the key is any other.
func (s *CoreServer) foundingKeyIsOurs(publicKey string) bool {
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return false
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, 0, 0)
	if err != nil {
		return false
	}
	offered, err := iacrypto.CanonicalVerkeyQB64(publicKey)
	if err != nil {
		return false
	}
	return offered == iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}
