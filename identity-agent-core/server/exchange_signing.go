package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Proving who sent an introduction or an acceptance.
//
// The exchange endpoint took the sender's identifier from the request body and
// believed it. Anyone who could reach an agent could therefore say "I am this
// identity and I accept", and a contact waiting on an answer would move to
// accepted — which is the status that authorises fetching that identity's
// encryption keys and registering them as somebody to encrypt to. A complete
// chain from an unauthenticated POST to a registered peer.
//
// So an exchange is signed now, with the same scheme an Ask uses rather than a
// second one invented here: the canonical body with the signature removed,
// signed by the key of the identity being claimed.
//
// The receiving side has two ways to check it and uses whichever applies. If it
// already knows the sender, it has their key on file and needs nothing from the
// network. If it does not, the key comes from the address the sender published,
// which is the same address the rest of the introduction is checked against.

// signExchange signs an exchange body as this agent's own identity.
//
// The key is re-derived rather than stored: an identity records where its key
// came from — the branch and how far along it — precisely so it can be found
// again. Deriving and then checking the result against the public key the
// identity actually published means a wrong index fails here, loudly, rather
// than producing a signature nobody can verify.
func (s *CoreServer) signExchange(body any) (string, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("this agent has no identity to sign as")
	}
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return "", fmt.Errorf("no key material to sign with: %w", err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, identity.DerivationIndex, identity.KeyGeneration)
	if err != nil {
		return "", fmt.Errorf("could not derive this identity's signing key: %w", err)
	}
	derived := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if identity.PublicKey != "" && derived != identity.PublicKey {
		// Signing with a key this identity never published would produce
		// something no counterparty can verify — a silent failure that only
		// shows up as the other side refusing, for reasons neither can see.
		return "", fmt.Errorf("the derived key is not the one this identity published, so it was not used")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return login.SignAsk(raw, seed)
}

// verifyExchangeSignature establishes that an exchange came from the identity
// it names.
//
// knownKey is what this agent already holds for that identifier, where it holds
// anything. Preferring it is not an optimisation: a key we recorded when we
// resolved somebody is a key we checked, while one fetched now comes from
// whoever answers the address in the request being verified.
func verifyExchangeSignature(body []byte, sig, knownKey string) error {
	if sig == "" {
		return fmt.Errorf("this exchange is not signed, so nothing shows who sent it")
	}
	if knownKey == "" {
		return fmt.Errorf("there is no key on file to check this signature against")
	}
	pub, err := login.DecodeVerkey(knownKey)
	if err != nil {
		return fmt.Errorf("the key on file cannot be read: %w", err)
	}
	ok, err := login.VerifyAsk(body, sig, pub)
	if err != nil || !ok {
		return fmt.Errorf("this exchange was not signed by the identity it claims to be from")
	}
	return nil
}
