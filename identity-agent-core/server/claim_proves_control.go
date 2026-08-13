package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"identity-agent-core/login"
)

// Proving that whoever is claiming a computer controls the identity they claim
// as.
//
// WHAT THIS REPLACES. The whole of the old check was two string comparisons:
// the presented token against the expected one, and the presented identifier
// against the expected one. The claimant also supplied the public key that
// would be sealed in as the owner's, and it was taken at face value. So the
// token was a bearer secret — whoever held it could claim as any identifier
// they liked, with any key, and the machine would seal it in permanently.
//
// A machine in a data centre survived that only because of WHEN it is told who
// to expect: while it is reachable by the host that started it and by nobody
// else. That window, not the token, was doing the work. A computer on an
// ordinary network has no such window — it is reachable from the moment it
// starts — so the same code there is a race that anybody on the network can
// enter.
//
// So the fix is not a second mechanism for computers you are sitting at. It is
// the missing half of the first one: MAKE THE CLAIMANT PROVE CONTROL. Once a
// claim proves who is making it, where the machine sits stops mattering, and
// both cases become the same exchange.
//
// WHAT IS PROVEN, AND WHAT IS NOT. This establishes that whoever sent the claim
// holds the private key of the identifier they are claiming as. It does not
// establish that they are the person the machine was meant for. On a machine
// that was told an identifier in advance, that second question is answered by
// the comparison against what it was told. On a machine offered from its own
// screen there is nothing to compare against, so the answer is: the first valid
// claim wins, and the code was only ever displayed on the machine itself. That
// is a race an attacker has to win while standing at your desk, rather than
// something they can do later from a photograph — which is worth stating
// plainly rather than implying the signature settles it.

// pairingChallenge is the nonce a claimant has to sign.
//
// Signed over rather than merely echoed, and bound to this machine and this
// offer, so a signature captured from one exchange cannot be replayed into
// another — including against a different machine that happens to be mid-offer.
func newPairingChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// claimSigningInput is the exact bytes a claimant signs.
//
// Every field that decides the outcome is in here. Leaving any of them out
// would let that field be swapped after the fact by anything sitting between
// the two parties, while the signature still verified — the offered key being
// the one that matters, since substituting it is how an attacker gets a machine
// to answer to keys of their own choosing.
//
// Serialised through encoding/json with sorted keys rather than assembled by
// hand, so the two sides cannot drift apart over a separator.
func claimSigningInput(challenge, token, ownerAID, offeredPublicKey string) []byte {
	b, _ := json.Marshal(map[string]string{
		"challenge":          challenge,
		"claim_token":        token,
		"machine_public_key": offeredPublicKey,
		"owner_aid":          ownerAID,
	})
	return b
}

// verifyClaimantControlsTheIdentity is the gate this file exists for.
//
// It answers one question — does whoever sent this claim hold the key of the
// identifier they are claiming as? — and it answers it from the claimant's own
// key log rather than from anything they simply asserted.
//
// The log is not fetched. A key log is self-verifying: each event's identifier
// is derived from its own content, each names the one before it, and the
// signatures are checked against the key the log itself puts in force at that
// point. So a machine with no route to the internet can still establish this,
// which matters because a computer being set up is exactly the machine most
// likely to have no working network yet.
//
// The limit of not fetching is real and worth naming: a presented log cannot
// reveal an event that was WITHHELD from it. Somebody who held a key, rotated
// away from it, and kept the rotation to themselves could present the earlier
// log and sign with the old key. Only witnesses close that, and a machine being
// paired has no relationship with any yet. It is the same exposure as any
// first contact, and it is bounded by the claim window.
// kelToPresent finds the key log for one of this device's own pairwise
// identities.
//
// Two places to look, because a pairwise identity minted for a machine may be
// claimed minutes later or days later. The in-memory registry has it
// immediately; the store has it across a restart. A rental reserved today and
// collected tomorrow depends on the second, so an identity that exists only in
// memory is not good enough on its own.
func (s *CoreServer) kelToPresent(aid string) []map[string]interface{} {
	// The stored form first: it carries the canonical bytes each event was
	// signed over and the signature itself, which is what proves authorship.
	// The in-memory registry holds the parsed events only — readable, and
	// unverifiable, so it is the fallback rather than the answer.
	if kel := s.ownKELForIntroduction(aid); len(kel) > 0 {
		return kel
	}
	if kel, ok := getPairwiseKEL(aid); ok {
		return kel
	}
	return nil
}

func (s *CoreServer) verifyClaimantControlsTheIdentity(req pairingCompleteRequest, challenge, offeredPublicKey string) error {
	if req.OwnerAID == "" {
		return fmt.Errorf("a claim has to say which identity is making it")
	}
	if req.OwnerSignature == "" {
		return fmt.Errorf("this claim carries no signature, so it proves only that " +
			"somebody knows the code — not that they hold the identity they are claiming as")
	}
	if len(req.OwnerKEL) == 0 {
		return fmt.Errorf("this claim carries no key log for %s, so there is nothing to "+
			"check the signature against", req.OwnerAID)
	}
	if s.KeriDriver == nil {
		// Refuse rather than skip. A machine that cannot check the proof must
		// not seal an owner in on the strength of an unchecked one.
		return fmt.Errorf("this instance cannot verify a key log right now, and sealing " +
			"an owner in without verifying one is how a machine ends up answering to whoever asked first")
	}

	result, err := s.KeriDriver.ValidateKEL(req.OwnerAID, req.OwnerKEL)
	if err != nil {
		return fmt.Errorf("could not check the key log for %s: %w", req.OwnerAID, err)
	}
	// KelVerified is the strict question — every event signed, and signed by
	// the key the log itself puts in force. LogSound only says it parses and
	// chains, which a log somebody wrote themselves also does.
	if !result.KelVerified {
		return fmt.Errorf("the key log for %s does not prove its own authorship (%v), so it "+
			"establishes nothing about who controls that identity", req.OwnerAID, result.ValidationErrors)
	}
	if result.CurrentPublicKey == "" {
		return fmt.Errorf("the key log for %s names no key currently in force", req.OwnerAID)
	}

	// THE KEY IS TAKEN FROM THE LOG, NOT FROM THE CLAIM. This is what stops a
	// claimant sealing in a key of their own choosing: the value they sent is
	// checked against what their log actually puts in force, and disagreement
	// is refused rather than resolved in their favour.
	if req.OwnerPublicKey != "" && req.OwnerPublicKey != result.CurrentPublicKey {
		return fmt.Errorf("the claim asks to seal in a key that %s's own log does not put in "+
			"force; the log says %s", req.OwnerAID, result.CurrentPublicKey)
	}

	pub, err := login.DecodeVerkey(result.CurrentPublicKey)
	if err != nil {
		return fmt.Errorf("the key %s's log puts in force cannot be read: %w", req.OwnerAID, err)
	}
	ok, err := login.VerifyString(
		string(claimSigningInput(challenge, req.AdoptionCode, req.OwnerAID, offeredPublicKey)),
		req.OwnerSignature, pub)
	if err != nil {
		return fmt.Errorf("the signature on this claim could not be checked: %w", err)
	}
	if !ok {
		return fmt.Errorf("the signature on this claim was not made by the key %s's log puts "+
			"in force, so whoever sent it does not hold that identity", req.OwnerAID)
	}
	return nil
}
