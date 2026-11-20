package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

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

// claimSigningInput is the exact bytes a claimant signs when it names no
// separate owner.
//
// Every field that decides the outcome is in here. Leaving any of them out
// would let that field be swapped after the fact by anything sitting between
// the two parties, while the signature still verified — the offered key being
// the one that matters, since substituting it is how an attacker gets a machine
// to answer to keys of their own choosing.
//
// Serialised through encoding/json with sorted keys rather than assembled by
// hand, so the two sides cannot drift apart over a separator.
//
// These bytes are fixed. A claim that names a separate owner signs the two
// inputs below instead, and neither of them can ever equal this one: each
// carries a field this one lacks.
func claimSigningInput(challenge, token, ownerAID, offeredPublicKey string) []byte {
	b, _ := json.Marshal(map[string]string{
		"challenge":          challenge,
		"claim_token":        token,
		"machine_public_key": offeredPublicKey,
		"owner_aid":          ownerAID,
	})
	return b
}

// claimNamingAnOwnerSigningInput is what a claimant signs when its claim names
// a separate owner for what the machine founds (ADR-038, Amendment 1).
//
// The claim's own fields, and the owner's identifier beside them. The owner
// decides the outcome as much as the offered key does, so it is signed for the
// same reason: without it, anything between the two parties could replace the
// owner with an identity of its own, or remove it so that the claiming identity
// is sealed as owner after all, and the claim would still verify.
func claimNamingAnOwnerSigningInput(challenge, token, claimerAID, offeredPublicKey, foundedOwnerAID string) []byte {
	b, _ := json.Marshal(map[string]string{
		"challenge":          challenge,
		"claim_token":        token,
		"founded_owner_aid":  foundedOwnerAID,
		"machine_public_key": offeredPublicKey,
		"owner_aid":          claimerAID,
	})
	return b
}

// foundedOwnerRole is the role a separately named owner signs under. It is in
// what the owner signs so that a signature made as an owner can never be
// offered as a claim, nor a claim's as an owner's.
const foundedOwnerRole = "founded_owner"

// foundedOwnerSigningInput is what a separately named owner signs (ADR-038,
// Amendment 1).
//
// The same exchange the claim signs, with two things said outright: that this
// identity is signing as the owner of what is founded, and which identity is
// making the claim it agrees to be named in. An owner that signed only the
// exchange would have agreed to be named by whoever presented its signature.
func foundedOwnerSigningInput(challenge, token, claimerAID, offeredPublicKey, foundedOwnerAID string) []byte {
	b, _ := json.Marshal(map[string]string{
		"challenge":          challenge,
		"claim_token":        token,
		"claimer_aid":        claimerAID,
		"founded_owner_aid":  foundedOwnerAID,
		"machine_public_key": offeredPublicKey,
		"role":               foundedOwnerRole,
	})
	return b
}

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
	if kel, ok := s.getPairwiseKEL(aid); ok {
		return kel
	}
	return nil
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
// log and sign with the old key. Only witnesses close that, so the log is then
// put to the witnesses it designates (theWitnessesDoNotRefuse). What remains is
// a computer offered from its own screen that can reach no witness, and an
// identity that named none: there an unconfirmed history is accepted and
// recorded, and the exposure is bounded by the claim window.
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
	// A claim that names a separate owner signs for that owner too, so the
	// owner in the request is the one the claimant chose.
	signed := claimSigningInput(challenge, req.AdoptionCode, req.OwnerAID, offeredPublicKey)
	if req.FoundedOwner != nil {
		signed = claimNamingAnOwnerSigningInput(challenge, req.AdoptionCode, req.OwnerAID,
			offeredPublicKey, req.FoundedOwner.AID)
	}
	if err := s.aKeyLogAndSignatureProveControl(req.OwnerAID, req.OwnerPublicKey, req.OwnerKEL,
		req.OwnerSignature, signed); err != nil {
		return err
	}
	// Authorship is established. Completeness is a different question, and this
	// is where it is asked — see corroborate_the_claim.go.
	return s.theWitnessesDoNotRefuse(req.OwnerAID, req.OwnerKEL)
}

// aKeyLogAndSignatureProveControl checks that a presented key log proves its
// own authorship and that a signature over this exchange was made by the key
// that log puts in force.
//
// One check for every identity a claim names, the claimant and a separately
// named owner alike, so that the two cannot come to be held to different
// standards.
func (s *CoreServer) aKeyLogAndSignatureProveControl(
	aid, offeredKey string, kel []map[string]interface{}, signature string, signed []byte,
) error {
	if s.KeriDriver == nil {
		// Refuse rather than skip. A machine that cannot check the proof must
		// not seal an owner in on the strength of an unchecked one.
		return fmt.Errorf("this instance cannot verify a key log right now, and sealing " +
			"an owner in without verifying one is how a machine ends up answering to whoever asked first")
	}

	result, err := s.KeriDriver.ValidateKEL(aid, kel)
	if err != nil {
		return fmt.Errorf("could not check the key log for %s: %w", aid, err)
	}
	// KelVerified is the strict question — every event signed, and signed by
	// the key the log itself puts in force. LogSound only says it parses and
	// chains, which a log somebody wrote themselves also does.
	if !result.KelVerified {
		return fmt.Errorf("the key log for %s does not prove its own authorship (%v), so it "+
			"establishes nothing about who controls that identity", aid, result.ValidationErrors)
	}
	if result.CurrentPublicKey == "" {
		return fmt.Errorf("the key log for %s names no key currently in force", aid)
	}

	// THE KEY IS TAKEN FROM THE LOG, NOT FROM THE REQUEST. This is what stops
	// a claimant sealing in a key of their own choosing: the value they sent is
	// checked against what the log actually puts in force, and disagreement is
	// refused rather than resolved in their favour.
	if offeredKey != "" && offeredKey != result.CurrentPublicKey {
		return fmt.Errorf("the key offered for %s is not the one its own log puts in "+
			"force; the log says %s", aid, result.CurrentPublicKey)
	}

	pub, err := login.DecodeVerkey(result.CurrentPublicKey)
	if err != nil {
		return fmt.Errorf("the key %s's log puts in force cannot be read: %w", aid, err)
	}
	ok, err := login.VerifyString(string(signed), signature, pub)
	if err != nil {
		return fmt.Errorf("the signature offered for %s could not be checked: %w", aid, err)
	}
	if !ok {
		return fmt.Errorf("the signature offered for %s was not made over this exchange by the "+
			"key its log puts in force, so whoever sent it does not hold that identity", aid)
	}
	return nil
}

// theWitnessesDoNotRefuse asks somebody other than the presenter whether a key
// log is the whole history of its identity.
//
// A presented log cannot reveal an event that was withheld from it: somebody
// who held a key, and kept back the rotation that retired it, can present the
// earlier log and sign with the old key. So every identity a claim names is put
// to the witnesses its own log designates, the claimant and a separately named
// owner alike. A history a witness contradicts, or one that cannot be checked,
// is refused on every machine. One that nobody could confirm is refused where
// this machine can always reach a witness (see mustBeCorroborated) and recorded
// where it cannot.
func (s *CoreServer) theWitnessesDoNotRefuse(aid string, kel []map[string]interface{}) error {
	c := s.askTheWitnesses(aid, kel)
	if c.Unverified != "" {
		return fmt.Errorf("this history cannot be corroborated: %s", c.Unverified)
	}
	if c.Contradicted {
		return fmt.Errorf("this history is not the whole history: %s", c.Why)
	}
	if !c.Corroborated() && s.mustBeCorroborated() {
		return fmt.Errorf("nobody other than whoever presented it could confirm %s's history "+
			"(%d witnesses named, %d answered signed, %d held the events and %d are needed, %d were empty, %d behind, %d failed; receipts to the threshold at every establishment event: %v). A machine that somebody else set up can "+
			"always reach a witness, so being unable to is a reason to refuse rather than "+
			"to proceed", aid, c.Designated, c.Asked, c.Held, c.Required, c.Empty, c.Behind, c.Failed, c.ReceiptsMet)
	}
	if !c.Corroborated() {
		// Recorded, not refused. This is a computer somebody is sitting at: it
		// may have no working network at all, which is the case the presented
		// log exists for. Refusing would make a machine unable to be set up in
		// exactly the situation setting it up is most normal.
		log.Printf("[pairing] %s accepted on an UNCORROBORATED history (%d witnesses named, "+
			"%d answered signed, %d held the events of %d needed, %d empty, %d behind, %d failed, receipts met: %v) — accepted because this machine was offered from its own screen, "+
			"where the person is present; a hosted machine would refuse",
			aid, c.Designated, c.Asked, c.Held, c.Required, c.Empty, c.Behind, c.Failed, c.ReceiptsMet)
	}
	return nil
}

// mustBeCorroborated reports whether this machine should refuse a history
// nobody else could confirm.
//
// The distinction is not about how much a machine is trusted; it is about what
// it can reach. A machine somebody else set up was reached by a provisioning
// host before anyone could claim it, so it has a network and can always ask a
// witness — being unable to is a genuine signal. A computer being set up on
// somebody's desk may have no route out at all, and refusing there would make
// the ordinary case impossible while stopping nobody: the person is standing in
// front of it.
//
// So the question is answered by HOW THIS MACHINE WAS OFFERED, which it already
// knows: told by a host, or offered from its own screen.
func (s *CoreServer) mustBeCorroborated() bool {
	_, live := localPairingOffer()
	return !live
}

// verifyTheOwnerBeingSealed checks that the claimant also holds the identity it
// is naming as the owner of what this machine founds.
//
// Separate from the claim itself because they answer different questions. The
// claim asks whether this is the party the machine was reserved for. This asks
// whether the identity about to be written into an inception event, permanently,
// is one the claimant can actually sign as. ADR-038 explains why those are two
// identities rather than one: the party that reserved the machine knows the
// first, and would otherwise be able to recognise its own customer in every
// identity that machine went on to found.
//
// An owner sealed on an unproved assertion could be an identity that never
// agreed to anything — and an owner named at inception can never be replaced.
// So it is held to the standard the claim is, by the same two checks: its key
// log proves its own authorship and its signature was made by the key that log
// puts in force, and the witnesses its log designates are asked whether that
// log is the whole history. What it signs names its role and the identity
// making the claim (see foundedOwnerSigningInput), so its agreement is to this
// claim and no other.
func (s *CoreServer) verifyTheOwnerBeingSealed(
	owner *foundedOwner, claimerAID, challenge, adoptionCode, offeredPublicKey string,
) error {
	if owner.AID == "" {
		return fmt.Errorf("an owner has to say which identity it is")
	}
	if owner.Signature == "" {
		return fmt.Errorf("no signature was offered for %s, so naming it as owner "+
			"asserts control rather than proving it", owner.AID)
	}
	if len(owner.KEL) == 0 {
		return fmt.Errorf("no key log was offered for %s, so there is nothing to check "+
			"its signature against", owner.AID)
	}
	if err := s.aKeyLogAndSignatureProveControl(owner.AID, owner.PublicKey, owner.KEL, owner.Signature,
		foundedOwnerSigningInput(challenge, adoptionCode, claimerAID, offeredPublicKey, owner.AID)); err != nil {
		return err
	}
	return s.theWitnessesDoNotRefuse(owner.AID, owner.KEL)
}
