package didcomm

import (
	"fmt"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Deciding whether a set of encryption keys really belongs to an identifier.
//
// This is the step the whole sealed transport rested on and nobody was doing.
// An agent fetched a counterparty's keys from an address and stored them, and
// the only check was that the identifier echoed back matched the one asked
// for — which is the answering server's own assertion. So whoever could answer
// that request decided what everybody encrypted to them, and on rented
// hardware that is the party the encryption exists to exclude.
//
// There are two ways to tie keys to an identifier and this uses whichever is
// available, strongest first.
//
// ANCHORED. The identifier commits to the keys in its own inception event. An
// identifier is derived from that event, so changing the keys changes who this
// is. Nothing has to be trusted and nothing has to be fetched separately —
// there is no step left to attack.
//
// VOUCHED FOR. The identifier's current signing key signs the keys. Weaker,
// because it relies on the key history being checked, and stronger than it
// sounds now that a history with an unsigned event in it is refused. This is
// what covers identities that already exist, whose inception committed to
// nothing because nothing was writing anchors when they were created.
//
// Neither is a refusal. Keys that cannot be tied to the identifier are keys
// that could belong to anybody.

// KeyTrust says how a set of keys is tied to an identifier.
type KeyTrust string

const (
	KeysAnchored KeyTrust = "anchored" // committed in the identifier itself
	KeysVouched  KeyTrust = "vouched"  // signed by the identifier's current key
	KeysUntied   KeyTrust = "not tied" // nothing connects these keys to it
)

// CheckKeysBelongTo establishes whether these keys belong to this identifier.
//
// kelEvents is the identifier's key history as fetched and validated for this
// use. currentKey is the key that history ends with.
func CheckKeysBelongTo(did *DID, kelEvents []map[string]interface{}, currentKey string) (KeyTrust, error) {
	if did == nil || did.AID == "" {
		return KeysUntied, fmt.Errorf("no keys were supplied")
	}

	// Anchored, if the inception committed to anything. Checked first because
	// it needs nothing else to be true.
	if len(kelEvents) > 0 {
		x, kem, err := iacrypto.AnchoredAgreementKeys(kelEvents[0])
		switch {
		case err == nil:
			if merr := did.MatchesAnchoredKeys(x, kem); merr != nil {
				return KeysUntied, fmt.Errorf("the keys offered for %s are not the ones that "+
					"identifier commits to: %w", did.AID, merr)
			}
			// The signing keys too, where the identifier commits to them.
			//
			// Confidentiality and authenticity are separate halves of the same
			// keyset, and checking only the first accepts a set whose signing
			// keys belong to somebody else. Absent means the identifier predates
			// committing to them, which is weaker rather than wrong, so it does
			// not refuse — but a set that IS committed to and does not match is
			// refused, because that is substitution rather than age.
			ed, dsa, serr := iacrypto.AnchoredSigningKeys(kelEvents[0])
			switch {
			case serr == nil:
				if merr := did.MatchesAnchoredSigningKeys(ed, dsa); merr != nil {
					return KeysUntied, fmt.Errorf("the signing keys offered for %s are not "+
						"the ones that identifier commits to: %w", did.AID, merr)
				}
			case !isNotAnchored(serr):
				return KeysUntied, fmt.Errorf("this identifier's committed signing keys "+
					"are unusable: %w", serr)
			}
			return KeysAnchored, nil
		case !isNotAnchored(err):
			// An anchor that exists and will not parse is a different thing
			// from one that was never there, and must not fall through to the
			// weaker check as though the identifier had said nothing.
			return KeysUntied, fmt.Errorf("this identifier's committed keys are unusable: %w", err)
		}
	}

	// Vouched for by the identity's current signing key.
	if did.KelSig == "" {
		return KeysUntied, fmt.Errorf("%s neither commits to these keys nor signs for them, "+
			"so nothing connects them to that identity", did.AID)
	}
	if currentKey == "" {
		return KeysUntied, fmt.Errorf("there is no verified signing key for %s to check "+
			"the signature against", did.AID)
	}
	pub, err := login.DecodeVerkey(currentKey)
	if err != nil {
		return KeysUntied, fmt.Errorf("the signing key on file for %s cannot be read: %w", did.AID, err)
	}
	ok, verr := login.VerifyString(string(did.SigningInput()), did.KelSig, pub)
	if verr != nil || !ok {
		return KeysUntied, fmt.Errorf("the keys offered for %s are not signed by that identity", did.AID)
	}
	return KeysVouched, nil
}

func isNotAnchored(err error) bool {
	return err != nil && err.Error() == iacrypto.ErrNotAnchored.Error()
}
