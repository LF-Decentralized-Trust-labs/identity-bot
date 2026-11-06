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
// ANCHORED. The identifier commits to the keys in its own key log: its
// inception event, or the later event that replaced its keyset, whichever
// anchored one last (ADR-061 section 8). Every event is signed by the keys in
// force and the inception names the identifier, so nobody else can change which
// keys are committed. Nothing else has to be trusted or fetched.
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
// kelEvents is the identifier's whole key history, as fetched and validated
// for this use: the keys in force are the ones it anchored last, so a history
// cut short would answer with keys it has since replaced. currentKey is the key
// that history ends with.
func CheckKeysBelongTo(did *DID, kelEvents []map[string]interface{}, currentKey string) (KeyTrust, error) {
	if did == nil || did.AID == "" {
		return KeysUntied, fmt.Errorf("no keys were supplied")
	}

	// Anchored, if the log committed to a keyset. Checked first because it
	// needs nothing else to be true. The keyset in force is the one the log
	// anchored last, not the founding's: after a move to a new recovery phrase
	// the founding's keys derive from a phrase that may have leaked, and are
	// out of use (ADR-061 section 8).
	if anchoring, aerr := iacrypto.KeySetInForce(kelEvents); aerr == nil {
		x, kem, err := iacrypto.AnchoredAgreementKeys(anchoring)
		switch {
		case err == nil:
			if merr := did.MatchesAnchoredKeys(x, kem); merr != nil {
				return KeysUntied, fmt.Errorf("the keys offered for %s are not the ones that "+
					"identifier commits to: %w", did.AID, merr)
			}
			// The signing keys too, where the anchor commits to them.
			//
			// Confidentiality and authenticity are separate halves of the same
			// keyset, and checking only the first accepts a set whose signing
			// keys belong to somebody else. A keyset anchor commits to both
			// (iacrypto.KeySetAnchor); one that commits to encryption keys
			// alone (a hybrid inception's, built only for tests) ties no
			// signing key, so signing keys offered beside it count only where
			// the identity's current key signed them, and are refused
			// otherwise. Offering none is fine: then nothing untied is taken.
			ed, dsa, serr := iacrypto.AnchoredSigningKeys(anchoring)
			switch {
			case serr == nil:
				if merr := did.MatchesAnchoredSigningKeys(ed, dsa); merr != nil {
					return KeysUntied, fmt.Errorf("the signing keys offered for %s are not "+
						"the ones that identifier commits to: %w", did.AID, merr)
				}
			case isNotAnchored(serr):
				if (did.Ed != "" || did.Dsa != "") && vouchedBy(did, currentKey) != nil {
					return KeysUntied, fmt.Errorf("%s commits to encryption keys and no signing "+
						"keys, and the signing keys offered are not signed by it", did.AID)
				}
			default:
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
	if err := vouchedBy(did, currentKey); err != nil {
		return KeysUntied, err
	}
	return KeysVouched, nil
}

// vouchedBy reports, as an error naming why not, whether the identity's current
// signing key signed the keys did offers.
func vouchedBy(did *DID, currentKey string) error {
	if did.KelSig == "" {
		return fmt.Errorf("the keys offered for %s are not signed by that identity", did.AID)
	}
	if currentKey == "" {
		return fmt.Errorf("there is no verified signing key for %s to check "+
			"the signature against", did.AID)
	}
	pub, err := login.DecodeVerkey(currentKey)
	if err != nil {
		return fmt.Errorf("the signing key on file for %s cannot be read: %w", did.AID, err)
	}
	ok, verr := login.VerifyString(string(did.SigningInput()), did.KelSig, pub)
	if verr != nil || !ok {
		return fmt.Errorf("the keys offered for %s are not signed by that identity", did.AID)
	}
	return nil
}

func isNotAnchored(err error) bool {
	return err != nil && err.Error() == iacrypto.ErrNotAnchored.Error()
}
