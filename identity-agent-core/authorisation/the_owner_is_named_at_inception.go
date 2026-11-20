package authorisation

import (
	"fmt"

	"identity-agent-core/drivers"
)

// Who owns an identity is read from its own inception event.
//
// An organisation names its owner, as a KERI event seal, in the event that
// creates it, so the owner is part of what the identifier is. The Identity
// Agent reads it here to decide who may act as the owner, and an offline
// verifier reads it here to check that an owner-signed request was signed by
// the owner the organisation names. Why the seal has this shape is set out
// where the seal is written (ownerAnchorSeal, in the server).

// OwnerSealSN is the position an owner seal names: the owner's inception.
const OwnerSealSN = drivers.OwnerSealSN

// OwnerFromKEL returns the owner named in an identity's inception event.
//
// Only the inception is consulted, deliberately. A later event cannot introduce
// an owner where there was none: an organisation that was not owned when it was
// created never had a founder, and letting a subsequent event claim otherwise
// would reintroduce exactly the silent-overwrite problem the anchor exists to
// remove. Changing owners is a rotation, and rotation is a separate ceremony
// with its own rules.
//
// Returns "" when the identity names no owner, which is the ordinary case for a
// person's own Identity Agent: its identity is delegated, so its delegator is
// already in the event and it needs no separate anchor.
func OwnerFromKEL(kel []map[string]interface{}) (string, error) {
	if len(kel) == 0 {
		return "", fmt.Errorf("no key events to read an owner from")
	}

	inception := kel[0]
	if t, _ := inception["t"].(string); t != "icp" && t != "dip" {
		return "", fmt.Errorf("the first event is %q, not an inception", t)
	}

	seals, ok := inception["a"].([]interface{})
	if !ok {
		return "", nil
	}
	for _, raw := range seals {
		seal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		aid, isOwner, err := OwnerFromSeal(seal)
		if err != nil {
			return "", err
		}
		if isOwner {
			return aid, nil
		}
	}
	return "", nil
}

// OwnerFromSeal returns the owner an anchored seal names, if it is one. The
// reading is drivers.OwnerFromSeal, so a seal is read one way wherever it is
// read.
func OwnerFromSeal(seal map[string]interface{}) (owner string, isOwner bool, err error) {
	return drivers.OwnerFromSeal(seal)
}
