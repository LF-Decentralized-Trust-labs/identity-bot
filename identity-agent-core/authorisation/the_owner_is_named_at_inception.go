package authorisation

import "fmt"

// Who owns an identity is read from its own inception event.
//
// An organisation names its owner, as a KERI event seal, in the event that
// creates it, so the owner is part of what the identifier is. The Identity
// Agent reads it here to decide who may act as the owner, and an offline
// verifier reads it here to check that an owner-signed request was signed by
// the owner the organisation names. Why the seal has this shape is set out
// where the seal is written (ownerAnchorSeal, in the server).

// OwnerSealSN is the position an owner seal names: the owner's inception.
const OwnerSealSN = "0"

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

// OwnerFromSeal returns the owner an anchored seal names, if it is one.
//
// Three outcomes, not two. A seal can name an owner, be something else
// entirely, or be an owner seal that is broken — and the third must not
// collapse into the second. An identity whose ownership record is corrupt and
// one that was never owned need different answers: the first is a fault to
// report, the second is the ordinary state of a person's own Identity Agent.
func OwnerFromSeal(seal map[string]interface{}) (owner string, isOwner bool, err error) {
	// An owner seal is a KERI event seal: exactly these three fields, naming the
	// owner's inception. Anything else — a digest seal from break-glass
	// recovery, a seal with extra fields — is not this function's business.
	if len(seal) != 3 {
		return "", false, nil
	}
	iRaw, hasI := seal["i"]
	sRaw, hasS := seal["s"]
	dRaw, hasD := seal["d"]
	if !hasI || !hasS || !hasD {
		return "", false, nil
	}
	aid, _ := iRaw.(string)
	sn, _ := sRaw.(string)
	d, _ := dRaw.(string)

	if aid == "" || d == "" {
		// The shape of an owner seal with nothing in it. Reported rather than
		// skipped: silently ignoring it would let a broken identity look like
		// an unowned one.
		return "", false, fmt.Errorf("an event seal names no identity or no event, so the " +
			"ownership record is malformed rather than absent")
	}
	if sn != OwnerSealSN {
		// A seal naming a later event of some identity. Real, and not a
		// statement about ownership.
		return "", false, nil
	}
	// The seal names the owner's inception, whose digest IS its identifier
	// because every identity here is self-addressing. Where the two disagree the
	// seal refers to some other identity's event and is not an ownership claim.
	if d != aid {
		return "", false, nil
	}
	return aid, true, nil
}
