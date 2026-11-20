package drivers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ownerEventSeal names the owner's inception event.
//
// An event seal, in the field order the specification lists. It was once
// {"i": <owner>, "r": "owner"}, which is not a shape KERI defines: a strict
// reader parses this field as one of a closed set of seals and could not parse
// an inception carrying the old form at all, so an owned identity's whole log
// was unreadable outside this project.
//
// Every identity here is self-addressing, so the identifier IS the digest of
// its inception event — which is what lets the seal name that event using only
// the identifier, and what makes it resolvable by anyone holding the owner's
// log. An identifier of another kind would produce a seal pointing at nothing.
//
// Written as ordered JSON rather than built from a map, because marshalling a
// map sorts the keys and a seal's field order is part of it.
func ownerEventSeal(ownerAID string) (json.RawMessage, error) {
	if ownerAID == "" {
		return nil, fmt.Errorf("an owner seal must name an owner")
	}
	if !strings.HasPrefix(ownerAID, "E") {
		return nil, fmt.Errorf("%q is not a self-addressing identifier, so an owner seal "+
			"naming it would point at no event", ownerAID)
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%q,"s":"0","d":%q}`, ownerAID, ownerAID)), nil
}

// Reading who an identity names as its owners, out of its own events.
//
// The reading lives here, beside the seal's writer and the log validator, so
// everything that asks "whom does this log name" reads it one way: the server
// for its own identity, an offline verifier for a request an owner signed, and
// the two-log ownership check. What a name proves is not decided here: a log
// names its owners, and ownership needs the owner's own log as well (ADR-087).

// OwnerSealSN is the position an owner seal names: the owner's inception.
const OwnerSealSN = "0"

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

// OwnerSetFromEvent reads an owner anchor out of one event.
//
// found distinguishes "this event changed the owners" from "this event set them
// to nobody", which are different statements and must not collapse. An identity
// cannot rotate itself to having no owners — that would leave it answering only
// to itself, which is the state this whole mechanism exists to make
// unreachable.
func OwnerSetFromEvent(event map[string]interface{}) (owners []string, found bool, err error) {
	seals, ok := event["a"].([]interface{})
	if !ok {
		return nil, false, nil
	}

	// Only an establishment event can name owners.
	//
	// An interaction anchors event seals of exactly the same shape — a registry,
	// a credential issuance, a delegation approval. Without this, issuing a
	// credential would read as reassigning the organisation to the credential.
	if !establishmentEvent(event) {
		return nil, false, nil
	}

	seen := map[string]bool{}
	for _, raw := range seals {
		seal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		aid, isOwner, err := OwnerFromSeal(seal)
		if err != nil {
			return nil, false, err
		}
		if !isOwner {
			continue
		}
		found = true
		// A set, not a list. The same owner twice would otherwise count twice
		// towards any threshold, which is how one person becomes a quorum.
		if seen[aid] {
			continue
		}
		seen[aid] = true
		owners = append(owners, aid)
	}

	if found && len(owners) == 0 {
		return nil, false, fmt.Errorf("an event claims to change the owners and names none")
	}
	return owners, found, nil
}

// establishmentEvent reports whether an event can carry an owner seal.
func establishmentEvent(event map[string]interface{}) bool {
	switch t, _ := event["t"].(string); t {
	case "icp", "dip", "rot", "drt":
		return true
	}
	return false
}

// OwnerSetsByEvent returns, for each event of a key log in order, the owner
// set in force once it is applied, in the order last recorded.
//
// The inception decides WHETHER the identity is owned, and by whom to begin
// with — one party or several. Subsequent owner anchors decide by whom from
// then on: an event that carries none leaves the set as it was. An identity
// whose inception names no owner has an empty set at every event no matter
// what later events say.
func OwnerSetsByEvent(kel []map[string]interface{}) ([][]string, error) {
	if len(kel) == 0 {
		return nil, fmt.Errorf("no key events to read an owner from")
	}
	inception := kel[0]
	if t, _ := inception["t"].(string); t != "icp" && t != "dip" {
		return nil, fmt.Errorf("the first event is %q, not an inception", t)
	}

	// EVERY owner named at inception, not just the first.
	//
	// An identity may be created already answering to more than one party. An
	// identity created for a child answers to whoever holds guardianship, and
	// that is frequently two people rather than one; anything created jointly is
	// the same. Reading only the first seal would silently drop the others, and
	// the identity would go on believing it answered to a smaller set than its
	// own inception event says — with nothing to indicate the difference.
	owners, found, err := OwnerSetFromEvent(inception)
	if err != nil {
		return nil, err
	}
	sets := make([][]string, len(kel))
	if !found {
		// Unowned at inception. Nothing later can change that, and this is also
		// the ordinary answer for an identity that needs no separate anchor
		// because its inception already names a delegator.
		return sets, nil
	}
	sets[0] = owners
	// Later events, newest last, so the final owner anchor wins. Read forwards
	// rather than backwards from the end: an event that is not an owner change
	// must not shadow one, and reading in order is how a log is meant to be
	// read.
	for i, event := range kel[1:] {
		set, found, err := OwnerSetFromEvent(event)
		if err != nil {
			return nil, err
		}
		if found {
			owners = set
		}
		sets[i+1] = owners
	}
	return sets, nil
}

// OwnersFromKEL returns the current owner set, in the order last recorded:
// the last of OwnerSetsByEvent.
func OwnersFromKEL(kel []map[string]interface{}) ([]string, error) {
	sets, err := OwnerSetsByEvent(kel)
	if err != nil {
		return nil, err
	}
	return sets[len(sets)-1], nil
}
