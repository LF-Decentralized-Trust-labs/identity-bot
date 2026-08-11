package server

import "testing"

func icpWithOwner(owner string) map[string]interface{} {
	e := map[string]interface{}{"t": "icp", "i": "EORG"}
	if owner != "" {
		e["a"] = []interface{}{map[string]interface{}{"i": owner, "s": "0", "d": owner}}
	}
	return e
}

func rotWithOwners(owners ...string) map[string]interface{} {
	seals := []interface{}{}
	for _, o := range owners {
		seals = append(seals, map[string]interface{}{"i": o, "s": "0", "d": o})
	}
	return map[string]interface{}{"t": "rot", "a": seals}
}

// An identity outliving the arrangement it was created under is ordinary, so the
// set has to be able to change.
func TestOwnersCanBeAddedByRotation(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		rotWithOwners("EFOUNDER", "ESECOND"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 || owners[0] != "EFOUNDER" || owners[1] != "ESECOND" {
		t.Errorf("owners are %v", owners)
	}
}

// Bought out, resigned, removed. The log records it and the current set is what
// the last owner event says.
func TestAnOwnerCanBeRemovedByRotation(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		rotWithOwners("EFOUNDER", "ESECOND"),
		rotWithOwners("ESECOND"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "ESECOND" {
		t.Errorf("owners are %v — the founder should be gone", owners)
	}
}

// THE RULE THAT KEEPS THIS SAFE. An identity founded without an owner can never
// acquire one, because that is exactly the silent claim of ownership the anchor
// exists to make impossible. Founded unowned means unowned forever.
func TestAnUnownedIdentityCannotAcquireAnOwnerLater(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner(""),
		rotWithOwners("EOPPORTUNIST"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 0 {
		t.Fatalf("an unowned identity acquired the owners %v after the fact", owners)
	}
}

// An identity answering to nobody is the state this whole mechanism exists to
// make unreachable, so it must not be reachable by rotating to an empty set
// either.
func TestAnIdentityCannotRotateItselfToHavingNoOwners(t *testing.T) {
	_, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		{"t": "rot", "a": []interface{}{map[string]interface{}{"i": "", "s": "0", "d": ""}}},
	})
	if err == nil {
		t.Fatal("an identity rotated itself to having no owner")
	}
}

// Events that are not owner changes must not shadow the set. A key rotation
// that says nothing about ownership changes nothing about ownership.
func TestOrdinaryEventsDoNotDisturbTheOwners(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		rotWithOwners("EFOUNDER", "ESECOND"),
		{"t": "rot"},
		{"t": "ixn", "a": []interface{}{map[string]interface{}{"i": "ESOMETHING", "r": "delegation"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 {
		t.Errorf("an unrelated event changed the owners: %v", owners)
	}
}

// The same owner twice would count twice towards any threshold, which is how
// one person becomes a quorum.
func TestAnOwnerNamedTwiceCountsOnce(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		rotWithOwners("ESECOND", "ESECOND", "ETHIRD"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 {
		t.Errorf("owners are %v — a repeat should not count twice", owners)
	}
}

// The founder is still the founder, and an identity with no rotations reads the
// same as it always did.
func TestAFreshIdentityReadsItsFounder(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{icpWithOwner("EFOUNDER")})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "EFOUNDER" {
		t.Errorf("owners are %v", owners)
	}
}

// Several owners from the very start.
//
// An identity created for a child answers to whoever holds guardianship, and
// that is frequently two people rather than one; anything created jointly is the
// same shape. Reading only the first seal dropped the rest silently, and the
// identity went on believing it answered to a smaller set than its own inception
// event said — with nothing to indicate the difference.
func TestAnIdentityCanBeCreatedAlreadyOwnedBySeveral(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		{"t": "icp", "i": "ECHILD", "a": []interface{}{
			map[string]interface{}{"i": "EGUARDIAN-ONE", "s": "0", "d": "EGUARDIAN-ONE"},
			map[string]interface{}{"i": "EGUARDIAN-TWO", "s": "0", "d": "EGUARDIAN-TWO"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 {
		t.Fatalf("read %d of 2 owners named at inception: %v", len(owners), owners)
	}
	if owners[0] != "EGUARDIAN-ONE" || owners[1] != "EGUARDIAN-TWO" {
		t.Errorf("owners are %v", owners)
	}
}

// And such an identity can still change hands — a guardianship that ends is a
// rotation like any other.
func TestAJointlyOwnedIdentityCanStillRotate(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		{"t": "icp", "i": "ECHILD", "a": []interface{}{
			map[string]interface{}{"i": "EGUARDIAN-ONE", "s": "0", "d": "EGUARDIAN-ONE"},
			map[string]interface{}{"i": "EGUARDIAN-TWO", "s": "0", "d": "EGUARDIAN-TWO"},
		}},
		rotWithOwners("ETHEMSELVES"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "ETHEMSELVES" {
		t.Errorf("owners are %v — guardianship should have ended", owners)
	}
}

// An owner seal and a credential issuance's seal are now the SAME SHAPE.
//
// The role label that used to tell them apart is gone: it was not a KERI seal,
// and an event carrying it could not be parsed by other implementations at all.
// What replaces it is position — only an establishment event can name owners.
//
// This is the case that rule exists for. An interaction anchoring a registry, a
// credential issuance or a delegation approval carries an event seal naming
// some other identity at position zero, which is indistinguishable from an
// owner seal by shape alone. Without the establishment-only rule, issuing a
// credential would silently reassign the organisation to that credential.
func TestAnInteractionsSealIsNotAnOwnerChange(t *testing.T) {
	const issuance = "EACDC-CREDENTIAL-JUST-ISSUED"
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		{"t": "ixn", "a": []interface{}{
			map[string]interface{}{"i": issuance, "s": "0", "d": issuance},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "EFOUNDER" {
		t.Fatalf("issuing a credential reassigned the identity: owners are %v", owners)
	}
}

// Break-glass recovery anchors a DIGEST seal in a rotation. A different shape
// from an owner seal, so the two cannot be confused however the log is read —
// which is what makes the establishment-only rule safe for rotations.
func TestARecoveryAnchorInARotationIsNotAnOwnerChange(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		{"t": "rot", "a": []interface{}{
			map[string]interface{}{"d": "ENEW-ROOT-INCEPTION-SAID"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "EFOUNDER" {
		t.Fatalf("a recovery authorisation changed the owners: %v", owners)
	}
}
