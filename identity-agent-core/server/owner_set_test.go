package server

import "testing"

func icpWithOwner(owner string) map[string]interface{} {
	e := map[string]interface{}{"t": "icp", "i": "EORG"}
	if owner != "" {
		e["a"] = []interface{}{map[string]interface{}{"i": owner, "r": "owner"}}
	}
	return e
}

func rotWithOwners(owners ...string) map[string]interface{} {
	seals := []interface{}{}
	for _, o := range owners {
		seals = append(seals, map[string]interface{}{"i": o, "r": "owner"})
	}
	return map[string]interface{}{"t": "rot", "a": seals}
}

// A company outliving the arrangement it was founded under is the ordinary life
// of a company, so the set has to be able to change.
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

// THE RULE THAT KEEPS THIS SAFE. An organisation founded without an owner can
// never acquire one, because that is exactly the silent claim of ownership the
// anchor exists to make impossible. Founded unowned means unowned forever.
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

// An organisation answering to nobody is the state this whole mechanism exists
// to make unreachable, so it must not be reachable by rotating to an empty set
// either.
func TestAnOrganisationCannotRotateItselfToHavingNoOwners(t *testing.T) {
	_, err := ownersFromKEL([]map[string]interface{}{
		icpWithOwner("EFOUNDER"),
		{"t": "rot", "a": []interface{}{map[string]interface{}{"r": "owner"}}},
	})
	if err == nil {
		t.Fatal("an organisation rotated itself to having no owner")
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
func TestAFreshOrganisationReadsItsFounder(t *testing.T) {
	owners, err := ownersFromKEL([]map[string]interface{}{icpWithOwner("EFOUNDER")})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "EFOUNDER" {
		t.Errorf("owners are %v", owners)
	}
}
