package server

import (
	"strings"
	"testing"
)

func inception(seals ...map[string]interface{}) []map[string]interface{} {
	event := map[string]interface{}{"t": "icp", "s": "0", "i": "EOrg"}
	if len(seals) > 0 {
		raw := make([]interface{}, 0, len(seals))
		for _, s := range seals {
			raw = append(raw, s)
		}
		event["a"] = raw
	}
	return []map[string]interface{}{event}
}

// The ordinary case: an organisation names its owner where anybody can read it.
func TestTheOwnerIsReadFromTheInception(t *testing.T) {
	owner, err := ownerFromKEL(inception(ownerAnchorSeal("EFounder")))
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("owner read as %q, want EFounder", owner)
	}
}

// A person's own agent is a delegated identity — its delegator is already named
// in the event, so it carries no separate owner seal. Requiring one would break
// every individual agent.
func TestAnIdentityWithNoOwnerSealIsNotAnError(t *testing.T) {
	owner, err := ownerFromKEL(inception())
	if err != nil {
		t.Fatalf("an identity with no owner seal was treated as broken: %v", err)
	}
	if owner != "" {
		t.Errorf("invented an owner: %q", owner)
	}
}

// Only the inception is consulted. A later event must not be able to introduce
// an owner where there was none — that would reintroduce the silent overwrite
// the anchor exists to remove.
func TestALaterEventCannotIntroduceAnOwner(t *testing.T) {
	kel := inception()
	kel = append(kel, map[string]interface{}{
		"t": "ixn", "s": "1", "i": "EOrg",
		"a": []interface{}{ownerAnchorSeal("EOpportunist")},
	})

	owner, err := ownerFromKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "" {
		t.Errorf("a later event claimed ownership of an unowned identity: %q", owner)
	}
}

// Nor may a later event replace one. Changing owners is a rotation ceremony
// with its own rules, not a seal somebody appends.
func TestALaterEventCannotReplaceTheOwner(t *testing.T) {
	kel := inception(ownerAnchorSeal("EFounder"))
	kel = append(kel, map[string]interface{}{
		"t": "ixn", "s": "1", "i": "EOrg",
		"a": []interface{}{ownerAnchorSeal("EUsurper")},
	})

	owner, err := ownerFromKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("the founder was displaced by a later event: %q", owner)
	}
}

// A seal claiming the owner role and naming nobody is malformed. Skipping it
// would make a broken organisation look like an unowned one, and those need
// different answers.
func TestAnOwnerSealNamingNobodyIsAnError(t *testing.T) {
	_, err := ownerFromKEL(inception(map[string]interface{}{"r": "owner"}))
	if err == nil {
		t.Fatal("a malformed owner seal passed as no owner at all")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("the error should say what was wrong, got: %v", err)
	}
}

// Other seals are none of this function's business.
func TestUnrelatedSealsAreIgnored(t *testing.T) {
	owner, err := ownerFromKEL(inception(
		map[string]interface{}{"i": "ESomething", "r": "something-else"},
		ownerAnchorSeal("EFounder"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("owner read as %q among unrelated seals", owner)
	}
}

func TestAnEmptyLogHasNoOwnerToRead(t *testing.T) {
	if _, err := ownerFromKEL(nil); err == nil {
		t.Error("an empty log answered a question it cannot answer")
	}
}

// The first event has to actually be an inception, or the identity is not what
// it claims and nothing after it can be trusted either.
func TestALogNotStartingWithAnInceptionIsRefused(t *testing.T) {
	_, err := ownerFromKEL([]map[string]interface{}{
		{"t": "ixn", "s": "0", "i": "EOrg"},
	})
	if err == nil {
		t.Error("a log beginning with an interaction event was accepted")
	}
}

// Written in one place, read in one place. If these disagree, ownership becomes
// unreadable in a way no single test would catch.
func TestTheSealShapeRoundTrips(t *testing.T) {
	seal := ownerAnchorSeal("EFounder")
	owner, err := ownerFromKEL(inception(seal))
	if err != nil || owner != "EFounder" {
		t.Fatalf("the seal this code writes is not the seal it reads: %v %q", err, owner)
	}
	if seal["r"] != ownerRole {
		t.Errorf("the seal role is %q, not the constant both sides use", seal["r"])
	}
}
