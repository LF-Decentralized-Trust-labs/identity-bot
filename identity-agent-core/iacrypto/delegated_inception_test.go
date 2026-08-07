package iacrypto

import (
	"bytes"
	"encoding/json"
	"testing"
)

func asEvent(t *testing.T, r *HybridInceptionResult) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(r.InceptionEvent)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A sealed machine holds keys it generated itself, and its identifier commits
// to them. That is what lets it decrypt without ever being given the owner's
// seed.
func TestADelegatedIdentityCommitsToItsOwnKeys(t *testing.T) {
	m := SyntheticHybridKeyMaterial(21)
	const owner = "EOWNER-AID"

	box, err := BuildHybridDelegatedInception(m, owner)
	if err != nil {
		t.Fatal(err)
	}
	if box.Delegator != owner {
		t.Errorf("delegator is %q, want %q — nothing records who this identity acts for", box.Delegator, owner)
	}

	event := asEvent(t, box)
	if event["t"] != "dip" {
		t.Errorf("event type is %v, want dip", event["t"])
	}
	if event["di"] != owner {
		t.Errorf("the event does not name its delegator: %v", event["di"])
	}

	x, kem, err := AnchoredAgreementKeys(event)
	if err != nil {
		t.Fatalf("a delegated inception did not yield its anchored keys: %v", err)
	}
	if !bytes.Equal(x, m.X25519AgreementRaw) || !bytes.Equal(kem, m.MLKEM768EncapRaw) {
		t.Error("the anchored keys are not the ones the machine generated")
	}
}

// The delegator is inside the event the identifier is derived from, so it
// cannot be changed afterwards without becoming a different identity. If it
// could, an operator could take an identity the owner vouched for and re-point
// it at themselves.
func TestTheDelegatorCannotBeChangedWithoutChangingTheIdentity(t *testing.T) {
	m := SyntheticHybridKeyMaterial(21)
	mine, err := BuildHybridDelegatedInception(m, "EOWNER-AID")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := BuildHybridDelegatedInception(m, "EOPERATOR-AID")
	if err != nil {
		t.Fatal(err)
	}
	if mine.AID == theirs.AID {
		t.Fatal("the same keys under two different delegators produced one identifier, " +
			"so the delegation is not part of what the identifier commits to")
	}
}

// A delegated identity is not the same identity as a standalone one with the
// same keys — otherwise a machine could present itself as acting alone.
func TestADelegatedIdentityIsNotTheStandaloneOne(t *testing.T) {
	m := SyntheticHybridKeyMaterial(21)
	alone, err := BuildHybridInception(m)
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := BuildHybridDelegatedInception(m, "EOWNER-AID")
	if err != nil {
		t.Fatal(err)
	}
	if alone.AID == delegated.AID {
		t.Fatal("delegated and standalone inceptions of the same keys share an identifier")
	}
	if delegated.Delegator == "" || alone.Delegator != "" {
		t.Error("the delegator is not reported consistently")
	}
	// An ordinary inception must not have gained the field.
	if _, present := asEvent(t, alone)["di"]; present {
		t.Error("a standalone inception carries a delegator field, which would change " +
			"every identifier already created")
	}
}

// An identity that acts for somebody must say who. Silence here would produce
// an identifier that looks delegated and names nobody.
func TestADelegatedInceptionMustNameItsDelegator(t *testing.T) {
	if _, err := BuildHybridDelegatedInception(SyntheticHybridKeyMaterial(1), ""); err == nil {
		t.Fatal("a delegated inception was built with no delegator")
	}
}
