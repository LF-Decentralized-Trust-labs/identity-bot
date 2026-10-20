package keriengine

import (
	"testing"

	"identity-agent-core/drivers"
)

// After a restart a delegated identity is held again from its keys, and the
// delegator's log is left exactly as it was stored: no second approval.
func TestADelegatedIdentityIsReinstatedWithoutASecondApproval(t *testing.T) {
	e := New()
	rootPub, rootNext, _ := keys(t)
	root, err := e.CreateInceptionNamed(rootPub, rootNext, "root")
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentNext, _ := keys(t)
	made, err := e.CreateDelegatedInception(agentPub, agentNext, "Research assistant", "root")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := e.GetKel("root")
	if err != nil {
		t.Fatal(err)
	}

	// A restart: a fresh engine holding only the delegator, reloaded from storage.
	restarted := New()
	if _, err := restarted.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID: root.AID, PublicKey: root.PublicKey, NextKeyDigest: root.NextKeyDigest,
		KEL: stored.KEL, RawEventsB64: stored.RawEventsB64,
	}); err != nil {
		t.Fatal(err)
	}

	back, err := restarted.ReinstateDelegatedIdentity(agentPub, agentNext, "Research assistant", root.AID)
	if err != nil {
		t.Fatalf("reinstating an approved delegated identity: %v", err)
	}
	if back.AID != made.AID {
		t.Fatalf("reinstated as %s, but it was created as %s", back.AID, made.AID)
	}
	after, err := restarted.GetKel(root.AID)
	if err != nil {
		t.Fatal(err)
	}
	if after.EventCount != stored.EventCount {
		t.Fatalf("the delegator's log went from %d to %d events: reinstating approved it again",
			stored.EventCount, after.EventCount)
	}
	agentKel, err := restarted.GetKel("Research assistant")
	if err != nil || agentKel.AID != made.AID || agentKel.EventCount != 1 {
		t.Fatalf("the reinstated identity's own log is wrong: %+v, %v", agentKel, err)
	}
}

// An identity the delegator never approved is refused, not reinstated: holding
// it would publish an authority nothing granted.
func TestAnUnapprovedDelegatedIdentityIsNotReinstated(t *testing.T) {
	e := New()
	rootPub, rootNext, _ := keys(t)
	if _, err := e.CreateInceptionNamed(rootPub, rootNext, "root"); err != nil {
		t.Fatal(err)
	}
	agentPub, agentNext, _ := keys(t)
	if _, err := e.ReinstateDelegatedIdentity(agentPub, agentNext, "stranger", "root"); err == nil {
		t.Fatal("an identity the delegator never approved was reinstated")
	}
	if _, err := e.GetKel("stranger"); err == nil {
		t.Fatal("a refused identity was held anyway")
	}
}

// A name already holding one delegated identity is not silently taken over by
// another: everything that looks identities up by name would then answer for
// the wrong one. The delegator's log is not advanced for the refused one.
func TestANameHoldingAnIdentityIsNotTakenByAnother(t *testing.T) {
	e := New()
	rootPub, rootNext, _ := keys(t)
	if _, err := e.CreateInceptionNamed(rootPub, rootNext, "root"); err != nil {
		t.Fatal(err)
	}
	aPub, aNext, _ := keys(t)
	if _, err := e.CreateDelegatedInception(aPub, aNext, "Research assistant", "root"); err != nil {
		t.Fatal(err)
	}
	before, _ := e.GetKel("root")
	bPub, bNext, _ := keys(t)
	if _, err := e.CreateDelegatedInception(bPub, bNext, "Research assistant", "root"); err == nil {
		t.Fatal("a second identity was held under a name that already held one")
	}
	after, _ := e.GetKel("root")
	if after.EventCount != before.EventCount {
		t.Fatal("the delegator approved an identity that was then refused")
	}
}
