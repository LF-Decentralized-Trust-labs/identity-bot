package keriengine

import (
	"errors"
	"testing"

	"identity-agent-core/drivers"
)

// A delegated inception prepared adds nothing and holds nothing; appended as
// prepared it adds the delegator's approval and holds the identity, and the
// same preparation cannot be appended twice.
func TestADelegationIsPreparedThenAppendedAsPrepared(t *testing.T) {
	e := New()
	rootPub, rootNext, _ := keys(t)
	root, err := e.CreateInceptionNamed(rootPub, rootNext, "root")
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentNext, _ := keys(t)
	p, err := e.PrepareDelegatedInception("root", agentPub, agentNext, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 1 {
		t.Fatalf("preparing added to the delegator's log: %d events", kel.EventCount)
	}
	if _, err := e.GetKel("agent"); err == nil {
		t.Fatal("preparing held the delegated identity")
	}
	got, err := e.AppendPreparedDelegation("root", "agent", p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.AID != p.AID || got.Said != p.DipSAID || got.DelegatorAID != root.AID {
		t.Fatalf("appended %+v, prepared %+v", got, p)
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 2 {
		t.Fatalf("the delegator's log has %d events, want its inception and the approval", kel.EventCount)
	}
	if _, err := e.AppendPreparedDelegation("root", "agent", p, nil); !errors.Is(err, drivers.ErrStalePreparation) {
		t.Fatalf("the same preparation appended twice: %v", err)
	}
}

// An interaction that does not approve the inception it is prepared with is
// not appended.
func TestADelegationWhoseApprovalIsAnotherEventIsRefused(t *testing.T) {
	e := New()
	rootPub, rootNext, _ := keys(t)
	if _, err := e.CreateInceptionNamed(rootPub, rootNext, "root"); err != nil {
		t.Fatal(err)
	}
	aPub, aNext, _ := keys(t)
	bPub, bNext, _ := keys(t)
	a, err := e.PrepareDelegatedInception("root", aPub, aNext, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.PrepareDelegatedInception("root", bPub, bNext, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.IxnRaw = b.IxnRaw
	if _, err := e.AppendPreparedDelegation("root", "a", a, nil); err == nil {
		t.Fatal("an approval of another inception was appended")
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 1 {
		t.Fatalf("a refused approval was added: %d events", kel.EventCount)
	}
}
