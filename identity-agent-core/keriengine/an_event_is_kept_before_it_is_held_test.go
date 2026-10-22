package keriengine

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

func newKey(t *testing.T) string {
	t.Helper()
	s, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := s.PublicKey()
	return p
}

// An interaction whose keep fails is not made: the log stays where it was, so
// the next interaction takes the same place. One whose keep succeeds is
// exactly the event the keep was given.
func TestAnInteractionIsMadeOnlyOnceKept(t *testing.T) {
	e := New()
	root, err := e.CreateInceptionNamed(newKey(t), newKey(t), "root")
	if err != nil {
		t.Fatal(err)
	}
	seal := []interface{}{map[string]interface{}{"d": root.AID}}
	if _, err := e.InteractKept("root", seal, func(drivers.KELKeep) error { return errors.New("disk full") }); err == nil {
		t.Fatal("an interaction that could not be kept was made")
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 1 {
		t.Fatalf("a failed keep left the log at %d events", kel.EventCount)
	}
	var kept drivers.KELKeep
	ixn, err := e.InteractKept("root", seal, func(k drivers.KELKeep) error { kept = k; return nil })
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ixn.RawBytesB64)
	if kept.AID != root.AID || kept.SN != 1 || !bytes.Equal(kept.Raw, raw) {
		t.Fatalf("the keep was given %s %d, not the interaction made", kept.AID, kept.SN)
	}
}

// A delegation whose keep fails approves nothing: the delegator's log is
// unchanged and no delegated identity is held.
func TestADelegationIsMadeOnlyOnceKept(t *testing.T) {
	e := New()
	if _, err := e.CreateInceptionNamed(newKey(t), newKey(t), "root"); err != nil {
		t.Fatal(err)
	}
	pub, next := newKey(t), newKey(t)
	if _, err := e.CreateDelegatedInceptionKept(pub, next, "rec", "root", func(drivers.KELKeep) error { return errors.New("disk full") }); err == nil {
		t.Fatal("a delegation that could not be kept was made")
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 1 {
		t.Fatalf("a failed keep advanced the delegator's log to %d events", kel.EventCount)
	}
	if _, err := e.GetKel("rec"); err == nil {
		t.Fatal("a failed keep left a delegated identity held")
	}
	var kept drivers.KELKeep
	d, err := e.CreateDelegatedInceptionKept(pub, next, "rec", "root", func(k drivers.KELKeep) error { kept = k; return nil })
	if err != nil {
		t.Fatal(err)
	}
	ixn, _ := base64.StdEncoding.DecodeString(d.DelegatorIxnRawBytesB64)
	dip, _ := base64.StdEncoding.DecodeString(d.RawBytesB64)
	if !bytes.Equal(kept.Raw, ixn) || !bytes.Equal(kept.Delegated, dip) {
		t.Fatal("the keep was not given the approval and the inception that were made")
	}
}
