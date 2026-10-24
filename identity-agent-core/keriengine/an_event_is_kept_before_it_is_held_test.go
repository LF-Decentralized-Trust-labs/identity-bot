package keriengine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

func newKey(t *testing.T) string {
	t.Helper()
	s, err := testSigner(true)
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
	if _, err := e.CreateDelegatedInceptionKept(pub, next, "rec", "root", nil, 0, func(drivers.KELKeep) error { return errors.New("disk full") }); err == nil {
		t.Fatal("a delegation that could not be kept was made")
	}
	if kel, _ := e.GetKel("root"); kel.EventCount != 1 {
		t.Fatalf("a failed keep advanced the delegator's log to %d events", kel.EventCount)
	}
	if _, err := e.GetKel("rec"); err == nil {
		t.Fatal("a failed keep left a delegated identity held")
	}
	var kept drivers.KELKeep
	d, err := e.CreateDelegatedInceptionKept(pub, next, "rec", "root", nil, 0, func(k drivers.KELKeep) error { kept = k; return nil })
	if err != nil {
		t.Fatal(err)
	}
	ixn, _ := base64.StdEncoding.DecodeString(d.DelegatorIxnRawBytesB64)
	dip, _ := base64.StdEncoding.DecodeString(d.RawBytesB64)
	if !bytes.Equal(kept.Raw, ixn) || !bytes.Equal(kept.Delegated, dip) {
		t.Fatal("the keep was not given the approval and the inception that were made")
	}
}

func aWitnessPrefix(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return iacrypto.NonTransferableAIDQB64(pub)
}

// A delegated identity can name the same witnesses as its delegator, and a
// reload keeps an identity's witnesses even when its last event is an
// interaction, which names none.
func TestWitnessesSurviveADelegationAndAReload(t *testing.T) {
	e := New()
	ws := []string{aWitnessPrefix(t), aWitnessPrefix(t), aWitnessPrefix(t)}
	if _, err := e.Incept(drivers.InceptionRequest{PublicKey: newKey(t), NextPublicKey: newKey(t), Name: "root", Witnesses: ws, Toad: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Interact("root", []interface{}{map[string]interface{}{"d": ws[0]}}); err != nil {
		t.Fatal(err)
	}
	kel, _ := e.GetKel("root")
	again := New()
	if _, err := again.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: kel.AID, KEL: kel.KEL, RawEventsB64: kel.RawEventsB64}); err != nil {
		t.Fatal(err)
	}
	got, toad, err := again.WitnessConfig(kel.AID)
	if err != nil || len(got) != 3 || toad != 2 {
		t.Fatalf("after a reload the identity names %v at %d", got, toad)
	}
	d, err := again.CreateDelegatedInceptionKept(newKey(t), newKey(t), "rec", kel.AID, got, toad, func(drivers.KELKeep) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	dip, _ := base64.StdEncoding.DecodeString(d.RawBytesB64)
	ev, err := keri.ParseEvent(dip)
	if err != nil || len(ev.Witnesses) != 3 || !ev.HasTOAD || ev.TOAD != 2 {
		t.Fatalf("the delegated inception does not name the delegator's witnesses: %+v %v", ev, err)
	}
}
