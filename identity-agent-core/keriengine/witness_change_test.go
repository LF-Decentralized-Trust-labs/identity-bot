package keriengine

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

func witnessKey(t *testing.T) string {
	t.Helper()
	s, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func witnessesOf(t *testing.T, rawB64 string) *keri.Event {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// A witness set is fixed at inception and can only be amended by a rotation.
// Without this an identity can never drop a witness that has gone away, and its
// published list drifts permanently from who actually witnesses for it.
func TestAWitnessCanBeRemovedAndAnotherAddedByRotation(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	w1, w2, w3 := witnessKey(t), witnessKey(t), witnessKey(t)

	icp, err := e.Incept(drivers.InceptionRequest{
		PublicKey: pub, NextPublicKey: next, Name: "alice",
		Witnesses: []string{w1, w2}, Toad: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := witnessesOf(t, icp.RawBytesB64); len(got.Witnesses) != 2 {
		t.Fatalf("founded with %v", got.Witnesses)
	}

	third, _, _ := keys(t)
	rot, err := e.Rotate(drivers.RotationRequest{
		Name: "alice", NewPublicKey: next, NewNextPublicKey: third,
		CutWitnesses: []string{w1}, AddWitnesses: []string{w3},
	})
	if err != nil {
		t.Fatal(err)
	}

	ev := witnessesOf(t, rot.RawBytesB64)
	if len(ev.WitnessCut) != 1 || ev.WitnessCut[0] != w1 {
		t.Fatalf("the rotation does not record the removal: cut=%v", ev.WitnessCut)
	}
	if len(ev.WitnessAdd) != 1 || ev.WitnessAdd[0] != w3 {
		t.Fatalf("the rotation does not record the addition: add=%v", ev.WitnessAdd)
	}

	// What the engine believes must match what the event says, or the agent
	// disagrees with its own published log.
	kel, err := e.GetKel("alice")
	if err != nil {
		t.Fatal(err)
	}
	raws := make([][]byte, 0, len(kel.RawEventsB64))
	for _, b := range kel.RawEventsB64 {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := keri.ValidateKEL(raws); err != nil {
		t.Fatalf("the log does not validate after a witness change: %v", err)
	}

	// The set now in force, as a validator computes it: w2 and w3, not w1.
	res, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{AID: icp.AID, RawEvents: raws})
	if err != nil {
		t.Fatal(err)
	}
	last := res.WitnessDetail[len(res.WitnessDetail)-1]
	if last.Witnesses != 2 {
		t.Fatalf("after the change %d witnesses are designated, expected 2", last.Witnesses)
	}
	// The set in force at the end of the log — w2 and w3, not w1.
	for _, w := range res.Witnesses {
		if w == w1 {
			t.Fatal("the removed witness is still designated")
		}
	}
}

// A witness that could never be checked must not be added, for the same reason
// it cannot be designated at inception: an event is permanent.
func TestATransferableWitnessCannotBeAddedByRotation(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.Incept(drivers.InceptionRequest{
		PublicKey: pub, NextPublicKey: next, Name: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	transferable, third, _ := keys(t)

	if _, err := e.Rotate(drivers.RotationRequest{
		Name: "alice", NewPublicKey: next, NewNextPublicKey: third,
		AddWitnesses: []string{transferable},
	}); err == nil {
		t.Fatal("a transferable identifier was added as a witness")
	}
}

// An ordinary rotation leaves the witness set alone. A key change is not a
// statement about who observes the identity.
func TestAnOrdinaryRotationDoesNotDisturbTheWitnesses(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	w1 := witnessKey(t)
	if _, err := e.Incept(drivers.InceptionRequest{
		PublicKey: pub, NextPublicKey: next, Name: "alice",
		Witnesses: []string{w1}, Toad: 1,
	}); err != nil {
		t.Fatal(err)
	}
	third, _, _ := keys(t)
	rot, err := e.RotateAid("alice", next, third)
	if err != nil {
		t.Fatal(err)
	}
	ev := witnessesOf(t, rot.RawBytesB64)
	if len(ev.WitnessCut) != 0 || len(ev.WitnessAdd) != 0 {
		t.Fatalf("a plain rotation changed the witnesses: cut=%v add=%v",
			ev.WitnessCut, ev.WitnessAdd)
	}
}
