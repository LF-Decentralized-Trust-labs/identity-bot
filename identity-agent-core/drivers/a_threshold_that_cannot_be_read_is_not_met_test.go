package drivers

import (
	"bytes"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// rotatedLog is an inception naming w1 and w2 with a threshold of one, then
// a rotation that cuts w1 and adds w3, keeping a threshold of one.
type rotatedLog struct {
	icp, rot         []byte
	icpSAID, rotSAID string
	w1, w2, w3       string
	sign1, sign3     func(string) string
}

func newRotatedLog(t *testing.T) rotatedLog {
	t.Helper()
	var l rotatedLog
	l.w1, l.sign1 = witness(t)
	l.w2, _ = witness(t)
	l.w3, l.sign3 = witness(t)
	k0, _ := keri.GenerateSigner(true)
	k1, _ := keri.GenerateSigner(true)
	k2, _ := keri.GenerateSigner(true)
	pub0, _ := k0.PublicKey()
	pub1, _ := k1.PublicKey()
	pub2, _ := k2.PublicKey()
	d1, _ := keri.NextDigest(pub1)
	d2, _ := keri.NextDigest(pub2)
	one := 1
	var err error
	l.icp, err = keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub0}, NextDigests: []string{d1}, Witnesses: []string{l.w1, l.w2}, Toad: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	icp, _ := keri.ParseEvent(l.icp)
	l.icpSAID = icp.SAID
	l.rot, err = keri.BuildRotation(keri.RotationInput{
		Prefix: icp.Identifier, Keys: []string{pub1}, PriorSAID: icp.SAID, SN: 1, NextDigests: []string{d2},
		PriorWitnesses: []string{l.w1, l.w2}, Cuts: []string{l.w1}, Adds: []string{l.w3}, Toad: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	rot, _ := keri.ParseEvent(l.rot)
	l.rotSAID = rot.SAID
	return l
}

func metAt(t *testing.T, events [][]byte, receipts map[string][]WitnessReceipt) map[int]bool {
	t.Helper()
	report, _ := witnessingReport(ValidateKELInput{RawEvents: events, Receipts: receipts})
	out := map[int]bool{}
	for _, row := range report {
		out[row.SequenceNumber] = row.Met
	}
	return out
}

// An event is judged by the witnesses at its own place in the log: one
// rotated out no longer counts, one rotated in does.
func TestARotatedEventIsJudgedByItsOwnWitnesses(t *testing.T) {
	l := newRotatedLog(t)
	events := [][]byte{l.icp, l.rot}
	byOld := map[string][]WitnessReceipt{
		l.icpSAID: {{WitnessAID: l.w1, CesrSignature: l.sign1(l.icpSAID)}},
		l.rotSAID: {{WitnessAID: l.w1, CesrSignature: l.sign1(l.rotSAID)}},
	}
	met := metAt(t, events, byOld)
	if !met[0] {
		t.Error("the inception, receipted by a witness it names, was not met")
	}
	if met[1] {
		t.Error("the rotation was met by a witness it cut")
	}
	byNew := map[string][]WitnessReceipt{
		l.rotSAID: {{WitnessAID: l.w3, CesrSignature: l.sign3(l.rotSAID)}},
	}
	if met := metAt(t, events, byNew); !met[1] {
		t.Error("the rotation, receipted by the witness it added, was not met")
	}
}

// Where a threshold cannot be read, nothing from there on is met. It used to
// inherit the previous threshold, which at inception is zero.
func TestAnEventWhoseThresholdCannotBeReadIsNotMet(t *testing.T) {
	l := newRotatedLog(t)
	receipts := map[string][]WitnessReceipt{
		l.icpSAID: {{WitnessAID: l.w1, CesrSignature: l.sign1(l.icpSAID)}},
		l.rotSAID: {{WitnessAID: l.w3, CesrSignature: l.sign3(l.rotSAID)}},
	}
	if met := metAt(t, [][]byte{l.icp, l.rot}, receipts); !met[0] || !met[1] {
		t.Fatalf("the intact log was not met: %v", met)
	}
	without := func(raw, field []byte) []byte {
		out := bytes.Replace(raw, field, nil, 1)
		if bytes.Equal(out, raw) {
			t.Fatalf("no %s to remove", field)
		}
		return out
	}

	// An inception with no witness threshold, and so none of what follows.
	noBT := without(l.icp, []byte(`"bt":"1",`))
	if met := metAt(t, [][]byte{noBT, l.rot}, receipts); met[0] || met[1] {
		t.Errorf("a log whose inception states no witness threshold was met: %v", met)
	}
	// A rotation with no witness threshold.
	if met := metAt(t, [][]byte{l.icp, without(l.rot, []byte(`"bt":"1",`))}, receipts); !met[0] || met[1] {
		t.Errorf("a rotation stating no witness threshold: %v", met)
	}
	// A threshold too large to hold.
	huge := bytes.Replace(l.icp, []byte(`"bt":"1"`), []byte(`"bt":"ffffffffff"`), 1)
	if met := metAt(t, [][]byte{huge, l.rot}, receipts); met[0] || met[1] {
		t.Errorf("a log whose inception threshold overflows was met: %v", met)
	}
	// A threshold in a second spelling does not parse, and neither the event
	// nor anything after it is met.
	padded := bytes.Replace(l.icp, []byte(`"bt":"1"`), []byte(`"bt":"01"`), 1)
	if met := metAt(t, [][]byte{padded, l.rot}, receipts); met[0] || met[1] {
		t.Errorf("a log whose inception threshold is respelled was met: %v", met)
	}
	// An event that does not parse at all.
	if met := metAt(t, [][]byte{l.icp, []byte("not an event"), l.rot}, receipts); !met[0] || met[1] {
		t.Errorf("a rotation after an unreadable event: %v", met)
	}
}
