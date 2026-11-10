package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// One witness is one receipt per event, however often it arrives: a repeat
// must not move the count, or a single witness could reach the threshold alone.
func TestOneWitnessCannotReachTheThresholdAlone(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const said = "EOnceEvent0123456789ABCDEFGHIJKLMNOPQRSTUVWX"
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: "ERoot", State: FinalizePending, Threshold: 2, StartedAt: now, UpdatedAt: now})

	for i := 0; i < 5; i++ {
		s.onReceipt(said, "EWitnessOne", "", nil, nil)
	}
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("one witness counted %d times, state %s", f.ReceiptCount, f.State)
	}
	s.onReceipt(said, "EWitnessTwo", "", nil, nil)
	if f, _ = s.Store.GetFinalization(said); f.ReceiptCount != 2 || f.State != FinalizeFinalized {
		t.Fatalf("a second witness was not counted: %d, %s", f.ReceiptCount, f.State)
	}
}

// After a rotation the list in force is the new one, which only the log can
// say, so the broadcast paths read it from there rather than from the event.
func TestTheListAfterARotationIsKnownToTheBroadcastPaths(t *testing.T) {
	s, _ := testService(t)
	wk := func() string {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return iacrypto.NonTransferableAIDQB64(pub)
	}
	w1, w2, w3 := wk(), wk(), wk()
	a, b, c := newOwner(t), newOwner(t), newOwner(t)
	_ = c
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(t, a.now)}, NextDigests: []string{digest(t, a.next)},
		Derivation: "self-addressing", Witnesses: []string{w1, w2},
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv := parsed(t, icp)
	two := 2
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1,
		Keys: []string{pub(t, a.next)}, NextDigests: []string{digest(t, b.now)},
		PriorWitnesses: []string{w1, w2}, Cuts: []string{w1}, Adds: []string{w3}, Toad: &two,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.StoreKelEvent(KelEvent{
		SignerAID: icpEv.Identifier, SequenceNum: 0, EventSAID: icpEv.SAID,
		RawBytesB64: base64.StdEncoding.EncodeToString(icp),
	}); err != nil {
		t.Fatal(err)
	}

	// The event alone names no list, so what is read is the log's.
	want := []string{w2, w3}
	if got := s.designatedInForce(icpEv.Identifier, rot); !reflect.DeepEqual(got, want) {
		t.Fatalf("list after the rotation = %v, want %v", got, want)
	}
	// And the same once the rotation is stored.
	var rev map[string]interface{}
	_ = json.Unmarshal(rot, &rev)
	_ = s.Store.StoreKelEvent(KelEvent{
		SignerAID: icpEv.Identifier, SequenceNum: 1, EventSAID: eventSAID(rev),
		RawBytesB64: base64.StdEncoding.EncodeToString(rot),
	})
	if got := s.designatedInForce(icpEv.Identifier, rot); !reflect.DeepEqual(got, want) {
		t.Fatalf("list after the stored rotation = %v, want %v", got, want)
	}
	// An inception still names its own.
	if got := s.designatedInForce(icpEv.Identifier, icp); !reflect.DeepEqual(got, []string{w1, w2}) {
		t.Fatalf("inception list = %v", got)
	}
}
