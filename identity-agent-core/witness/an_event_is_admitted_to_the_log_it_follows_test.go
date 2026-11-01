package witness

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// owner is one signing key with the key that follows it.
type owner struct {
	now, next keri.Signer
}

func newOwner(t *testing.T) owner {
	t.Helper()
	now, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	next, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	return owner{now: now, next: next}
}

func pub(t *testing.T, s keri.Signer) string {
	t.Helper()
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func digest(t *testing.T, s keri.Signer) string {
	t.Helper()
	d, err := keri.NextDigest(pub(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// signAt is s's indexed signature over raw at the places given.
func signAt(t *testing.T, s keri.Signer, raw []byte, at keri.SignaturePlace) string {
	t.Helper()
	sig, err := s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	qb, err := keri.EncodeIndexedSignature(sig, at)
	if err != nil {
		t.Fatal(err)
	}
	return qb
}

// witnessFor is a witness service holding nothing yet, witnessing for whatever
// identity it is given.
func witnessFor(t *testing.T) *Service {
	t.Helper()
	s, _, _, _ := enrolled(t)
	return s
}

func witnessesFor(t *testing.T, s *Service, aid string) {
	t.Helper()
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: aid, WitnessingFor: true, BackendType: BackendDesktop,
	}); err != nil {
		t.Fatal(err)
	}
}

func mustReceive(t *testing.T, s *Service, aid string, raw []byte, sigs ...string) {
	t.Helper()
	if _, err := s.ReceiveSignedEvent(aid, raw, sigs); err != nil {
		t.Fatalf("the witness refused the event: %v", err)
	}
}

func parsed(t *testing.T, raw []byte) *keri.Event {
	t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// A two-owner identity's rotation, whose keys sit in the other order from the
// commitments they open, carries 2A signatures naming both places. A witness
// receipts it, and keeps both signatures.
func TestATwoOwnerRotationWithDualIndexSignaturesIsReceipted(t *testing.T) {
	s := witnessFor(t)
	a, b := newOwner(t), newOwner(t)
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pub(t, a.now), pub(t, b.now)},
		NextDigests: []string{digest(t, a.next), digest(t, b.next)},
		Isith:       json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv := parsed(t, icp)
	witnessesFor(t, s, icpEv.Identifier)
	mustReceive(t, s, icpEv.Identifier, icp,
		signAt(t, a.now, icp, keri.SamePlace(0)), signAt(t, b.now, icp, keri.SamePlace(1)))

	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, PriorSAID: icpEv.SAID, SN: 1,
		Keys:        []string{pub(t, b.next), pub(t, a.next)},
		NextDigests: []string{digest(t, b.now), digest(t, a.now)},
		Isith:       json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	bSig := signAt(t, b.next, rot, keri.SignaturePlace{Index: 0, Ondex: 1})
	aSig := signAt(t, a.next, rot, keri.SignaturePlace{Index: 1, Ondex: 0})
	if len(bSig) != 92 || len(aSig) != 92 {
		t.Fatalf("the signatures are not in the dual-index form: %d and %d characters",
			len(bSig), len(aSig))
	}
	mustReceive(t, s, icpEv.Identifier, rot, bSig, aSig)

	held, err := s.Store.GetKelEvents(icpEv.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 || len(held[1].Signatures) != 2 {
		t.Fatalf("the witness holds %d events, the rotation with %d signatures",
			len(held), len(held[len(held)-1].Signatures))
	}

	// One owner alone does not meet kt 2.
	solo, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: icpEv.Identifier, PriorSAID: parsed(t, rot).SAID, SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReceiveSignedEvent(icpEv.Identifier, solo,
		[]string{signAt(t, b.next, solo, keri.SamePlace(0))}); err == nil {
		t.Fatal("an interaction one of two owners signed was receipted")
	}
}

// identity is a one-key identity whose events a test builds.
type identity struct {
	t      *testing.T
	keys   []keri.Signer // the key at each generation
	gen    int
	prefix string
	saids  []string
}

func newIdentity(t *testing.T) (*identity, []byte, string) {
	t.Helper()
	k0, k1 := newOwner(t), newOwner(t)
	id := &identity{t: t, keys: []keri.Signer{k0.now, k1.now, k0.next, k1.next}}
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(t, id.keys[0])}, NextDigests: []string{digest(t, id.keys[1])},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := parsed(t, icp)
	id.prefix = ev.Identifier
	id.saids = []string{ev.SAID}
	return id, icp, signAt(t, id.keys[0], icp, keri.SamePlace(0))
}

// interaction at sn, after the event at sn-1, signed by the key in force.
func (id *identity) interaction(sn int, seal string) ([]byte, string) {
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: id.prefix,
		PriorSAID: id.saids[sn-1], SN: sn, Data: []json.RawMessage{json.RawMessage(seal)}})
	if err != nil {
		id.t.Fatal(err)
	}
	return raw, signAt(id.t, id.keys[id.gen], raw, keri.SamePlace(0))
}

// rotation at sn, after the event at sn-1, to the next generation's key.
func (id *identity) rotation(sn int, gen int) ([]byte, string) {
	raw, err := keri.BuildRotation(keri.RotationInput{Prefix: id.prefix,
		PriorSAID: id.saids[sn-1], SN: sn, Keys: []string{pub(id.t, id.keys[gen])},
		NextDigests: []string{digest(id.t, id.keys[gen+1])}})
	if err != nil {
		id.t.Fatal(err)
	}
	return raw, signAt(id.t, id.keys[gen], raw, keri.SamePlace(0))
}

func (id *identity) kept(raw []byte) {
	ev := parsed(id.t, raw)
	if int(ev.SN) == len(id.saids) {
		id.saids = append(id.saids, ev.SAID)
	} else {
		id.saids = append(id.saids[:ev.SN], ev.SAID)
	}
}

// A witness holding two interactions takes a recovery rotation after the
// first: it replaces the second, which is kept as superseded, and a second
// rotation at the rotation's place is refused and kept as evidence.
func TestAWitnessTakesARecoveryRotationAndKeepsTheFirstEstablishment(t *testing.T) {
	s := witnessFor(t)
	id, icp, icpSig := newIdentity(t)
	witnessesFor(t, s, id.prefix)
	mustReceive(t, s, id.prefix, icp, icpSig)
	id.kept(icp)
	for sn := 1; sn <= 2; sn++ {
		raw, sig := id.interaction(sn, `{"i":"EA","s":"0","d":"EA"}`)
		mustReceive(t, s, id.prefix, raw, sig)
		id.kept(raw)
	}
	superseded := id.saids[2]

	rot, rotSig := id.rotation(2, 1)
	mustReceive(t, s, id.prefix, rot, rotSig)
	id.kept(rot)
	id.gen = 1

	held, err := s.Store.GetKelEvents(id.prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 3 || held[2].EventSAID != id.saids[2] {
		t.Fatalf("after recovery the witness holds %d events", len(held))
	}
	gone, err := s.Store.GetSupersededKelEvents(id.prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 1 || gone[0].EventSAID != superseded || len(gone[0].Signatures) != 1 {
		t.Fatalf("the superseded interaction was not kept: %+v", gone)
	}

	// The interaction the rotation replaced, sent again, is a conflict.
	if _, err := s.ReceiveSignedEvent(id.prefix, mustRaw(t, gone[0]), gone[0].Signatures); err == nil {
		t.Fatal("the superseded interaction was taken back")
	}

	// A different rotation at sn 2, signed by the same revealed key.
	other, err := keri.BuildRotation(keri.RotationInput{Prefix: id.prefix,
		PriorSAID: id.saids[1], SN: 2, Keys: []string{pub(t, id.keys[1])},
		NextDigests: []string{digest(t, id.keys[3])}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ReceiveSignedEvent(id.prefix, other,
		[]string{signAt(t, id.keys[1], other, keri.SamePlace(0))})
	if err == nil || err.Error() != "duplicate_sequence" {
		t.Fatalf("a second rotation at a rotation's place: %v", err)
	}
	conflicts, err := s.Store.GetKelConflicts(id.prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 || conflicts[0].EventSAID != parsed(t, other).SAID ||
		conflicts[0].HeldSAID != id.saids[2] {
		t.Fatalf("the second rotation was not kept as evidence: %+v", conflicts)
	}

	// An unsigned conflict is evidence of nothing, and is not kept.
	forged, err := keri.BuildRotation(keri.RotationInput{Prefix: id.prefix,
		PriorSAID: id.saids[1], SN: 2, Keys: []string{pub(t, id.keys[1])},
		NextDigests: []string{digest(t, id.keys[0])}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReceiveSignedEvent(id.prefix, forged,
		[]string{signAt(t, id.keys[3], forged, keri.SamePlace(0))}); err == nil {
		t.Fatal("a wrongly signed rotation was taken")
	}
	if conflicts, _ := s.Store.GetKelConflicts(id.prefix); len(conflicts) != 1 {
		t.Fatal("a wrongly signed event was kept as evidence")
	}
}

func mustRaw(t *testing.T, e KelEvent) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A repeat carrying a signature the witness did not hold has it kept; a junk
// signature sent with an event is never kept.
func TestARepeatsNewSignatureIsKeptAndJunkNeverIs(t *testing.T) {
	s := witnessFor(t)
	a, b := newOwner(t), newOwner(t)
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pub(t, a.now), pub(t, b.now)},
		NextDigests: []string{digest(t, a.next), digest(t, b.next)},
		Isith:       json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	aid := parsed(t, icp).Identifier
	witnessesFor(t, s, aid)

	stranger := newOwner(t)
	junk := signAt(t, stranger.now, icp, keri.SamePlace(1))
	mustReceive(t, s, aid, icp, signAt(t, a.now, icp, keri.SamePlace(0)), junk)
	held, _ := s.Store.GetKelEvents(aid)
	if len(held) != 1 || len(held[0].Signatures) != 1 {
		t.Fatalf("the witness kept %d signatures; only one verified", len(held[0].Signatures))
	}

	late := signAt(t, b.now, icp, keri.SamePlace(1))
	mustReceive(t, s, aid, icp, late)
	held, _ = s.Store.GetKelEvents(aid)
	if len(held[0].Signatures) != 2 || held[0].Signatures[1] != late {
		t.Fatalf("the late signature was not kept: %v", held[0].Signatures)
	}
	mustReceive(t, s, aid, icp, late)
	if held, _ = s.Store.GetKelEvents(aid); len(held[0].Signatures) != 2 {
		t.Fatal("the same signature sent twice was kept twice")
	}
}

// One public signature spelled thousands of ways, sent with a repeat, is kept
// once: the 2A form's prior-next place is not covered by the signature, so
// anyone holding it can respell it, and a witness keeping each spelling could
// be filled until it can no longer frame the event.
func TestASignatureRespelledIsKeptOnce(t *testing.T) {
	s := witnessFor(t)
	id, icp, icpSig := newIdentity(t)
	witnessesFor(t, s, id.prefix)
	mustReceive(t, s, id.prefix, icp, icpSig)
	id.kept(icp)

	raw, err := id.keys[0].Sign(icp)
	if err != nil {
		t.Fatal(err)
	}
	var spellings []string
	for ondex := 0; ondex < 2000; ondex++ {
		qb, err := keri.EncodeIndexedSignature(raw, keri.SignaturePlace{Index: 0, Ondex: ondex})
		if err != nil {
			t.Fatal(err)
		}
		spellings = append(spellings, qb)
	}
	mustReceive(t, s, id.prefix, icp, spellings...)
	held, _ := s.Store.GetKelEvents(id.prefix)
	if len(held[0].ControllerSignatures()) != 1 {
		t.Fatalf("the witness kept %d spellings of one signature", len(held[0].ControllerSignatures()))
	}
	next, sig := id.interaction(1, `{"i":"EA","s":"0","d":"EA"}`)
	mustReceive(t, s, id.prefix, next, sig)
}

// Events of one identity arriving together are judged one at a time: an
// interaction by a key being recovered from and the recovery rotation, sent at
// once, leave a log that still verifies, whichever lands first.
func TestEventsArrivingTogetherLeaveAVerifiableLog(t *testing.T) {
	for round := 0; round < 20; round++ {
		s := witnessFor(t)
		id, icp, icpSig := newIdentity(t)
		witnessesFor(t, s, id.prefix)
		mustReceive(t, s, id.prefix, icp, icpSig)
		id.kept(icp)
		ixn1, sig1 := id.interaction(1, `{"i":"EA","s":"0","d":"EA"}`)
		mustReceive(t, s, id.prefix, ixn1, sig1)
		id.kept(ixn1)
		ixn2, sig2 := id.interaction(2, `{"i":"EB","s":"0","d":"EB"}`)
		rot, rotSig := id.rotation(1, 1)

		done := make(chan struct{}, 2)
		go func() { _, _ = s.ReceiveSignedEvent(id.prefix, ixn2, []string{sig2}); done <- struct{}{} }()
		go func() { _, _ = s.ReceiveSignedEvent(id.prefix, rot, []string{rotSig}); done <- struct{}{} }()
		<-done
		<-done

		held, err := s.Store.GetKelEvents(id.prefix)
		if err != nil {
			t.Fatal(err)
		}
		var log [][]byte
		for _, e := range held {
			m, err := signedMessage(mustRaw(t, e), e.ControllerSignatures())
			if err != nil {
				t.Fatal(err)
			}
			log = append(log, m)
		}
		if _, err := keri.ValidateSignedKEL(log); err != nil {
			t.Fatalf("round %d: the witness's log no longer verifies: %v", round, err)
		}
	}
}

// A witness hands back every signature it holds over an event.
func TestAWitnessHandsBackEverySignature(t *testing.T) {
	s := witnessFor(t)
	a, b := newOwner(t), newOwner(t)
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pub(t, a.now), pub(t, b.now)},
		NextDigests: []string{digest(t, a.next), digest(t, b.next)},
		Isith:       json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	aid := parsed(t, icp).Identifier
	witnessesFor(t, s, aid)
	mustReceive(t, s, aid, icp, signAt(t, a.now, icp, keri.SamePlace(0)),
		signAt(t, b.now, icp, keri.SamePlace(1)))
	got, err := s.EventAt(aid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Signatures) != 2 || got.CesrSignature != got.Signatures[0] {
		t.Fatalf("the witness handed back %d signatures", len(got.Signatures))
	}
	var sent map[string]interface{}
	if err := json.Unmarshal(eventBody(aid, got.RawBytesB64, got.Signatures), &sent); err != nil {
		t.Fatal(err)
	}
	if list, _ := sent["cesr_signatures"].([]interface{}); len(list) != 2 || sent["cesr_signature"] != got.Signatures[0] {
		t.Fatalf("an event is sent to a witness as %v", sent)
	}
}

// Storing an event at a place already held fails, so no receipt is issued for
// an event that was not stored.
func TestAnEventAtAHeldPlaceIsNotStored(t *testing.T) {
	s := witnessFor(t)
	ev := KelEvent{SignerAID: "EX", SequenceNum: 0, EventJSON: "{}", EventSAID: "E1"}
	if err := s.Store.StoreKelEvent(ev); err != nil {
		t.Fatal(err)
	}
	ev.EventSAID = "E2"
	if err := s.Store.StoreKelEvent(ev); err == nil {
		t.Fatal("a second event at a held place was reported stored")
	}
	if err := s.Store.SupersedeKelEvents("EX", KelEvent{SignerAID: "EX", SequenceNum: 0, EventSAID: "E3"}, 5); err == nil {
		t.Fatal("a recovery judged against a log that ended elsewhere was stored")
	}
}
