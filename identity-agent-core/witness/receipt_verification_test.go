package witness

import (
	"encoding/base64"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// What a witness receipt is supposed to mean.
//
// A receipt is third-party evidence that a named controller published a
// specific event. It was not that: the event arrived parsed, with no signature
// anywhere on the wire, so the witness could attest only that somebody sent it
// a JSON object — and it re-encoded the event before storing, which sorts the
// fields and destroys the byte sequence a digest and a signature are over, so
// it could not check afterwards either.
//
// These tests are the difference between those two situations.

// enrolled returns a service witnessing for a signer, and a real signed
// inception from that signer.
func enrolled(t *testing.T) (s *Service, aid string, raw []byte, sig string) {
	t.Helper()
	return enrolledListing(t, false)
}

// enrolledListing is enrolled, with the inception naming this agent's own
// witnessing key as the one witness when listed is true, and the service
// reading that log as the key log.
func enrolledListing(t *testing.T, listed bool) (s *Service, aid string, raw []byte, sig string) {
	t.Helper()
	s, mc := testService(t)
	// The witnessing key belongs to the agent, so the host supplies it. Each
	// test agent gets its own, which is what makes two of them two observers.
	wsigner, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	wkey, err := wsigner.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	s.OurWitnessAID = func() (string, error) { return wkey, nil }
	s.SignReceipt = func(said string) (string, string, error) {
		raw, serr := wsigner.Sign([]byte(said))
		if serr != nil {
			return "", "", serr
		}
		sig, serr := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return wkey, sig, serr
	}
	s.SignEventReceipt = func(rawEvent []byte, _ []string) (string, string, error) {
		raw, serr := wsigner.Sign(rawEvent)
		if serr != nil {
			return "", "", serr
		}
		sig, serr := iacrypto.MatterIndexedSigQB64("A", 0, raw, 88)
		return wkey, sig, serr
	}

	a, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pubA, err := a.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubB, err := b.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err := keri.NextDigest(pubB)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = keri.BuildInception(keri.InceptionInput{
		Keys: []string{pubA}, NextDigests: []string{next}, Derivation: "self-addressing",
		Witnesses: witnessesListed(listed, wkey),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	aid = ev.Identifier

	rawSig, err := a.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
	if err != nil {
		t.Fatal(err)
	}

	if listed {
		s.KeyLogOf = keyLog(aid, raw)
	}
	mc.contacts[aid] = store.ContactRecord{AID: aid, Status: "accepted"}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: aid, WitnessingFor: true, BackendType: BackendDesktop,
	}); err != nil {
		t.Fatal(err)
	}
	return s, aid, raw, sig
}

func witnessesListed(listed bool, wkey string) []string {
	if !listed {
		return nil
	}
	return []string{wkey}
}

// The ordinary case: a properly signed event is receipted, and the witness
// keeps what it would need to prove that later.
func TestAWitnessReceiptsAnEventItCanVerify(t *testing.T) {
	s, aid, raw, sig := enrolled(t)

	if _, err := s.ReceiveEvent(aid, raw, sig); err != nil {
		t.Fatalf("a correctly signed event was refused: %v", err)
	}

	stored, err := s.Store.GetKelEvents(aid)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored %d events, expected 1", len(stored))
	}
	// The published bytes must survive storage, or nothing can be re-checked.
	if stored[0].RawBytesB64 == "" {
		t.Fatal("the witness kept no canonical bytes, so what it attested to cannot be re-checked")
	}
	back, err := base64.StdEncoding.DecodeString(stored[0].RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(raw) {
		t.Fatal("the stored bytes are not the bytes that were received")
	}
	if stored[0].CesrSignature != sig {
		t.Fatal("the witness discarded the signature it verified against")
	}
}

// An unsigned event must be refused. A witness that attests to unsigned events
// is one anybody can make say anything, and its receipts stop distinguishing a
// real history from an invented one.
func TestAWitnessRefusesAnUnsignedEvent(t *testing.T) {
	s, aid, raw, _ := enrolled(t)

	_, err := s.ReceiveEvent(aid, raw, "")
	if err == nil {
		t.Fatal("a witness receipted an event carrying no signature")
	}
	if !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("the refusal does not say what was wrong: %v", err)
	}
}

// A signature from the wrong key means the identity did not authorise this
// event. Receipting it would put a witness's name to somebody else's forgery.
func TestAWitnessRefusesAnEventSignedByAStranger(t *testing.T) {
	s, aid, raw, _ := enrolled(t)
	_, _, _, strangerSig := enrolled(t)

	if _, err := s.ReceiveEvent(aid, raw, strangerSig); err == nil {
		t.Fatal("a witness receipted an event signed by a key the event does not declare")
	}
}

// Altering any byte changes the digest the event carries. This is the case that
// parsed-event validation could never catch, because re-encoding produced
// different bytes anyway.
func TestAWitnessRefusesATamperedEvent(t *testing.T) {
	s, aid, raw, sig := enrolled(t)

	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	for i := len(tampered) - 2; i > 0; i-- {
		if tampered[i] >= 'a' && tampered[i] <= 'y' {
			tampered[i]++
			break
		}
	}
	if _, err := s.ReceiveEvent(aid, tampered, sig); err == nil {
		t.Fatal("a witness receipted an event that had been altered")
	}
}

// A log that is not this identity's has nothing to say about it. Without this
// check a witness could be led to build a history for one identity out of
// another's events.
func TestAWitnessRefusesAnEventFromADifferentIdentity(t *testing.T) {
	s, aid, _, _ := enrolled(t)
	_, _, otherRaw, otherSig := enrolled(t)

	if _, err := s.ReceiveEvent(aid, otherRaw, otherSig); err == nil {
		t.Fatal("a witness accepted another identity's event as this identity's")
	}
}

// Broadcasting an unsigned event would ask every witness for an attestation
// none of them could honestly make. Refused locally, where the cause is visible.
func TestBroadcastingAnUnsignedEventIsRefusedLocally(t *testing.T) {
	s, aid, raw, _ := enrolled(t)

	if err := s.BroadcastEvent(t.Context(), aid, raw, ""); err == nil {
		t.Fatal("an unsigned event was broadcast to witnesses")
	}
}

// The receipt a witness issues is the one keripy makes: it names the
// controller, carries an indexed signature over the event's bytes, and checks
// out against those bytes and no others. A witness still answering in the
// earlier form (a signature over the SAID string) is read too, which
// TestAGenuineReceiptIsAccepted covers.
func TestTheIssuedReceiptIsSignedOverTheEventBytes(t *testing.T) {
	s, aid, raw, sig := enrolled(t)
	out, err := s.ReceiveEvent(aid, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	said := out["event_said"].(string)
	wit := out["witness_aid"].(string)
	rsig := out["cesr_signature"].(string)
	if !strings.HasPrefix(rsig, "AA") {
		t.Fatalf("the receipt signature is not an indexed Ed25519 signature: %.4s", rsig)
	}
	rct := out["receipt"].(map[string]interface{})
	if rct["i"] != aid || rct["d"] != said || rct["s"] != "0" || rct["t"] != "rct" {
		t.Fatalf("not keripy's receipt of the inception: %v", rct)
	}
	if err := receiptCheck(out, raw, said); err != nil {
		t.Fatalf("the issued receipt does not check out: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-3] ^= 1
	if err := receiptCheck(out, tampered, said); err == nil {
		t.Fatal("the receipt checked out against bytes it did not sign")
	}
	_ = wit
}

func receiptCheck(resp map[string]interface{}, raw []byte, said string) error {
	_, _, err := ReceiptFromResponse(resp, raw, said, nil)
	return err
}

// A reply's receipt is held to the witness list it is checked against: its
// index is the witness's place in that list, so a list that puts the witness
// elsewhere refuses it, and one that puts it where the index says takes it.
func TestAReceiptIsHeldToTheWitnessListItIsCheckedAgainst(t *testing.T) {
	s, aid, raw, sig := enrolled(t)
	out, err := s.ReceiveEvent(aid, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	said := out["event_said"].(string)
	wit := out["witness_aid"].(string)
	_, at, _, err := iacrypto.DecodeIndexedEd25519SignatureQB64(out["cesr_signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	other := "BOtherWitnessKey0123456789ABCDEFGHIJKLMNOPQ"
	right := make([]string, at+1)
	for i := range right {
		right[i] = other
	}
	right[at] = wit
	if _, _, err := ReceiptFromResponse(out, raw, said, right); err != nil {
		t.Fatalf("a receipt at its place in the list was refused: %v", err)
	}
	wrong := append([]string{other, other}, right...)
	if _, _, err := ReceiptFromResponse(out, raw, said, wrong); err == nil {
		t.Fatal("a receipt was accepted at an index that is not the witness's place in the list")
	}
}

// A receipt whose index is not its witness's place in the list in force is not
// kept and not counted when it arrives: the index sits outside the signature,
// so a copy of a genuine receipt can carry another, and the count must be the
// one the key log check makes.
func TestAMisIndexedReceiptIsNeitherKeptNorCountedOnArrival(t *testing.T) {
	s, aid, raw, sig := enrolledListing(t, true)
	out, err := s.ReceiveEvent(aid, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	said := out["event_said"].(string)
	wit := out["witness_aid"].(string)
	good := out["cesr_signature"].(string)
	_, at, _, err := iacrypto.DecodeIndexedEd25519SignatureQB64(good)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rawSig, _ := iacrypto.DecodeIndexedEd25519SignatureQB64(good)
	moved, err := iacrypto.MatterIndexedSigQB64("A", at+1, rawSig, 88)
	if err != nil {
		t.Fatal(err)
	}

	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: aid, State: FinalizePending, Threshold: 1, StartedAt: now, UpdatedAt: now})
	if err := s.receive(said, wit, moved, raw); err == nil {
		t.Fatal("a mis-indexed copy was taken")
	}
	// The count is the key log check's own, so only what is held shows that
	// the check was made on arrival.
	if held, _ := s.Contacts.GetWitnessReceipts(said); len(held) != 0 {
		t.Fatalf("a mis-indexed copy was kept: %+v", held)
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 0 {
		t.Fatalf("a mis-indexed copy was counted: %d", f.ReceiptCount)
	}
	if err := s.receive(said, wit, good, raw); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 1 {
		t.Fatalf("the genuine receipt was not counted: %d", f.ReceiptCount)
	}
}
