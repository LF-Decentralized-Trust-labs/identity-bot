package witness

import (
	"encoding/base64"
	"strings"
	"testing"

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

	mc.contacts[aid] = store.ContactRecord{AID: aid, Status: "accepted"}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: aid, WitnessingFor: true, BackendType: BackendDesktop,
	}); err != nil {
		t.Fatal(err)
	}
	return s, aid, raw, sig
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
