package drivers

import (
	"testing"

	keri "github.com/grapeid/keri-go"
)

// witness returns a non-transferable witness identifier and a signer for it.
func witness(t *testing.T) (aid string, sign func(said string) string) {
	t.Helper()
	s, err := keri.GenerateSigner(false) // non-transferable
	if err != nil {
		t.Fatal(err)
	}
	aid, err = s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return aid, func(said string) string {
		raw, err := s.Sign([]byte(said))
		if err != nil {
			t.Fatal(err)
		}
		qb64, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		if err != nil {
			t.Fatal(err)
		}
		return qb64
	}
}

// A witness identifier IS its verifying key, so a receipt is checkable with
// nothing fetched.
func TestARealReceiptVerifiesWithNoLookup(t *testing.T) {
	aid, sign := witness(t)
	said := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"

	if err := VerifyReceipt(aid, said, sign(said)); err != nil {
		t.Fatalf("a genuine receipt did not verify: %v", err)
	}
}

// A receipt covers exactly the event it was issued for. Without this a receipt
// could be lifted off one event and presented as corroborating another.
func TestAReceiptDoesNotCoverAnEventItWasNotIssuedFor(t *testing.T) {
	aid, sign := witness(t)
	sig := sign("EAAAtheeventitwasissuedfor0123456789ABCDEFG")

	if err := VerifyReceipt(aid, "EBBBsomeotherentirelydifferentevent01234567", sig); err == nil {
		t.Fatal("a receipt for one event was accepted as covering another")
	}
}

// A receipt naming a witness that did not sign it proves nothing.
func TestAReceiptAttributedToTheWrongWitnessIsRefused(t *testing.T) {
	_, sign := witness(t)
	other, _ := witness(t)
	said := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"

	if err := VerifyReceipt(other, said, sign(said)); err == nil {
		t.Fatal("a receipt was accepted as coming from a witness that did not sign it")
	}
}

// A transferable identifier cannot be a witness here: checking its receipts
// would mean resolving its key log and deciding which key was in force, which
// is exactly what a receipt is supposed to avoid needing.
func TestATransferableWitnessIsRefused(t *testing.T) {
	s, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	said := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	raw, err := s.Sign([]byte(said))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(aid, said, sig); err == nil {
		t.Fatal("a transferable identifier was accepted as a witness")
	}
}

// witnessedLog builds a log whose inception designates two witnesses with a
// threshold of two, and returns receipts from both.
func witnessedLog(t *testing.T) (in ValidateKELInput, w1, w2 string, sign1, sign2 func(string) string) {
	t.Helper()
	w1, sign1 = witness(t)
	w2, sign2 = witness(t)

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
	toad := 2
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pubA}, NextDigests: []string{next},
		Witnesses: []string{w1, w2}, Toad: &toad, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, err := a.Sign(icp)
	if err != nil {
		t.Fatal(err)
	}
	ctrlSig, err := keri.MatterQB64(keri.CodeEd25519Sig, sigRaw)
	if err != nil {
		t.Fatal(err)
	}

	in = ValidateKELInput{
		AID: ev.Identifier, RawEvents: [][]byte{icp}, CesrSignatures: []string{ctrlSig},
		Receipts: map[string][]WitnessReceipt{
			ev.SAID: {
				{WitnessAID: w1, CesrSignature: sign1(ev.SAID)},
				{WitnessAID: w2, CesrSignature: sign2(ev.SAID)},
			},
		},
	}
	return in, w1, w2, sign1, sign2
}

// A log its designated witnesses have receipted reaches its threshold.
func TestAWitnessedLogReportsItsThresholdMet(t *testing.T) {
	in, _, _, _, _ := witnessedLog(t)
	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatalf("the log did not verify: %v", got.ValidationErrors)
	}
	if !got.Witnessed {
		t.Fatalf("a fully receipted log was not reported as witnessed: %+v", got.Witnessing)
	}
	if len(got.Witnessing) != 1 || got.Witnessing[0].Verified != 2 {
		t.Fatalf("expected two verified receipts, got %+v", got.Witnessing)
	}
}

// Corroboration is separate from soundness. A log with no receipts is still a
// valid log; what it lacks is anybody else having seen it.
func TestAnUnwitnessedLogIsStillValidButNotWitnessed(t *testing.T) {
	in, _, _, _, _ := witnessedLog(t)
	in.Receipts = nil

	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatal("a sound log was reported invalid because nobody had witnessed it")
	}
	if got.Witnessed {
		t.Fatal("a log with no receipts was reported as witnessed")
	}
}

// A threshold that undesignated witnesses could help meet is not a threshold:
// anybody can generate a key and sign.
func TestAReceiptFromAnUndesignatedWitnessDoesNotCount(t *testing.T) {
	in, w1, _, sign1, _ := witnessedLog(t)
	stranger, strangerSign := witness(t)

	for k := range in.Receipts {
		in.Receipts[k] = []WitnessReceipt{
			{WitnessAID: w1, CesrSignature: sign1(k)},
			{WitnessAID: stranger, CesrSignature: strangerSign(k)},
		}
	}

	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Witnessed {
		t.Fatal("an outsider's receipt helped meet the threshold")
	}
	if got.Witnessing[0].Verified != 1 {
		t.Fatalf("expected only the designated witness to count, got %+v", got.Witnessing)
	}
}

// One witness must not meet a threshold of two by sending its receipt twice.
func TestOneWitnessCannotMeetAThresholdTwice(t *testing.T) {
	in, w1, _, sign1, _ := witnessedLog(t)
	for k := range in.Receipts {
		in.Receipts[k] = []WitnessReceipt{
			{WitnessAID: w1, CesrSignature: sign1(k)},
			{WitnessAID: w1, CesrSignature: sign1(k)},
		}
	}

	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Witnessed || got.Witnessing[0].Verified != 1 {
		t.Fatalf("one witness counted twice towards a threshold: %+v", got.Witnessing)
	}
}
