package drivers

import (
	"encoding/base64"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// signedLog builds a real two-event log and the controller signatures over it.
func signedLog(t *testing.T) (aid string, raws [][]byte, sigs []string) {
	t.Helper()
	a, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub := func(s keri.Signer) string {
		p, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	digest := func(s keri.Signer) string {
		d, err := keri.NextDigest(pub(s))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(a)}, NextDigests: []string{digest(b)},
		Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, err := keri.ParseEvent(icp)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{pub(b)},
		PriorSAID: icpEv.SAID, SN: 1, NextDigests: []string{digest(c)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signed the way the agent signs: an unindexed CESR signature over the
	// canonical event bytes. An inception is signed by the key it declares; a
	// rotation by the key it reveals.
	sign := func(s keri.Signer, raw []byte) string {
		sig, err := s.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		qb64, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
		if err != nil {
			t.Fatal(err)
		}
		return qb64
	}
	return icpEv.Identifier, [][]byte{icp, rot}, []string{sign(a, icp), sign(b, rot)}
}

func TestARealSignedLogVerifies(t *testing.T) {
	aid, raws, sigs := signedLog(t)
	got, err := ValidateKELFromBytes(ValidateKELInput{AID: aid, RawEvents: raws, CesrSignatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatalf("a genuine signed log did not verify: %v", got.ValidationErrors)
	}
	if got.EventsValidated != 2 {
		t.Errorf("validated %d events, expected 2", got.EventsValidated)
	}
	// The current key is the one the rotation revealed, not the founding key.
	if got.CurrentPublicKey == "" {
		t.Error("verification did not report the key now in force")
	}
}

// The check that matters most. Everything else — the chain, the sequence, the
// signatures — is satisfied by a wholly forged log, because the forger supplies
// all of it. What makes a log somebody's is that its inception derives their
// identifier.
func TestALogThatIsNotThisIdentitysIsRefused(t *testing.T) {
	_, raws, sigs := signedLog(t)
	other, _, _ := signedLog(t)

	got, err := ValidateKELFromBytes(ValidateKELInput{
		AID: other, RawEvents: raws, CesrSignatures: sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("one identity's log verified as another's — a forged log would pass")
	}
	if !strings.Contains(strings.Join(got.ValidationErrors, " "), "belongs to") {
		t.Errorf("the refusal does not say what is wrong: %v", got.ValidationErrors)
	}
}

// A signature that does not verify means the event was not authorised by the
// identity whose log it claims to extend.
func TestAnEventSignedByTheWrongKeyIsRefused(t *testing.T) {
	aid, raws, sigs := signedLog(t)
	_, _, otherSigs := signedLog(t)
	sigs[1] = otherSigs[1]

	got, err := ValidateKELFromBytes(ValidateKELInput{AID: aid, RawEvents: raws, CesrSignatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an event signed by a key it does not declare was accepted")
	}
}

// Altering any byte changes the digest the event carries, so the log stops
// holding together. This is what parsed-event validation cannot catch.
func TestATamperedEventIsCaught(t *testing.T) {
	aid, raws, sigs := signedLog(t)
	tampered := make([]byte, len(raws[0]))
	copy(tampered, raws[0])
	for i := len(tampered) - 2; i > 0; i-- {
		if tampered[i] >= 'a' && tampered[i] <= 'y' {
			tampered[i]++
			break
		}
	}
	raws[0] = tampered

	got, err := ValidateKELFromBytes(ValidateKELInput{AID: aid, RawEvents: raws, CesrSignatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an altered event was accepted")
	}
}

// A log with no signatures is a normal thing to be handed by a stranger. It
// must not fail, and it must not be reported as though authorship was proven.
func TestAnUnsignedLogIsVerifiedStructurallyAndSaysSo(t *testing.T) {
	aid, raws, _ := signedLog(t)
	got, err := ValidateKELFromBytes(ValidateKELInput{AID: aid, RawEvents: raws})
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatalf("an intact unsigned log was rejected: %v", got.ValidationErrors)
	}
	joined := strings.Join(got.ValidationErrors, " ")
	if !strings.Contains(joined, "no signature") {
		t.Errorf("nothing told the caller that authorship was unchecked: %v", got.ValidationErrors)
	}
}

func TestAnEmptyLogIsNotAVerdict(t *testing.T) {
	got, err := ValidateKELFromBytes(ValidateKELInput{AID: "EWhoever"})
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an empty log was reported as verified")
	}
}

// Bytes are required. A caller holding only parsed events must be told it
// cannot verify them, rather than handed a verdict that skipped the two checks
// that matter.
func TestEventsWithoutCanonicalBytesAreRefusedRatherThanGuessed(t *testing.T) {
	if _, err := DecodeRawEvents([]string{""}); err == nil {
		t.Fatal("an event with no canonical bytes was accepted for verification")
	}
}

// recordsFor packages a log the way the agent publishes one in an OOBI: event
// records carrying the canonical bytes and the controller's signature.
func recordsFor(raws [][]byte, sigs []string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(raws))
	for i, raw := range raws {
		rec := map[string]interface{}{
			"sequence_number": i,
			"event_json":      string(raw),
			"raw_bytes_b64":   base64.StdEncoding.EncodeToString(raw),
		}
		if i < len(sigs) {
			rec["cesr_signature"] = sigs[i]
		}
		out = append(out, rec)
	}
	return out
}

// A published log verifies through the record shape an OOBI actually carries.
func TestAPublishedLogVerifiesFromItsRecords(t *testing.T) {
	aid, raws, sigs := signedLog(t)
	in, ok := ValidateKELInputFromRecords(aid, recordsFor(raws, sigs))
	if !ok {
		t.Fatal("records carrying canonical bytes were not recognised as verifiable")
	}
	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.KelVerified {
		t.Fatalf("a genuine published log did not verify: %v", got.ValidationErrors)
	}
}

// The case this whole path exists for. Somebody hands over a log that holds
// together perfectly — chain, sequence, signatures, all self-consistent —
// claiming it belongs to an identity it does not. Parsed-event validation
// accepts that, because every field it compares was written by the forger.
func TestAForgedLogPresentedAsSomebodyElsesIsRefused(t *testing.T) {
	victim, _, _ := signedLog(t)
	_, forgedRaws, forgedSigs := signedLog(t)

	in, ok := ValidateKELInputFromRecords(victim, recordsFor(forgedRaws, forgedSigs))
	if !ok {
		t.Fatal("the records were not recognised as verifiable")
	}
	got, err := ValidateKELFromBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("a well-formed log was accepted as belonging to an identity that did not " +
			"publish it — impersonation would succeed")
	}
}

// A log published without canonical bytes — an older agent, or another
// implementation — must be reported as unverifiable rather than silently
// validated by a weaker route that looks the same to the caller.
func TestRecordsWithoutCanonicalBytesAreNotTreatedAsVerifiable(t *testing.T) {
	aid, raws, sigs := signedLog(t)
	records := recordsFor(raws, sigs)
	delete(records[1], "raw_bytes_b64")

	if _, ok := ValidateKELInputFromRecords(aid, records); ok {
		t.Fatal("a log missing canonical bytes was offered up as verifiable")
	}
}
