package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// keys returns two distinct public keys in qb64, and the raw base64 spelling of
// the first, so tests can exercise both forms the wire uses.
func keys(t *testing.T) (pub, next, pubRawB64 string) {
	t.Helper()
	a, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = a.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err = b.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.MatterRaw(keri.CodeEd25519, pub, 32)
	if err != nil {
		t.Fatal(err)
	}
	return pub, next, base64.StdEncoding.EncodeToString(raw)
}

func TestAnIdentityIsCreatedAndItsLogValidates(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)

	got, err := e.CreateInceptionNamed(pub, next, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.AID == "" || got.RawBytesB64 == "" {
		t.Fatalf("inception returned nothing usable: %+v", got)
	}

	kel, err := e.GetKel("alice")
	if err != nil {
		t.Fatal(err)
	}
	if kel.EventCount != 1 || kel.AID != got.AID {
		t.Fatalf("expected one event for %s, got %d for %s", got.AID, kel.EventCount, kel.AID)
	}

	// The returned bytes must be the event, not a re-encoding of it: the
	// identifier is a digest over exactly these bytes.
	raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := keri.ValidateKEL([][]byte{raw}); err != nil {
		t.Fatalf("the engine produced a key log that does not validate: %v", err)
	}
}

// The same key in either spelling has to yield the same identity. A raw key
// mistaken for qb64 decodes to 32 plausible bytes of the wrong value and
// produces an identifier that is wrong in a way nothing downstream detects.
func TestTheTwoKeyEncodingsProduceTheSameIdentity(t *testing.T) {
	pub, next, pubRaw := keys(t)

	fromQB64, err := New().CreateInceptionNamed(pub, next, "a")
	if err != nil {
		t.Fatal(err)
	}
	fromRaw, err := New().CreateInceptionNamed(pubRaw, next, "a")
	if err != nil {
		t.Fatal(err)
	}
	if fromQB64.AID != fromRaw.AID {
		t.Fatalf("the same key spelled two ways founded two identities:\n qb64: %s\n raw:  %s",
			fromQB64.AID, fromRaw.AID)
	}
}

// Pre-rotation is only worth anything if the key revealed is the one that was
// committed to. A rotation to any other key is refused before it is published,
// because every conformant implementation would refuse it afterwards — leaving
// the identity stranded with a rotation nobody accepts.
func TestARotationToAnUncommittedKeyIsRefused(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "alice"); err != nil {
		t.Fatal(err)
	}

	stranger, _, _ := keys(t)
	_, err := e.RotateAid("alice", stranger, pub)
	if err == nil {
		t.Fatal("rotating to a key the identity never committed to was allowed")
	}
	if !strings.Contains(err.Error(), "not the one committed to") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}

	// The committed key is accepted, and the log still validates afterwards.
	third, _, _ := keys(t)
	if _, err := e.RotateAid("alice", next, third); err != nil {
		t.Fatalf("rotating to the committed key was refused: %v", err)
	}
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
		t.Fatalf("the log does not validate after a rotation: %v", err)
	}
}

// Committing to the key already in use would mean a compromise of that key also
// carried the right to rotate, which is the whole thing pre-rotation prevents.
func TestAnIdentityCannotCommitToItsOwnCurrentKey(t *testing.T) {
	pub, _, _ := keys(t)
	_, err := New().CreateInceptionNamed(pub, pub, "alice")
	if err == nil {
		t.Fatal("an identity was allowed to pre-rotate to the key it already uses")
	}
}

// The engine holds no private keys, so it cannot sign, and says so rather than
// returning something a caller might treat as a signature.
func TestTheEngineRefusesToSign(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "alice"); err != nil {
		t.Fatal(err)
	}
	resp, err := e.SignPayload("alice", base64.StdEncoding.EncodeToString([]byte("hello")))
	if err == nil {
		t.Fatalf("the engine claimed to sign something: %+v", resp)
	}
	if !strings.Contains(err.Error(), "holds no private keys") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

// A restart hands the engine back what was persisted. A log whose stored bytes
// have been altered must fail here, not at the point where the identity next
// publishes something.
func TestATamperedStoredLogIsRefusedOnReload(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	created, err := e.CreateInceptionNamed(pub, next, "alice")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("alice")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[0])
	if err != nil {
		t.Fatal(err)
	}
	// Change one byte of the payload, leaving the digest claiming the original.
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	for i := len(tampered) - 2; i > 0; i-- {
		if tampered[i] >= 'a' && tampered[i] <= 'y' {
			tampered[i]++
			break
		}
	}

	_, err = New().ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID:          created.AID,
		KEL:          kel.KEL,
		RawEventsB64: []string{base64.StdEncoding.EncodeToString(tampered)},
	})
	if err == nil {
		t.Fatal("a tampered key log was accepted on reload")
	}
}

// A round trip through storage has to restore an identity that can keep
// extending its own log, rather than one that forks it.
func TestAnIdentitySurvivesAReload(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	created, err := e.CreateInceptionNamed(pub, next, "alice")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("alice")
	if err != nil {
		t.Fatal(err)
	}

	restored := New()
	resp, err := restored.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID:           created.AID,
		PublicKey:     created.PublicKey,
		NextKeyDigest: created.NextKeyDigest,
		KEL:           kel.KEL,
		RawEventsB64:  kel.RawEventsB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Status, "reloaded") || strings.Contains(resp.Status, "not verified") {
		t.Fatalf("a log with canonical bytes should have been verified, got %q", resp.Status)
	}

	// The restored identity extends the same log rather than starting one.
	ixn, err := restored.Interact(created.AID, []interface{}{map[string]string{"note": "after restart"}})
	if err != nil {
		t.Fatal(err)
	}
	if ixn.SequenceNumber != 1 {
		t.Fatalf("the restored identity continued at %d, so it did not resume the log",
			ixn.SequenceNumber)
	}
	full, err := restored.GetKel(created.AID)
	if err != nil {
		t.Fatal(err)
	}
	raws := make([][]byte, 0, len(full.RawEventsB64))
	for _, b := range full.RawEventsB64 {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := keri.ValidateKEL(raws); err != nil {
		t.Fatalf("the log does not validate across a reload: %v", err)
	}
}

// A log restored without canonical bytes can be continued and has not been
// verified. Reporting it as verified would be the dangerous answer, and
// re-encoding the parsed events to manufacture bytes would produce exactly
// that.
func TestALogWithoutCanonicalBytesIsRestoredButNotClaimedVerified(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	created, err := e.CreateInceptionNamed(pub, next, "alice")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("alice")
	if err != nil {
		t.Fatal(err)
	}

	restored := New()
	resp, err := restored.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID:            created.AID,
		PublicKey:      created.PublicKey,
		NextKeyDigest:  created.NextKeyDigest,
		SequenceNumber: 0,
		LastSAID:       kel.KEL[0]["d"].(string),
		KEL:            kel.KEL,
		// No RawEventsB64 — the pre-existing stored form.
	})
	if err != nil {
		t.Fatalf("an identity with an intact but unverifiable log should still be restored: %v", err)
	}
	if !strings.Contains(resp.Status, "not verified") {
		t.Fatalf("the engine did not report that the history was unverified: %q", resp.Status)
	}

	// It can still extend the log, and the event it produces is real.
	ixn, err := restored.Interact(created.AID, []interface{}{map[string]string{"note": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(ixn.RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := keri.ValidateEvent(raw); err != nil {
		t.Fatalf("the event produced after an unverified reload is malformed: %v", err)
	}

	// And GetKel must not present a re-encoding as though it were canonical.
	full, err := restored.GetKel(created.AID)
	if err != nil {
		t.Fatal(err)
	}
	if full.RawEventsB64[0] != "" {
		t.Fatalf("an event with no stored bytes was given bytes anyway: %q", full.RawEventsB64[0])
	}
}

// A credential must be issued, anchored, and verify against its own identifier.
func TestACredentialIsIssuedAndVerifies(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	issuer, err := e.CreateInceptionNamed(pub, next, "issuer")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptRegistry("issuer")
	if err != nil {
		t.Fatal(err)
	}

	holderPub, holderNext, _ := keys(t)
	holder, err := New().CreateInceptionNamed(holderPub, holderNext, "holder")
	if err != nil {
		t.Fatal(err)
	}

	schema, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.IssueCredentialInRegistry("issuer",
		map[string]interface{}{"role": "engineer"}, schema, holder.AID, nil, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	if issued.IssSaid == "" {
		t.Fatal("a credential issued into a registry has no issuance event, so it could never be revoked")
	}

	verified, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:           issued.AcdcJsonB64,
		HolderAid:          holder.AID,
		TrustedSchemaSaids: []string{schema},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Verified {
		t.Fatalf("a credential this engine just issued does not verify: %v", verified.Errors)
	}
	if verified.AcdcSaid != issued.AcdcSaid {
		t.Fatalf("verification reports a different credential: %s vs %s",
			verified.AcdcSaid, issued.AcdcSaid)
	}

	// Revocation names the issuance as its predecessor; without that the TEL is
	// a set of assertions rather than a chain.
	if _, err := e.RevokeCredential("issuer", issued.AcdcSaid, reg.RegistrySaid, issued.IssSaid); err != nil {
		t.Fatalf("revoking a credential this engine issued failed: %v", err)
	}

	// The issuer's own log must still hold together after all of it.
	kel, err := e.GetKel("issuer")
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
		t.Fatalf("the issuer's log does not validate after issuing and revoking: %v", err)
	}
	if kel.AID != issuer.AID {
		t.Fatalf("the issuer's identifier changed: %s vs %s", kel.AID, issuer.AID)
	}
}

// A tampered credential must not verify, and the reason must name the tampering
// rather than something downstream of it.
func TestATamperedCredentialIsRefused(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "issuer"); err != nil {
		t.Fatal(err)
	}
	schema, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.IssueCredential("issuer", map[string]interface{}{"role": "engineer"}, schema, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.StdEncoding.DecodeString(issued.AcdcJsonB64)
	if err != nil {
		t.Fatal(err)
	}
	altered := []byte(strings.Replace(string(raw), "engineer", "director", 1))
	if len(altered) != len(raw) {
		t.Skip("the substitution changed the length, so this would fail for the wrong reason")
	}

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson: base64.StdEncoding.EncodeToString(altered),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("a credential whose claims were altered still verified")
	}
}

// A witness that is not designated must not contribute to a threshold, and one
// witness must not meet a threshold by submitting twice.
func TestReceiptsAreCountedOnlyFromDesignatedWitnessesAndOnlyOnce(t *testing.T) {
	e := New()

	stranger, err := e.SubmitReceipt(&drivers.DriverSubmitReceiptRequest{
		EventSAID:        "EAAAtest",
		WitnessAID:       "Bstranger",
		TrustedWitnesses: []string{"Bdesignated"},
		Threshold:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stranger.Accepted || stranger.ThresholdMet {
		t.Fatalf("a receipt from an undesignated witness was counted: %+v", stranger)
	}

	first, err := e.SubmitReceipt(&drivers.DriverSubmitReceiptRequest{
		EventSAID:        "EAAAtest",
		WitnessAID:       "Bdesignated",
		TrustedWitnesses: []string{"Bdesignated", "Bother"},
		Threshold:        2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Accepted || first.ReceiptCount != 1 {
		t.Fatalf("a designated witness's receipt was not recorded: %+v", first)
	}

	repeat, err := e.SubmitReceipt(&drivers.DriverSubmitReceiptRequest{
		EventSAID:        "EAAAtest",
		WitnessAID:       "Bdesignated",
		TrustedWitnesses: []string{"Bdesignated", "Bother"},
		Threshold:        2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if repeat.ReceiptCount != 1 || repeat.ThresholdMet {
		t.Fatalf("one witness met a threshold of two by submitting twice: %+v", repeat)
	}
}

// A group whose threshold exceeds its membership can never act. Refusing at
// construction beats discovering it when the group first tries to sign.
func TestAGroupThatCouldNeverActIsRefused(t *testing.T) {
	e := New()
	a, _, _ := keys(t)
	b, _, _ := keys(t)
	if _, err := e.GenerateMultisigEvent(nil, 3, []string{a, b}, nil, "icp"); err == nil {
		t.Fatal("a group needing three of two signatures was created")
	}
}

// The three discovery operations refuse rather than returning something empty,
// which a caller cannot tell from a real answer.
func TestTheUnsupportedOperationsRefuseRatherThanReturnNothing(t *testing.T) {
	e := New()
	if e.SupportsDiscovery() {
		t.Fatal("the engine claims to support discovery")
	}
	if _, err := e.ResolveOobi("http://example.test/oobi"); err == nil {
		t.Fatal("ResolveOobi returned an answer it cannot produce")
	}
	if _, err := e.EndpointLocation(&drivers.DriverEndpointLocationRequest{EID: "E1"}); err == nil {
		t.Fatal("EndpointLocation returned an answer it cannot produce")
	}
	if _, err := e.PresentCredential("Ecred", "Eholder", "Eissuer", "Eschema"); err == nil {
		t.Fatal("PresentCredential returned an answer it cannot produce")
	}
}

// A hybrid identity whose secrets cannot be stored must not be reported as
// created: it could never sign and could never rotate.
func TestAHybridIdentityIsRefusedWhenItsSecretsWouldBeLost(t *testing.T) {
	if _, err := New().CreateHybridInception(false, "root"); err == nil {
		t.Fatal("a hybrid identity was created with nowhere to keep its private half")
	}

	e := NewWithSecretStore(keri.NewMemoryKeyStore())
	got, err := e.CreateHybridInception(false, "root")
	if err != nil {
		t.Fatal(err)
	}
	if got.AID == "" || got.CipherSuite == "" {
		t.Fatalf("the hybrid identity is incomplete: %+v", got)
	}
	// The identity is real: its log validates like any other.
	kel, err := e.GetKel("root")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := keri.ValidateEvent(raw); err != nil {
		t.Fatalf("the hybrid inception is not a valid event: %v", err)
	}
}

// Anchored data has to travel in the rotation itself. Anchoring it in a
// following interaction would let a relay separate the two.
func TestARotationCarriesItsAnchorInTheSameEvent(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "alice"); err != nil {
		t.Fatal(err)
	}
	third, _, _ := keys(t)

	got, err := e.RotateAidWithAnchor("alice", next, third,
		[]interface{}{map[string]string{"recovery": "session-1"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(got.RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	anchors, ok := body["a"].([]interface{})
	if !ok || len(anchors) != 1 {
		t.Fatalf("the rotation does not carry its anchor: %v", body["a"])
	}
	if got.SequenceNumber != 1 {
		t.Fatalf("the rotation is at sequence %d, not 1", got.SequenceNumber)
	}
}
