package keriengine

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// What a presentation has to prove, and what it used to prove instead.
//
// The check verified a caller-supplied signature over caller-supplied bytes
// under a caller-supplied key. Every one of those three came from the party
// being checked, so it established only that whoever was presenting could sign
// with a key they had picked — which anybody can do, including somebody
// presenting a copy of a stranger's credential. It passed, and the credential
// verified, and nothing anywhere said the proof was attached to nothing.
//
// These tests are written as the attacks rather than as the happy path, because
// the happy path passed throughout.

type holder struct {
	AID    string
	Signer keri.Signer
	Pub    string
	KEL    []map[string]interface{}
}

func newHolder(t *testing.T, e *Engine, name string) holder {
	t.Helper()
	signer, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	nextSigner, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err := nextSigner.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	icp, err := e.CreateInceptionNamed(pub, next, name)
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel(name)
	if err != nil {
		t.Fatal(err)
	}
	// The log has to arrive signed, or it establishes no key to check against.
	records := make([]map[string]interface{}, 0, len(kel.KEL))
	for i, ev := range kel.KEL {
		raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[i])
		if err != nil {
			t.Fatal(err)
		}
		rawSig, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, map[string]interface{}{
			"sequence_number": i,
			"event_json":      ev,
			"raw_bytes_b64":   kel.RawEventsB64[i],
			"cesr_signature":  sig,
		})
	}
	return holder{AID: icp.AID, Signer: signer, Pub: pub, KEL: records}
}

// issuedTo founds an issuer, issues a credential into a registry, and returns
// everything a verifier would be handed.
func issuedTo(t *testing.T, e *Engine, subject string) (acdcB64, acdcSAID, registry string, log []string) {
	t.Helper()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "issuer"); err != nil {
		t.Fatal(err)
	}
	schema, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptRegistry("issuer")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.IssueCredentialInRegistry("issuer",
		map[string]interface{}{"role": "engineer"}, schema, subject, nil, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	tel, err := e.CredentialLog("issuer", reg.RegistrySaid, issued.AcdcSaid)
	if err != nil {
		t.Fatal(err)
	}
	return issued.AcdcJsonB64, issued.AcdcSaid, reg.RegistrySaid, tel
}

// presentedBy builds a presentation of acdcSAID by h and signs it with h's key.
func presentedBy(t *testing.T, e *Engine, h holder, acdcSAID, holderAID string) *drivers.DriverPresentCredentialResponse {
	t.Helper()
	pres, err := e.PresentCredential(acdcSAID, holderAID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := base64.StdEncoding.DecodeString(pres.PresSaidB64)
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := h.Signer.Sign(signed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
	if err != nil {
		t.Fatal(err)
	}
	// Stash the signature on the response so callers below can use one value.
	pres.PresentationBody["__sig"] = sig
	return pres
}

func sigOf(pres *drivers.DriverPresentCredentialResponse) string {
	s, _ := pres.PresentationBody["__sig"].(string)
	return s
}

func bodyOf(pres *drivers.DriverPresentCredentialResponse) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range pres.PresentationBody {
		if k != "__sig" {
			out[k] = v
		}
	}
	return out
}

// The genuine case. Without this passing, everything below would be satisfied
// by a check that always refuses.
func TestTheSubjectPresentingTheirOwnCredentialIsAccepted(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, said, _, log := issuedTo(t, e, subject.AID)
	pres := presentedBy(t, e, subject, said, subject.AID)

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		HolderAid:         subject.AID,
		PresentationSaid:  pres.PresSaidB64,
		PresentationBody:  bodyOf(pres),
		CesrSignature:     sigOf(pres),
		HolderPublicKey:   subject.Pub,
		HolderKelEvents:   subject.KEL,
		RegistryEventsB64: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified {
		t.Fatalf("a subject presenting their own live credential was refused: %v", got.Errors)
	}
	for _, name := range []string{"presentation", "presentation_intact",
		"presentation_binds_credential", "presentation_binds_holder",
		"holder_key_established", "not_revoked"} {
		if got.Checks[name] != true {
			t.Errorf("check %q was %v, expected true", name, got.Checks[name])
		}
	}
}

// The attack the old check could not see. A stranger holding a copy of the
// credential generates their own key, signs the genuine presentation with it,
// and names their key as the holder's. Every byte is well formed and the
// signature verifies — under a key that is not the subject's.
func TestAStrangerSigningWithTheirOwnKeyIsRefused(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	stranger := newHolder(t, e, "stranger")
	acdc, said, _, log := issuedTo(t, e, subject.AID)

	// Signed by the stranger, over the subject's genuine presentation.
	pres := presentedBy(t, e, stranger, said, subject.AID)

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		HolderAid:         subject.AID,
		PresentationSaid:  pres.PresSaidB64,
		PresentationBody:  bodyOf(pres),
		CesrSignature:     sigOf(pres),
		HolderPublicKey:   stranger.Pub, // the key they chose
		HolderKelEvents:   subject.KEL,  // the subject's real log
		RegistryEventsB64: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("anybody holding a copy of this credential could present it as their own")
	}
	if got.Checks["holder_key_established"] != false {
		t.Errorf("the key was not challenged: %v", got.Checks["holder_key_established"])
	}
}

// A proof of possession of some other credential is not a proof about this one.
func TestAPresentationOfADifferentCredentialIsRefused(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, _, _, log := issuedTo(t, e, subject.AID)

	other, err := keri.Blake3SAID([]byte("some other credential"))
	if err != nil {
		t.Fatal(err)
	}
	pres := presentedBy(t, e, subject, other, subject.AID)

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		HolderAid:         subject.AID,
		PresentationSaid:  pres.PresSaidB64,
		PresentationBody:  bodyOf(pres),
		CesrSignature:     sigOf(pres),
		HolderPublicKey:   subject.Pub,
		HolderKelEvents:   subject.KEL,
		RegistryEventsB64: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("a presentation of an unrelated credential was accepted as a presentation of this one")
	}
	if got.Checks["presentation_binds_credential"] != false {
		t.Errorf("the presentation was not checked against the credential")
	}
}

// A presentation whose contents were changed after it was signed. The signature
// still verifies, because it is over the identifier the presentation claims
// rather than over what it now says.
func TestAnAlteredPresentationIsRefused(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, said, _, log := issuedTo(t, e, subject.AID)
	pres := presentedBy(t, e, subject, said, subject.AID)

	body := bodyOf(pres)
	body["i"] = "Esomebody-else-entirely"

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		HolderAid:         subject.AID,
		PresentationSaid:  pres.PresSaidB64,
		PresentationBody:  body,
		CesrSignature:     sigOf(pres),
		HolderPublicKey:   subject.Pub,
		HolderKelEvents:   subject.KEL,
		RegistryEventsB64: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("a presentation edited after signing was accepted")
	}
	if got.Checks["presentation_intact"] != false {
		t.Errorf("the alteration was not detected")
	}
}

// A signature with no presentation behind it. This is exactly what the old
// check received, and it reported a pass.
func TestASignatureWithoutThePresentationIsNotAProof(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, said, _, log := issuedTo(t, e, subject.AID)
	pres := presentedBy(t, e, subject, said, subject.AID)

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		HolderAid:         subject.AID,
		PresentationSaid:  pres.PresSaidB64,
		CesrSignature:     sigOf(pres),
		HolderPublicKey:   subject.Pub,
		HolderKelEvents:   subject.KEL,
		RegistryEventsB64: log,
		// PresentationBody deliberately absent.
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("a signature that binds to nothing was accepted as proof of possession")
	}
	if got.Checks["presentation"] != false {
		t.Errorf("the missing presentation was not reported")
	}
}

// A revoked credential must not verify, and the holder is the party who would
// rather not mention it.
func TestARevokedCredentialIsRefused(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "issuer"); err != nil {
		t.Fatal(err)
	}
	schema, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptRegistry("issuer")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := e.IssueCredentialInRegistry("issuer",
		map[string]interface{}{"role": "engineer"}, schema, subject.AID, nil, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RevokeCredential("issuer", issued.AcdcSaid, reg.RegistrySaid, issued.IssSaid); err != nil {
		t.Fatal(err)
	}
	log, err := e.CredentialLog("issuer", reg.RegistrySaid, issued.AcdcSaid)
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          issued.AcdcJsonB64,
		RegistryEventsB64: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified {
		t.Fatal("a revoked credential still verified")
	}
	if got.Checks["not_revoked"] != false {
		t.Errorf("the revocation was not seen: %v", got.Checks["not_revoked"])
	}
}

// Withholding the log is the obvious move for someone presenting a revoked
// credential. It must not read as "not revoked".
func TestACredentialWhoseLogIsWithheldIsNotReportedValid(t *testing.T) {
	e := New()
	subject := newHolder(t, e, "subject")
	acdc, _, _, _ := issuedTo(t, e, subject.AID)

	got, err := e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson: acdc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Checks["not_revoked"] == true {
		t.Fatal("a credential with no transaction log supplied was reported as not revoked, " +
			"which is exactly what withholding a revocation would produce")
	}
}
