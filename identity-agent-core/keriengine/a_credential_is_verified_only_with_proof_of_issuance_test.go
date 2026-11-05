package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// signedLogOf is an identity's key log the way a verifier is handed it: each
// event with the bytes it was published as and its controller's signature.
func signedLogOf(t *testing.T, e *Engine, name string) []map[string]interface{} {
	t.Helper()
	kel, err := e.GetKel(name)
	if err != nil {
		t.Fatal(err)
	}
	icp := kel.KEL[0]
	key := icp["k"].([]interface{})[0].(string) // the one key that signed every event here
	out := make([]map[string]interface{}, 0, len(kel.KEL))
	for i, ev := range kel.KEL {
		body, _ := json.Marshal(ev)
		raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[i])
		if err != nil {
			t.Fatal(err)
		}
		sig, err := testEventSignature(kel.AID, key, raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]interface{}{
			"event_json": string(body), "raw_bytes_b64": kel.RawEventsB64[i], "cesr_signature": sig})
	}
	return out
}

type anIssuerWorld struct {
	e        *Engine
	issuer   string
	registry string
	schema   string
	holder   string
	kel      []map[string]interface{}
}

func anIssuerHoldingARegistry(t *testing.T) *anIssuerWorld {
	t.Helper()
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
	schema, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	hpub, hnext, _ := keys(t)
	holder, err := New().CreateInceptionNamed(hpub, hnext, "holder")
	if err != nil {
		t.Fatal(err)
	}
	return &anIssuerWorld{e: e, issuer: issuer.AID, registry: reg.RegistrySaid, schema: schema, holder: holder.AID}
}

// verify hands the engine everything a verifier holding the issuer's log would.
func (w *anIssuerWorld) verify(t *testing.T, acdc string, tel []string) *drivers.DriverVerifyCredentialResponse {
	t.Helper()
	got, err := w.e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          acdc,
		IssuerKelEvents:   signedLogOf(t, w.e, "issuer"),
		RegistryEventsB64: tel,
		HolderAid:         w.holder,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (w *anIssuerWorld) forgery(t *testing.T, registry string) string {
	t.Helper()
	acdc, err := keri.BuildCredential(keri.CredentialInput{
		SchemaSAID: w.schema, Issuer: w.issuer, Recipient: w.holder, Registry: registry,
		Data: json.RawMessage(`{"role":"engineer","dt":"2026-11-05T00:00:00.000000+00:00"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(acdc)
}

func mustNotBeVerified(t *testing.T, what string, got *drivers.DriverVerifyCredentialResponse) {
	t.Helper()
	if got.Verified || got.Checks["issuance_proved"] == true {
		t.Fatalf("%s was verified: %v %v", what, got.Checks, got.Errors)
	}
	if len(got.Errors) == 0 {
		t.Fatalf("%s was refused without saying why", what)
	}
}

// The genuine case: without it, the refusals below could be a check that
// always refuses.
func TestACredentialTheIssuerIssuedAndAnchoredIsVerified(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	issued, err := w.e.IssueCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, w.schema, w.holder, nil, w.registry)
	if err != nil {
		t.Fatal(err)
	}
	tel, err := w.e.CredentialLog("issuer", w.registry, issued.AcdcSaid)
	if err != nil {
		t.Fatal(err)
	}
	got := w.verify(t, issued.AcdcJsonB64, tel)
	if !got.Verified || got.Checks["issuance_proved"] != true {
		t.Fatalf("a credential the issuer issued and anchored was not verified: %v %v", got.Checks, got.Errors)
	}
}

// Anybody can build a credential naming any issuer: it matches its own
// identifier and the issuer's log is sound, but nothing says the issuer issued it.
func TestAForgeryNamingAKnownIssuerWithNoRegistryIsRefused(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	mustNotBeVerified(t, "a forgery naming the issuer, with no registry", w.verify(t, w.forgery(t, ""), nil))
}

func TestACredentialWhoseIssuerNeverAnchoredItsIssuanceIsRefused(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	// Names the issuer's real registry and carries a well-formed issuance event
	// for it, written by the forger: nothing in the issuer's log seals it.
	acdc := w.forgery(t, w.registry)
	raw, _ := base64.StdEncoding.DecodeString(acdc)
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := keri.BuildIssuance(keri.IssuanceInput{
		CredentialSAID: cred.SAID, Registry: w.registry, DT: time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")})
	if err != nil {
		t.Fatal(err)
	}
	mustNotBeVerified(t, "a credential with an issuance the issuer never anchored",
		w.verify(t, acdc, []string{base64.StdEncoding.EncodeToString(iss)}))
}

func TestACredentialNamingARegistryWithNoIssuanceEventHeldIsRefused(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	mustNotBeVerified(t, "a credential with a registry and no log", w.verify(t, w.forgery(t, w.registry), nil))
}

// An issuance sealed in the issuer's log is proof for that credential only.
func TestAnotherCredentialsIssuanceIsNoProofOfThisOne(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	real, err := w.e.IssueCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, w.schema, w.holder, nil, w.registry)
	if err != nil {
		t.Fatal(err)
	}
	tel, _ := w.e.CredentialLog("issuer", w.registry, real.AcdcSaid)
	mustNotBeVerified(t, "a forgery handed a genuine credential's log", w.verify(t, w.forgery(t, w.registry), tel))
}

// A log supplied without its bytes and signatures is a log anybody could have
// written, so a seal in it proves nothing.
func TestASealInAnUnverifiedIssuerLogIsNoProof(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	issued, err := w.e.IssueCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, w.schema, w.holder, nil, w.registry)
	if err != nil {
		t.Fatal(err)
	}
	tel, _ := w.e.CredentialLog("issuer", w.registry, issued.AcdcSaid)
	kel, _ := w.e.GetKel("issuer")
	got, err := w.e.VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson: issued.AcdcJsonB64, IssuerKelEvents: kel.KEL, RegistryEventsB64: tel, HolderAid: w.holder})
	if err != nil {
		t.Fatal(err)
	}
	mustNotBeVerified(t, "a credential checked against an unsigned issuer log", got)
}

// A credential with no registry cannot be revoked, so the issuer's seal of the
// credential's own identifier is its issuance. Fails if that seal is not read.
func TestARegistryLessCredentialTheIssuerSealedIsVerified(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	issued, err := w.e.IssueCredential("issuer", map[string]interface{}{"role": "engineer"}, w.schema, w.holder, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := w.verify(t, issued.AcdcJsonB64, nil)
	if !got.Verified || got.Checks["issuance_proved"] != true {
		t.Fatalf("a registry-less credential the issuer sealed was not verified: %v %v", got.Checks, got.Errors)
	}
}

// The seal is of this credential and no other. Fails if any seal in the log, or
// the absence of a registry alone, is taken as proof.
func TestARegistryLessCredentialWithNoSealIsRefused(t *testing.T) {
	w := anIssuerHoldingARegistry(t)
	if _, err := w.e.IssueCredential("issuer", map[string]interface{}{"role": "engineer"}, w.schema, w.holder, nil); err != nil {
		t.Fatal(err) // the issuer's log now holds a seal, of a different credential
	}
	mustNotBeVerified(t, "a registry-less forgery beside a genuine sealed credential", w.verify(t, w.forgery(t, ""), nil))
}
