package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// aGateWorld is an agent that holds a credential issued by a real issuer whose
// key log it also holds, plus the sign-in identity the credential was issued to.
// The credential passes every check the gate makes; each test below breaks
// exactly one.
type aGateWorld struct {
	s      *CoreServer
	schema string
	issuer string
	holder string // the identity signing in, and the credential's issuee
}

func aGateWorldIssuingTo(t *testing.T, issueeIsSigner, agentHoldsIssuerLog bool) *aGateWorld {
	t.Helper()
	s := witnessWithSeed(t, 1)
	s.KeriDriver = keriengine.New()

	issuerEngine := keriengine.New()
	issuerEngine.SetEventSignature(signsWithTheKeysMadeHere)
	ipub, inext := newKeyPair(t)
	issuer, err := issuerEngine.CreateInceptionNamed(ipub, inext, "issuer")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := issuerEngine.InceptRegistry("issuer")
	if err != nil {
		t.Fatal(err)
	}
	hpub, hnext := newKeyPair(t)
	holder, err := keriengine.New().CreateInceptionNamed(hpub, hnext, "holder")
	if err != nil {
		t.Fatal(err)
	}
	opub, onext := newKeyPair(t)
	other, err := keriengine.New().CreateInceptionNamed(opub, onext, "other")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := keri.Blake3SAID([]byte("a gate test schema"))
	if err != nil {
		t.Fatal(err)
	}
	issuee := holder.AID
	if !issueeIsSigner {
		issuee = other.AID
	}
	issued, err := issuerEngine.IssueCredentialInRegistry("issuer",
		map[string]interface{}{"role": "engineer"}, schema, issuee, nil, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	if agentHoldsIssuerLog {
		kel, err := issuerEngine.GetKel("issuer")
		if err != nil {
			t.Fatal(err)
		}
		// A verified log carries each event with the bytes it was verified by.
		events := make([]map[string]interface{}, 0, len(kel.KEL))
		for i, ev := range kel.KEL {
			body, _ := json.Marshal(ev)
			raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[i])
			if err != nil {
				t.Fatal(err)
			}
			sig, err := signsWithTheKeysMadeHere(issuer.AID, ipub, raw) // the issuer's one key signed every event
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, map[string]interface{}{
				"event_json": string(body), "raw_bytes_b64": kel.RawEventsB64[i], "cesr_signature": sig})
		}
		if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: issuer.AID, KEL: events, KelVerified: true}); err != nil {
			t.Fatal(err)
		}
	}
	// Held the way issue and delivery keep it: the body already in base64.
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID: issued.AcdcSaid, IssuerAID: issuer.AID, HolderAID: issuee,
		SchemaSAID: schema, AcdcJson: issued.AcdcJsonB64, Status: "issued", Format: "acdc",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.initLoginHandler(); err != nil {
		t.Fatal(err)
	}
	return &aGateWorld{s: s, schema: schema, issuer: issuer.AID, holder: holder.AID}
}

// presented is what the agent would put in its assertion, as the site reads it.
func (w *aGateWorld) presented(t *testing.T) []interface{} {
	t.Helper()
	held := w.s.loginHandler.HeldCredentials()
	raw, _ := json.Marshal(held)
	var out []interface{}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 1 {
		t.Fatalf("expected the one held credential, got %d (%v)", len(out), err)
	}
	return out
}

func (w *aGateWorld) gate(t *testing.T) (bool, string) {
	t.Helper()
	return w.s.credentialGateSatisfied(context.Background(), w.presented(t), w.holder, w.schema, w.issuer)
}

// A genuine held credential, as the agent presents it, passes the gate. Fails if
// the held body is encoded a second time on its way out.
func TestAGenuineHeldCredentialPassesTheCredentialGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, true)
	if ok, reason := w.gate(t); !ok {
		t.Fatalf("a genuine credential was refused: %s", reason)
	}
}

// The body is sent in one encoding whichever way it was kept.
func TestAHeldBodyIsEncodedOnceWhetherKeptEncodedOrPlain(t *testing.T) {
	const plain = `{"v":"ACDC10JSON"}`
	enc := acdcAsBase64(plain)
	if acdcAsBase64(enc) != enc {
		t.Fatal("an already-encoded body was encoded again")
	}
	if enc == plain || strings.HasPrefix(enc, "{") {
		t.Fatalf("a plain body was not encoded: %q", enc)
	}
}

// The credential's issuee must be the identity signing in.
func TestACredentialIssuedToSomebodyElseIsRefusedAtTheGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, false, true)
	ok, reason := w.gate(t)
	if ok {
		t.Fatal("a credential issued to somebody other than the identity signing in was accepted")
	}
	if !strings.Contains(reason, "subject") {
		t.Fatalf("the refusal does not say the holder is wrong: %q", reason)
	}
}

// The issuer's key log must be one the agent holds.
func TestACredentialWhoseIssuerLogIsNotHeldIsRefusedAtTheGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, false)
	ok, reason := w.gate(t)
	if ok {
		t.Fatal("a credential was accepted with no key log for its issuer")
	}
	if !strings.Contains(reason, "issuer KEL not found") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

// gateKeys holds the signers newKeyPair made, so an issuer engine can sign.
var gateKeys sync.Map

func signsWithTheKeysMadeHere(_, key string, raw []byte) (string, error) {
	v, ok := gateKeys.Load(key)
	if !ok {
		return "", fmt.Errorf("no key %q was made here", key)
	}
	sig, err := v.(*keri.SoftwareSigner).Sign(raw)
	if err != nil {
		return "", err
	}
	return keri.MatterQB64(keri.CodeEd25519Sig, sig)
}

func newKeyPair(t *testing.T) (pub, next string) {
	t.Helper()
	a, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	if pub, err = a.PublicKey(); err != nil {
		t.Fatal(err)
	}
	if next, err = b.PublicKey(); err != nil {
		t.Fatal(err)
	}
	gateKeys.Store(pub, a)
	return pub, next
}
