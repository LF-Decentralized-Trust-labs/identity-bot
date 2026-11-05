package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	acdc   string // the credential's body as issued, base64
}

// Where the agent holds the issuer's key log.
type issuerLogHeld int

const (
	logNotHeld       issuerLogHeld = iota // the issuer is nobody this agent knows
	logHeldAsContact                      // a verified log kept for a contact
	logHeldAsOwn                          // this agent's own log: the issuer is its organisation
)

func aGateWorldIssuingTo(t *testing.T, issueeIsSigner, agentHoldsIssuerLog bool) *aGateWorld {
	t.Helper()
	held := logNotHeld
	if agentHoldsIssuerLog {
		held = logHeldAsContact
	}
	return aGateWorldHolding(t, issueeIsSigner, held)
}

// How the credential the agent holds came to be.
type howIssued int

const (
	issuedByTheIssuer       howIssued = iota // issued into the issuer's registry and anchored in its log
	forgedWithNoRegistry                     // built by anybody, naming the issuer, with no registry
	forgedInIssuersRegistry                  // names the issuer's registry; an issuance event the issuer never anchored
	forgedWithNoLogHeld                      // names the issuer's registry; no transaction log is held
)

func aGateWorldHolding(t *testing.T, issueeIsSigner bool, held issuerLogHeld) *aGateWorld {
	t.Helper()
	return aGateWorldWhere(t, issueeIsSigner, held, issuedByTheIssuer)
}

func aGateWorldWhere(t *testing.T, issueeIsSigner bool, held issuerLogHeld, how howIssued) *aGateWorld {
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
	if how != issuedByTheIssuer {
		// Anybody can build a credential naming any issuer. The issuer's real
		// credential above stays unused: its log is the only thing it leaves.
		registry := ""
		if how != forgedWithNoRegistry {
			registry = reg.RegistrySaid
		}
		acdc, err := keri.BuildCredential(keri.CredentialInput{
			SchemaSAID: schema, Issuer: issuer.AID, Recipient: issuee, Registry: registry,
			Data: json.RawMessage(`{"role":"engineer","dt":"2026-11-05T00:00:00.000000+00:00"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		cred, err := keri.VerifyCredential(acdc)
		if err != nil {
			t.Fatal(err)
		}
		if how == forgedInIssuersRegistry {
			iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: cred.SAID, Registry: registry, DT: "2026-11-05T00:00:00.000000+00:00"})
			if err != nil {
				t.Fatal(err)
			}
			ev, err := keri.VerifyTELEvent(iss)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.DataStore.AppendCredentialTELEvent(store.CredentialTELEvent{
				RegistrySAID: registry, AcdcSAID: cred.SAID, Seq: 0, SAID: ev.SAID, Kind: "iss",
				RawB64: base64.StdEncoding.EncodeToString(iss),
			}); err != nil {
				t.Fatal(err)
			}
		}
		issued.AcdcSaid, issued.AcdcJsonB64 = cred.SAID, base64.StdEncoding.EncodeToString(acdc)
	} else {
		// The issuer's transaction log for the credential, as this core keeps it.
		tel, err := issuerEngine.CredentialLog("issuer", reg.RegistrySaid, issued.AcdcSaid)
		if err != nil {
			t.Fatal(err)
		}
		for i, raw := range tel {
			ev, _ := keri.VerifyTELEvent(mustDecode(t, raw))
			if err := s.DataStore.AppendCredentialTELEvent(store.CredentialTELEvent{
				RegistrySAID: reg.RegistrySaid, AcdcSAID: issued.AcdcSaid, Seq: i, SAID: ev.SAID, Kind: ev.Ilk, RawB64: raw,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if held != logNotHeld {
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
		if held == logHeldAsContact {
			if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: issuer.AID, KEL: events, KelVerified: true}); err != nil {
				t.Fatal(err)
			}
		} else {
			// Kept the way an agent keeps its own log: one record per event.
			for i, ev := range events {
				if err := s.DataStore.SaveEvent(store.EventRecord{
					AID: issuer.AID, SequenceNumber: i, EventType: kel.KEL[i]["t"].(string),
					EventJSON: ev["event_json"].(string), RawBytesB64: kel.RawEventsB64[i],
					CesrSignature: ev["cesr_signature"].(string),
				}); err != nil {
					t.Fatal(err)
				}
			}
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
	return &aGateWorld{s: s, schema: schema, issuer: issuer.AID, holder: holder.AID, acdc: issued.AcdcJsonB64}
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

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
