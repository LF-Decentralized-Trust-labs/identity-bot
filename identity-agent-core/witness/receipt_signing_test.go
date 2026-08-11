package witness

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// Accepting an event is the path that issues a receipt, and until now nothing
// exercised it — both existing tests stop at a rejection, which is why a
// "signature" that involved no key survived here unnoticed.
func acceptOneEvent(t *testing.T, s *Service) (map[string]interface{}, error) {
	t.Helper()
	// A real inception, signed by the key it declares.
	//
	// It has to be real now: a witness validates before it receipts, so a
	// hand-written stand-in is refused for being what it is. That is the
	// behaviour these tests exist to protect, so they build a genuine event
	// rather than working around it.
	signer, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	next, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKey()
	nextPub, _ := next.PublicKey()
	digest, err := keri.NextDigest(nextPub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub}, NextDigests: []string{digest}, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	cesrSig, err := keri.MatterQB64(keri.CodeEd25519Sig, sigRaw)
	if err != nil {
		t.Fatal(err)
	}

	mc := s.Contacts.(*memContacts)
	mc.contacts[ev.Identifier] = store.ContactRecord{AID: ev.Identifier, Status: "accepted"}
	_ = s.Store.SaveContactMeta(ContactMeta{
		ContactAID: ev.Identifier, WitnessingFor: true, BackendType: BackendDesktop,
	})
	return s.ReceiveEvent(ev.Identifier, raw, cesrSig)
}

// A witness with no key says nothing, rather than saying something that cannot
// be checked. The controller has to be able to tell its event was not witnessed.
func TestAWitnessWithNoKeyRefusesToReceipt(t *testing.T) {
	s, _ := testService(t)
	s.SignReceipt = nil

	if _, err := acceptOneEvent(t, s); err == nil {
		t.Fatal("issued a receipt with no key to sign it with")
	} else if !strings.Contains(err.Error(), "witnessing key") {
		t.Errorf("the reason should name the missing key, got: %v", err)
	}
}

// The value in the receipt has to depend on a secret. The version this replaces
// was a hash of the receipt itself, so two different witnesses handed the same
// event produced the same "signature" — and anybody holding the event could
// produce it too.
func TestAReceiptDependsOnTheWitnessKeyAndNotOnlyOnTheEvent(t *testing.T) {
	sigs := make([]string, 0, 2)
	for _, secret := range []byte{1, 2} {
		s, _ := testService(t)
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = secret
		key := ed25519.NewKeyFromSeed(seed)
		s.SignReceipt = func(said string) (string, string, error) {
			return "BWitness", "0B" + string(ed25519.Sign(key, []byte(said))[:8]), nil
		}
		out, err := acceptOneEvent(t, s)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		sig, _ := out["cesr_signature"].(string)
		if sig == "" {
			t.Fatal("no signature in the receipt")
		}
		sigs = append(sigs, sig)
	}
	if sigs[0] == sigs[1] {
		t.Fatal("two witnesses with different keys produced the same receipt, so the " +
			"receipt does not depend on any key")
	}
}

// The witness names itself with the identifier its key belongs to, so a verifier
// knows which key to check against.
func TestTheReceiptCarriesTheWitnessIdentifier(t *testing.T) {
	s, _ := testService(t)
	s.SignReceipt = func(said string) (string, string, error) {
		return "BWitnessIdentifier", "0Bsig", nil
	}
	out, err := acceptOneEvent(t, s)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if out["witness_aid"] != "BWitnessIdentifier" {
		t.Errorf("witness_aid is %v", out["witness_aid"])
	}
	rct, _ := out["receipt"].(map[string]interface{})
	if rct["i"] != "BWitnessIdentifier" {
		t.Errorf("the receipt names %v as the witness", rct["i"])
	}
}

// A signer that fails must stop the receipt, not produce a blank one.
func TestAFailedSignatureIsNotIssuedAsAReceipt(t *testing.T) {
	s, _ := testService(t)
	s.SignReceipt = func(said string) (string, string, error) {
		return "", "", errTest
	}
	if _, err := acceptOneEvent(t, s); err == nil {
		t.Fatal("a receipt was issued despite the signature failing")
	}
}

var errTest = errTestType("the key is unavailable")

type errTestType string

func (e errTestType) Error() string { return string(e) }
