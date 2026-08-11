package server

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

func aDID(t *testing.T, aid string) *didcomm.DID {
	t.Helper()
	ks, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func signingPair(t *testing.T, b byte) ([]byte, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return seed, iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// THE ONE THAT MATTERS. Keys that nothing ties to an identifier could belong to
// anybody — including whoever answered the request for them, which on rented
// hardware is the party the encryption exists to exclude.
func TestKeysThatAreNotTiedToTheIdentifierAreRefused(t *testing.T) {
	did := aDID(t, "ETHEIRS")
	_, verkey := signingPair(t, 7)

	trust, err := checkPeerKeys(did, nil, verkey)
	if err == nil {
		t.Fatal("keys with nothing connecting them to the identifier were accepted")
	}
	if trust != peerKeysUntied {
		t.Errorf("trust reported as %q", trust)
	}
	if !strings.Contains(err.Error(), "neither commits") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

// Signed by the identity's current key: acceptable, and reported as the weaker
// of the two so a caller can tell them apart.
func TestKeysSignedByTheIdentityAreAccepted(t *testing.T) {
	did := aDID(t, "ETHEIRS")
	seed, verkey := signingPair(t, 11)
	sig, err := login.SignString(string(did.SigningInput()), seed)
	if err != nil {
		t.Fatal(err)
	}
	did.KelSig = sig

	trust, cerr := checkPeerKeys(did, nil, verkey)
	if cerr != nil {
		t.Fatalf("properly vouched-for keys were refused: %v", cerr)
	}
	if trust != peerKeysVouched {
		t.Errorf("trust reported as %q, want %q", trust, peerKeysVouched)
	}
}

// Somebody else's signature must not do. This is the substitution the whole
// check exists to stop.
func TestKeysSignedBySomebodyElseAreRefused(t *testing.T) {
	did := aDID(t, "ETHEIRS")
	attackerSeed, _ := signingPair(t, 90)
	_, realVerkey := signingPair(t, 11)

	sig, err := login.SignString(string(did.SigningInput()), attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	did.KelSig = sig

	if _, cerr := checkPeerKeys(did, nil, realVerkey); cerr == nil {
		t.Fatal("keys signed by somebody else were accepted")
	}
}

// A signature over one set of keys must not carry over to another.
func TestASignatureDoesNotCoverDifferentKeys(t *testing.T) {
	did := aDID(t, "ETHEIRS")
	seed, verkey := signingPair(t, 11)
	sig, _ := login.SignString(string(did.SigningInput()), seed)

	swapped := aDID(t, "ETHEIRS")
	swapped.KelSig = sig // the attacker's keys, the real identity's signature

	if _, err := checkPeerKeys(swapped, nil, verkey); err == nil {
		t.Fatal("a signature over one set of keys was accepted for another")
	}
}

// Anchored is the strong path: the identifier commits to the keys in its own
// inception, so nothing else has to be trusted.
func TestKeysCommittedInTheIdentifierAreAcceptedWithoutASignature(t *testing.T) {
	m := iacrypto.SyntheticHybridKeyMaterial(5)
	built, err := iacrypto.BuildHybridInception(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	did := &didcomm.DID{
		AID:    built.AID,
		X25519: b64urlOf(m.X25519AgreementRaw),
		MlKem:  b64urlOf(m.MLKEM768EncapRaw),
		Suite:  didcomm.CipherSuite,
	}

	trust, cerr := checkPeerKeys(did, []map[string]interface{}{event}, "")
	if cerr != nil {
		t.Fatalf("keys the identifier commits to were refused: %v", cerr)
	}
	if trust != peerKeysAnchored {
		t.Errorf("trust reported as %q, want %q", trust, peerKeysAnchored)
	}
}

// And an anchored identifier must refuse keys other than the ones it committed
// to, whoever signed for them.
func TestAnAnchoredIdentifierRefusesOtherKeys(t *testing.T) {
	m := iacrypto.SyntheticHybridKeyMaterial(5)
	built, _ := iacrypto.BuildHybridInception(m)
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	other := aDID(t, built.AID)
	seed, verkey := signingPair(t, 21)
	other.KelSig, _ = login.SignString(string(other.SigningInput()), seed)

	if _, err := checkPeerKeys(other, []map[string]interface{}{event}, verkey); err == nil {
		t.Fatal("an anchored identifier accepted keys it never committed to, because they were signed")
	}
}

func b64urlOf(b []byte) string {
	return didcomm.EncodeKeyForTest(b)
}
