package server

import (
	"strings"
	"testing"

	"identity-agent-core/didcomm"
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

func b64urlOf(b []byte) string {
	return didcomm.EncodeKeyForTest(b)
}
