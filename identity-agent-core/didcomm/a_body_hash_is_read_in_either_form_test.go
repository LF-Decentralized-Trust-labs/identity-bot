package didcomm

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/zeebo/blake3"

	"identity-agent-core/iacrypto"
)

// The two forms are what they say: the CESR one is the digest of the body in
// qb64 with code E, and the earlier one is E and the raw digest in base64url.
func TestTheTwoBodyHashFormsAreWhatTheySay(t *testing.T) {
	body := []byte(`{"hi":"there"}`)
	sum := blake3.Sum256(body)
	if raw, err := iacrypto.DecodeQB64("E", cesrBodyHash(body), 32); err != nil || string(raw) != string(sum[:]) {
		t.Fatalf("the CESR body_hash is not the CESR digest of the body: %v", err)
	}
	if got, want := bodyHashBeforeCESR(body), "E"+base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("the earlier body_hash is %q, want %q", got, want)
	}
}

// A new message is written with the form writeCESRBodyHash names, and only
// that form: a kept message carries it, and a signed plaintext is signed over
// it and not over the other.
func TestANewMessageIsWrittenWithTheFormTheSwitchNames(t *testing.T) {
	want, other := bodyHashBeforeCESR, cesrBodyHash
	if writeCESRBodyHash {
		want, other = cesrBodyHash, bodyHashBeforeCESR
	}
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()
	jwm := mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"})

	env, err := PackAuthcrypt(alice, bobDID, jwm)
	if err != nil {
		t.Fatal(err)
	}
	got, signed, err := UnpackAuthcryptKeeping(bob, aliceDID, env)
	if err != nil {
		t.Fatal(err)
	}
	var sj signedJWM
	if err := json.Unmarshal(signed, &sj); err != nil {
		t.Fatal(err)
	}
	if sj.BodyHash != want(got.Body) {
		t.Fatalf("a new message carries body_hash %q, not the form the switch names", sj.BodyHash)
	}

	plain, err := PackSigned(alice, jwm)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := base64.RawURLEncoding.DecodeString(plain.Plain)
	var carried JWM
	_ = json.Unmarshal(canonical, &carried)
	edSig, dsaSig, _ := hybridSignatures(plain.EdSig, plain.DsaSig)
	pd, _ := aliceDID.parse()
	if !verifyHybrid(pd, signInput(canonical, want(carried.Body)), edSig, dsaSig) {
		t.Fatal("a new signed plaintext is not signed over the form the switch names")
	}
	if verifyHybrid(pd, signInput(canonical, other(carried.Body)), edSig, dsaSig) {
		t.Fatal("a new signed plaintext is signed over the other form")
	}
}

// signedOver is a signed message as a sender writing the given body_hash form
// writes it, kept and as a signed plaintext.
func signedOver(t *testing.T, k *KeySet, jwm *JWM, form func([]byte) string) (kept []byte, plain *Envelope) {
	t.Helper()
	jwm, err := withNormalisedBody(jwm)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(jwm)
	h := form(jwm.Body)
	edSig, dsaSig := signHybrid(k, signInput(canonical, h))
	kept, _ = json.Marshal(signedJWM{JWM: canonical, BodyHash: h,
		EdSig: b64.EncodeToString(edSig), DsaSig: b64.EncodeToString(dsaSig)})
	plain = &Envelope{Mode: "signed", Protected: ProtectedHeader{Alg: "none", Enc: "none", Skid: k.AID},
		Plain: b64.EncodeToString(canonical), EdSig: b64.EncodeToString(edSig), DsaSig: b64.EncodeToString(dsaSig)}
	return kept, plain
}

// A message signed over either form verifies, kept or as a signed plaintext:
// from a sender on either side of the switch, countersigned or kept before or
// after it.
func TestAMessageSignedOverEitherBodyHashFormVerifies(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	aliceDID, _ := alice.DID()
	for name, form := range map[string]func([]byte) string{"CESR": cesrBodyHash, "earlier": bodyHashBeforeCESR} {
		jwm := mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": name})
		kept, plain := signedOver(t, alice, jwm, form)
		if _, err := VerifySignedMessage(aliceDID, kept); err != nil {
			t.Errorf("a kept message signed over the %s body_hash: %v", name, err)
		}
		if _, err := UnpackSigned(aliceDID, plain); err != nil {
			t.Errorf("a signed plaintext signed over the %s body_hash: %v", name, err)
		}
	}
}

// A kept message's body_hash is accepted only as one of the two its body
// gives, and only under a signature that covers it: re-signed by its own
// sender over any other value it is refused, and respelled into the other form
// without the sender's key it no longer verifies, in either direction.
func TestAKeptBodyHashIsOnlyEitherFormItsBodyGives(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	aliceDID, _ := alice.DID()
	jwm, _ := withNormalisedBody(mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"}))

	other := func([]byte) string { return iacrypto.Blake3QB64Must([]byte("another body")) }
	kept, _ := signedOver(t, alice, jwm, other)
	if _, err := VerifySignedMessage(aliceDID, kept); err == nil || err.Error() != "body_hash_mismatch" {
		t.Fatalf("a body_hash its body does not give was accepted: %v", err)
	}

	for _, swap := range [][2]func([]byte) string{{bodyHashBeforeCESR, cesrBodyHash}, {cesrBodyHash, bodyHashBeforeCESR}} {
		kept, _ := signedOver(t, alice, jwm, swap[0])
		var sj signedJWM
		_ = json.Unmarshal(kept, &sj)
		sj.BodyHash = swap[1](jwm.Body)
		respelled, _ := json.Marshal(sj)
		if _, err := VerifySignedMessage(aliceDID, respelled); err == nil {
			t.Fatal("a kept message respelled into the other body_hash form verified")
		}
	}
}
