package didcomm

import (
	"encoding/json"
	"strings"
	"testing"
)

func mkJWM(t *testing.T, from, to, typ string, body any) *JWM {
	t.Helper()
	b, _ := json.Marshal(body)
	return &JWM{
		ID: "id-" + typ, Type: typ,
		From: "did:keri:" + from, To: []string{"did:keri:" + to},
		CreatedTime: "2026-07-29T00:00:00Z", ExpiresTime: "2026-07-29T01:00:00Z",
		Body: b,
	}
}

func TestAuthcryptRoundTrip(t *testing.T) {
	alice, err := GenerateKeySet("EAlice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeySet("EBob")
	if err != nil {
		t.Fatal(err)
	}
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()

	jwm := mkJWM(t, "EAlice", "EBob", TypeAgentMessage, map[string]string{"question": "what is 2+2?"})
	env, err := PackAuthcrypt(alice, bobDID, jwm)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if env.Protected.Skid != "EAlice" || env.Recipients[0].Header.Kid != "EBob" {
		t.Fatalf("header AIDs wrong: skid=%s kid=%s", env.Protected.Skid, env.Recipients[0].Header.Kid)
	}

	got, err := UnpackAuthcrypt(bob, aliceDID, env)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if got.ID != jwm.ID || got.Type != TypeAgentMessage {
		t.Fatalf("jwm mismatch: %+v", got)
	}
	var body map[string]string
	json.Unmarshal(got.Body, &body)
	if body["question"] != "what is 2+2?" {
		t.Fatalf("body mismatch: %v", body)
	}
}

func TestAuthcryptTamperCiphertext(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()
	env, _ := PackAuthcrypt(alice, bobDID, mkJWM(t, "EAlice", "EBob", TypeDirectMessage, map[string]string{"x": "y"}))
	before := env.Ciphertext
	env.Ciphertext = tamper(t, env.Ciphertext)
	if env.Ciphertext == before {
		t.Fatal("the ciphertext was not modified, so nothing was tested")
	}
	if _, err := UnpackAuthcrypt(bob, aliceDID, env); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

// tamper changes exactly one character of a base64url string, and is guaranteed
// to change it.
//
// The obvious spelling — overwrite the first character with a fixed one — does
// nothing when the character is already that one. The ciphertext here is random
// per run, so that happened roughly one run in sixty-four, and the test then
// decrypted an untouched envelope and failed for having succeeded. A test that
// fails at random teaches people to re-run it.
func tamper(t *testing.T, s string) string {
	t.Helper()
	if s == "" {
		t.Fatal("nothing to tamper with")
	}
	// Pick a replacement from the same alphabet that differs from what is there,
	// so the result stays decodable and the failure under test is integrity,
	// not a malformed encoding.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] != s[0] {
			return string(alphabet[i]) + s[1:]
		}
	}
	t.Fatalf("could not find a replacement character for %q", s[0])
	return ""
}

func TestAuthcryptWrongRecipient(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	eve, _ := GenerateKeySet("EEve")
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()
	env, _ := PackAuthcrypt(alice, bobDID, mkJWM(t, "EAlice", "EBob", TypeDirectMessage, map[string]string{"x": "y"}))
	// Eve is not the recipient — kid won't match, and even forcing it, decryption fails.
	if _, err := UnpackAuthcrypt(eve, aliceDID, env); err == nil {
		t.Fatal("wrong recipient must fail")
	}
}

func TestAuthcryptWrongSenderKey(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	mallory, _ := GenerateKeySet("EAlice") // same AID, different keys
	bobDID, _ := bob.DID()
	malloryDID, _ := mallory.DID()
	env, _ := PackAuthcrypt(alice, bobDID, mkJWM(t, "EAlice", "EBob", TypeDirectMessage, map[string]string{"x": "y"}))
	// Bob resolves the WRONG keys for EAlice (mallory's) → sender-auth ECDH mismatch.
	if _, err := UnpackAuthcrypt(bob, malloryDID, env); err == nil {
		t.Fatal("wrong sender key must fail (sender authentication)")
	}
}

func TestSignedRoundTripAndTamper(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	aliceDID, _ := alice.DID()
	env, err := PackSigned(alice, mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnpackSigned(aliceDID, env); err != nil {
		t.Fatalf("signed verify: %v", err)
	}
	beforeSig := env.EdSig
	env.EdSig = tamper(t, env.EdSig)
	if env.EdSig == beforeSig {
		t.Fatal("the signature was not modified, so nothing was tested")
	}
	if _, err := UnpackSigned(aliceDID, env); err == nil {
		t.Fatal("tampered signature must fail")
	}
}

func TestKeySetPersistence(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	blob, err := alice.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalKeySet(blob)
	if err != nil {
		t.Fatal(err)
	}
	// A message packed to the restored set's DID must decrypt with the restored keys.
	bob, _ := GenerateKeySet("EBob")
	bobDID, _ := bob.DID()
	restoredDID, _ := restored.DID()
	env, _ := PackAuthcrypt(bob, restoredDID, mkJWM(t, "EBob", "EAlice", TypeAgentMessage, map[string]int{"n": 42}))
	bobDID2, _ := bob.DID()
	if _, err := UnpackAuthcrypt(restored, bobDID2, env); err != nil {
		t.Fatalf("restored keyset cannot decrypt: %v", err)
	}
	_ = bobDID
}

// A received message can be shown later, to somebody without the recipient's
// key, to have come from its sender: the signed form kept from the envelope
// verifies against the sender's keys, and fails if a byte of it changes or if
// it is checked against anybody else's.
func TestAReceivedMessageCanBeProvedLater(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()
	sent := mkJWM(t, "EAlice", "EBob", TypeAgentMessage, map[string]string{"text": "ship it"})
	env, err := PackAuthcrypt(alice, bobDID, sent)
	if err != nil {
		t.Fatal(err)
	}
	got, signed, err := UnpackAuthcryptKeeping(bob, aliceDID, env)
	if err != nil || got.ID != sent.ID || len(signed) == 0 {
		t.Fatalf("unpack: %v %+v %d", err, got, len(signed))
	}

	again, err := VerifySignedMessage(aliceDID, signed)
	if err != nil || again.ID != sent.ID || string(again.Body) != string(got.Body) {
		t.Fatalf("the kept message does not prove itself: %v", err)
	}
	if _, err := VerifySignedMessage(bobDID, signed); err == nil {
		t.Fatal("a message was proved to come from somebody who did not sign it")
	}
	i := strings.Index(string(signed), "ship it")
	altered := append([]byte(nil), signed...)
	altered[i] = 'S'
	if _, err := VerifySignedMessage(aliceDID, altered); err == nil {
		t.Fatal("an altered message still proved itself")
	}
}

// A message names its own sender and recipient inside what was signed, and
// those must be the ones it was authenticated as: a sender cannot sign words
// that read as somebody else's.
func TestASignedMessageNamesItsParties(t *testing.T) {
	m := mkJWM(t, "EAlice", "EBob", TypeAgentMessage, map[string]string{"text": "hi"})
	if err := m.NamesParties("EAlice", "EBob"); err != nil {
		t.Fatalf("a message naming its own parties was refused: %v", err)
	}
	if err := m.NamesParties("EMallory", "EBob"); err == nil {
		t.Fatal("a message naming another sender was taken as the authenticated sender's")
	}
	if err := m.NamesParties("EAlice", "ECarol"); err == nil {
		t.Fatal("a message addressed to somebody else was taken as addressed to this recipient")
	}
}
