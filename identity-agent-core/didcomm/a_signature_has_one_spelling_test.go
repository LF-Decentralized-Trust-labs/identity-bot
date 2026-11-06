package didcomm

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each half of a hybrid signature is read in its one canonical string. The
// Ed25519 half leaves 4 spare bits in its last character, and read leniently
// it had 16 strings that all verified; either half with a line break inside
// it read as the original.
func TestARespelledHybridSignatureIsRefused(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alice, _ := GenerateKeySet("EAlice")
	aliceDID, _ := alice.DID()
	env, err := PackSigned(alice, mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnpackSigned(aliceDID, env); err != nil {
		t.Fatalf("the canonical message did not verify: %v", err)
	}
	last := len(env.EdSig) - 1
	v := strings.IndexByte(alphabet, env.EdSig[last])
	for name, mutate := range map[string]func(e *Envelope){
		"ed spare bits":  func(e *Envelope) { e.EdSig = e.EdSig[:last] + string(alphabet[v|1]) },
		"ed line break":  func(e *Envelope) { e.EdSig = e.EdSig[:10] + "\n" + e.EdSig[10:] },
		"dsa line break": func(e *Envelope) { e.DsaSig = e.DsaSig[:10] + "\n" + e.DsaSig[10:] },
	} {
		e := *env
		mutate(&e)
		if _, err := UnpackSigned(aliceDID, &e); err == nil {
			t.Errorf("%s: the respelled signature verified", name)
		}
	}
}

// A known peer's envelope is never accepted on its classical signature alone.
// What admits a sealed request as the owner's (isSealedOwnerRequest in the
// server package) is the sender this check names, and the check needs the
// Ed25519 signature AND the ML-DSA-65 one under the sender's published keys.
// So a stage-two owner cannot be admitted on a known-peer envelope signed
// classically: one with the second signature missing, empty, or made by
// another key is refused here, whatever the first says.
func TestAKnownPeersMessageNeedsBothSignatures(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	other, _ := GenerateKeySet("EOther")
	aliceDID, _ := alice.DID()
	bobDID, _ := bob.DID()
	env, err := PackAuthcrypt(alice, bobDID, mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"}))
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err := UnpackAuthcryptKeeping(bob, aliceDID, env)
	if err != nil {
		t.Fatalf("the whole message did not verify: %v", err)
	}
	var sj signedJWM
	if err := json.Unmarshal(signed, &sj); err != nil {
		t.Fatal(err)
	}
	otherSigned, _ := PackSigned(other, mkJWM(t, "EAlice", "EBob", TypeContactRequest, map[string]string{"hi": "there"}))
	for name, dsa := range map[string]string{
		"missing":          "",
		"another key's":    otherSigned.DsaSig,
		"the wrong length": sj.DsaSig[:len(sj.DsaSig)-4],
	} {
		forged := sj
		forged.DsaSig = dsa
		raw, _ := json.Marshal(forged)
		if _, err := VerifySignedMessage(aliceDID, raw); err == nil {
			t.Errorf("a message with its post-quantum signature %s was accepted on the classical one", name)
		}
	}
}
