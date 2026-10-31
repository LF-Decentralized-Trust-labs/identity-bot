package didcomm

import (
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
