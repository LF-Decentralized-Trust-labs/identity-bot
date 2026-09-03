//go:build darwin && cgo && sepblob

package secureenclave_test

import (
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// The two halves have to agree, and this is the only test that can prove it.
//
// One side is the Secure Enclave: real hardware, a real P-256 key, a real
// signature. The other is the encoding a grant records and a request is checked
// against. Everything else in this area is a unit test of one half against a
// fixture of the other, which is exactly how the Dart and Go sides drifted into
// producing identifiers neither could read.
//
// So this signs with the machine's own key and verifies through the same
// functions the controller path uses — nothing simulated on either side.
func TestWhatTheEnclaveSignsVerifiesThroughTheMachinePath(t *testing.T) {
	signer := secureenclave.NewPlatformSigner(t.TempDir())
	if !secureenclave.UsingHardware(signer) {
		t.Skip("no usable hardware key on this machine")
	}

	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	aid, err := iacrypto.MachineAIDForKey(pub)
	if err != nil {
		t.Fatalf("a machine holding a key must be nameable: %v", err)
	}
	verkey, err := iacrypto.MachineVerkeyForKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the identifier and the key are the same key", func(t *testing.T) {
		// What a grant checks before it will admit anything: an identifier that
		// IS a key cannot name a different one.
		named, err := iacrypto.KeyFromMachineIdentifier(aid)
		if err != nil {
			t.Fatalf("the agent must be able to read its own identifier: %v", err)
		}
		fromVerkey, err := iacrypto.KeyFromMachineIdentifier(iacrypto.CodeP256N + verkey[4:])
		if err != nil {
			t.Fatal(err)
		}
		if string(named) != string(fromVerkey) {
			t.Fatal("the identifier and the verification key name different keys")
		}
	})

	t.Run("a signature the enclave made verifies", func(t *testing.T) {
		msg := []byte("this machine is asking to act for you")
		raw, err := signer.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := iacrypto.MachineSignatureQB64(pub, raw)
		if err != nil {
			t.Fatalf("a signature from this machine's own key must encode: %v", err)
		}
		ok, err := iacrypto.VerifyMachineSignature(verkey, sig, msg)
		if err != nil {
			t.Fatalf("verification failed outright: %v", err)
		}
		if !ok {
			t.Fatal("the enclave's own signature did not verify against the key it published")
		}
	})

	t.Run("a signature over something else does not verify", func(t *testing.T) {
		raw, err := signer.Sign([]byte("one message"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := iacrypto.MachineSignatureQB64(pub, raw)
		if err != nil {
			t.Fatal(err)
		}
		ok, _ := iacrypto.VerifyMachineSignature(verkey, sig, []byte("a different message"))
		if ok {
			t.Fatal("a signature must not verify over a message it was not made for")
		}
	})

	t.Run("the signature is not claimed to be Ed25519", func(t *testing.T) {
		// The failure a length check cannot catch: both signatures are 64 bytes,
		// so a P-256 signature encodes cleanly under the Ed25519 code and lies
		// about what it is. Deciding the code from the key is the only defence,
		// and this is what proves that is what happens.
		raw, err := signer.Sign([]byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := iacrypto.MachineSignatureQB64(pub, raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := sig[:2]; got != iacrypto.CodeP256Sig {
			t.Fatalf("a P-256 signature must carry %q, got %q", iacrypto.CodeP256Sig, got)
		}
	})
}
