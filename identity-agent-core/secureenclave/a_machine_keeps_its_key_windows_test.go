//go:build windows

package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The machine's key survives the process that made it, on Windows.
//
// The counterpart of the macOS test, and the one that has never been run. The
// signer was written against the provider's documented contract on a Mac, so
// everything here is unproven until this passes on real hardware with a real
// TPM.
//
// Skips rather than fails where there is no usable TPM. Windows 11 cannot ship
// without one, but Windows 10 can, so a machine without one is an ordinary
// answer rather than a broken setup.
func TestAMachineKeepsItsKeyOnWindows(t *testing.T) {
	first := newTPMSigner()
	if !first.Available() {
		cap := HardwareRootStatus()
		t.Skipf("no usable TPM on this machine: %s", cap.String())
	}

	pub, err := first.PublicKey()
	if err != nil {
		t.Fatalf("a machine that has a key must be able to show it: %v", err)
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Fatalf("expected an uncompressed P-256 point, got %d bytes starting %#x", len(pub), pub[0])
	}

	t.Run("a second signer finds the same key rather than minting another", func(t *testing.T) {
		// What a restart looks like. A different key here means the machine
		// forgot who it was, and every grant made to it is void.
		second := newTPMSigner()
		if !second.Available() {
			t.Fatal("the stored key must be usable by a later process")
		}
		again, err := second.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, again) {
			t.Fatal("reopening produced a different key, so the machine is not the same machine")
		}
	})

	t.Run("what it signs verifies against the key it published", func(t *testing.T) {
		msg := []byte("this machine is asking to act for you")
		sig, err := first.Sign(msg)
		if err != nil {
			t.Fatalf("a machine must be able to prove it holds its own key: %v", err)
		}
		// Raw r||s, not DER. This provider produces that natively, which is what
		// CESR's secp256r1 signature code carries — so a wrong answer here means
		// the signature would need converting and the macOS and Windows paths
		// would stop being one path.
		if len(sig) != 64 {
			t.Fatalf("expected 64 bytes of raw r||s, got %d", len(sig))
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), pub)
		if x == nil {
			t.Fatal("the published key is not a point on P-256")
		}
		sum := sha256.Sum256(msg)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, sum[:], r, s) {
			t.Fatal("the signature does not verify against the machine's own published key")
		}
	})

	t.Run("the key is really in the TPM, not in software", func(t *testing.T) {
		// THE ASSERT THAT DISTINGUISHES REAL HARDWARE. Checking that the export
		// policy is "no export" proves nothing, because that is the default on
		// every provider including software ones. What separates them is that
		// this provider implements no export at all: asking for an exportable
		// key FAILS rather than quietly obliging.
		//
		// So a key that can be created exportable is not in a TPM, whatever the
		// provider is called.
		provider, err := openProvider()
		if err != nil {
			t.Fatalf("the platform crypto provider must open: %v", err)
		}
		defer procFreeObject.Call(uintptr(provider))

		name, err := windows.UTF16PtrFromString("IdentityAgentExportProbe.v1")
		if err != nil {
			t.Fatal(err)
		}
		algorithm, err := windows.UTF16PtrFromString("ECDSA_P256")
		if err != nil {
			t.Fatal(err)
		}
		var key windows.Handle
		if r, _, _ := procCreatePersistedKey.Call(uintptr(provider),
			uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algorithm)),
			uintptr(unsafe.Pointer(name)), 0, 0); r != 0 {
			t.Skipf("could not create a probe key (0x%X)", uint32(r))
		}
		defer procFreeObject.Call(uintptr(key))

		// NCRYPT_EXPORT_POLICY_PROPERTY set to allow export. This must be
		// refused; the value is NCRYPT_ALLOW_EXPORT_FLAG.
		policy, err := windows.UTF16PtrFromString("Export Policy")
		if err != nil {
			t.Fatal(err)
		}
		allow := uint32(0x00000001)
		setProperty := ncrypt.NewProc("NCryptSetProperty")
		r, _, _ := setProperty.Call(uintptr(key), uintptr(unsafe.Pointer(policy)),
			uintptr(unsafe.Pointer(&allow)), unsafe.Sizeof(allow), 0)
		if r == 0 {
			t.Error("this provider accepted an exportable key, so the key it holds is " +
				"not protected by a TPM — a key that can be exported is an authorisation " +
				"anybody who copies it holds")
		} else {
			t.Logf("exportable key refused (0x%X), which is what a real TPM does", uint32(r))
		}
	})
}
