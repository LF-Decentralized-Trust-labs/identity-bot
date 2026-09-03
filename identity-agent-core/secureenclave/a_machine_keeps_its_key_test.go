//go:build darwin && cgo && sepblob

package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// The machine's key survives the process that made it.
//
// This is the whole requirement, and the reason the keychain was in the picture
// at all: a controller is granted authority once and must still be the same
// machine tomorrow. A key that cannot outlive its process cannot be granted
// anything.
//
// It runs against the real Secure Enclave, so it is skipped where there is none.
// That is deliberate rather than a gap — the thing being checked is the hardware
// behaviour, and a fake would only prove the fake works.
func TestAMachineKeepsItsKey(t *testing.T) {
	dir := t.TempDir()
	first := newSepSigner(dir)
	if !first.Available() {
		t.Skip("no usable Secure Enclave on this machine")
	}

	pub, err := first.PublicKey()
	if err != nil {
		t.Fatalf("a machine that has a key must be able to show it: %v", err)
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Fatalf("expected an uncompressed P-256 point, got %d bytes starting %#x", len(pub), pub[0])
	}

	t.Run("the key is on disk, and only readable by its owner", func(t *testing.T) {
		p := filepath.Join(dir, "secureenclave", "machine_key.sep")
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("the wrapped key must be written where it can be found again: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("the wrapped key is the machine's authority; mode %04o is too open", perm)
		}
	})

	t.Run("a second signer finds the same key rather than minting another", func(t *testing.T) {
		// THE POINT OF ALL OF THIS. A fresh signer over the same directory is
		// what a restart looks like. A different key here means the machine
		// forgot who it was, and every grant made to it is void.
		second := newSepSigner(dir)
		if !second.Available() {
			t.Fatal("the stored key must be usable by a later process")
		}
		again, err := second.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, again) {
			t.Fatal("a restart produced a different key, so the machine is not the same machine")
		}
	})

	t.Run("what it signs verifies against the key it published", func(t *testing.T) {
		msg := []byte("this machine is asking to act for you")
		sig, err := first.Sign(msg)
		if err != nil {
			t.Fatalf("a machine must be able to prove it holds its own key: %v", err)
		}
		// Raw r||s, not DER — that is what CESR's secp256r1 signature code
		// carries, and taking it in that form is why no unwrapping step exists.
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

	t.Run("a damaged key is refused, not handed to the enclave", func(t *testing.T) {
		// CryptoKit does not return an error on a blob of the wrong size, it
		// traps — so this must be caught here or a corrupt file takes the whole
		// agent down. Truncating the envelope's blob is the cheap way to be sure
		// the guard is doing something.
		bad := t.TempDir()
		s := newSepSigner(bad).(*sepSigner)
		if err := s.ensure(); err != nil {
			t.Skip("cannot mint a key to damage")
		}
		p := filepath.Join(bad, "secureenclave", "machine_key.sep")
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		// Cut the file short: valid JSON is no longer parseable, which is the
		// commonest real corruption.
		if err := os.WriteFile(p, data[:len(data)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := newSepSigner(bad).(*sepSigner)
		if _, err := fresh.read(); err == nil {
			t.Fatal("a truncated key file must be refused rather than restored")
		}
	})
}
