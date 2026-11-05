// Package testkeys is the one place a test makes a P-256 machine key and signs
// with it.
//
// It signs the way the Secure Enclave and TPM signers do: SHA-256 over the
// message, then a raw r||s of 64 bytes with s in the low half of the order.
// Tests that signed with a bare ecdsa.Sign got a high-s signature half the
// time, which the verifier rightly refuses, so each copy grew its own loop to
// avoid it; this is that loop, once.
//
// Only tests import this package. TestOnlyTestsImportThisPackage fails the
// build of any other file that does.
package testkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Key is a P-256 key a test can sign with.
type Key struct{ Priv *ecdsa.PrivateKey }

// New makes a fresh key. A test that needs the same bytes every run uses FromD.
func New() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv}, nil
}

// FromD is the key whose private scalar is d.
func FromD(d *big.Int) *Key {
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	return &Key{priv}
}

// Compressed is the 33-byte SEC1 compressed public key.
func (k *Key) Compressed() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), k.Priv.X, k.Priv.Y)
}

// Uncompressed is the 65-byte SEC1 uncompressed public key.
func (k *Key) Uncompressed() []byte {
	return elliptic.Marshal(elliptic.P256(), k.Priv.X, k.Priv.Y)
}

// Sign signs SHA-256(msg) and returns raw r||s, 64 bytes, with s low.
func (k *Key) Sign(msg []byte) ([]byte, error) {
	sum := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k.Priv, sum[:])
	if err != nil {
		return nil, err
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}
