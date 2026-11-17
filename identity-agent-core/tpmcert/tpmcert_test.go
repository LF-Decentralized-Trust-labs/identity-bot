package tpmcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// A CA certificate of our own, and its key, to take apart and sign again.
func aCertificate(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x8a01), Subject: pkix.Name{CommonName: "STM TPM EK Intermediate CA 99"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

type certParts struct {
	TBS    asn1.RawValue
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
}

// reshape takes der apart, lets change alter the body's fields (each a TLV), and signs it
// again with k, so a refusal is the change's and not a broken signature's.
func reshape(t *testing.T, der []byte, k *ecdsa.PrivateKey, change func(fields []asn1.RawValue) []asn1.RawValue, outer func(*certParts)) []byte {
	t.Helper()
	var c certParts
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(c.TBS.FullBytes, &fields); err != nil {
		t.Fatal(err)
	}
	if change != nil {
		fields = change(fields)
	}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, d[:])
	c.TBS = asn1.RawValue{FullBytes: tbs}
	c.Sig = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	if outer != nil {
		outer(&c)
	}
	out, err := asn1.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func serial(content ...byte) asn1.RawValue {
	full, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: content})
	return asn1.RawValue{FullBytes: full}
}

func withSerial(content ...byte) func([]asn1.RawValue) []asn1.RawValue {
	return func(f []asn1.RawValue) []asn1.RawValue { f[1] = serial(content...); return f }
}

// A certificate crypto/x509 reads is read the same here.
func TestAWellFormedCertificateIsReadAsCryptoX509ReadsIt(t *testing.T) {
	der, k := aCertificate(t)
	want, _ := x509.ParseCertificate(der)
	got, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsCA || got.Subject.CommonName != want.Subject.CommonName || !bytes.Equal(got.RawTBS, want.RawTBSCertificate) ||
		!got.NotAfter.Equal(want.NotAfter) || !got.PublicKey.(*ecdsa.PublicKey).Equal(&k.PublicKey) {
		t.Fatalf("read differently: %+v", got)
	}
	if err := got.CheckSignatureFrom(&k.PublicKey); err != nil {
		t.Fatal(err)
	}
}

// The one irregularity taken: a serial with redundant leading zeros, which crypto/x509 refuses.
func TestASerialWithRedundantLeadingZerosIsTheOneIrregularityTaken(t *testing.T) {
	der, k := aCertificate(t)
	odd := reshape(t, der, k, withSerial(0x00, 0x00, 0x8a, 0x01), nil)
	if _, err := x509.ParseCertificate(odd); err == nil {
		t.Fatal("crypto/x509 was expected to refuse the serial, so this test would show nothing")
	}
	c, err := Parse(odd)
	if err != nil {
		t.Fatalf("the leading-zero serial was refused: %v", err)
	}
	if err := c.CheckSignatureFrom(&k.PublicKey); err != nil {
		t.Fatal(err)
	}
}

// Anything else crypto/x509 would refuse, or that this package does not read, is refused.
func TestEveryOtherIrregularityIsRefused(t *testing.T) {
	der, k := aCertificate(t)
	sha1RSA := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}}
	cases := map[string][]byte{
		"a negative serial":                       reshape(t, der, k, withSerial(0x8a, 0x01), nil),
		"a negative serial with a redundant byte": reshape(t, der, k, withSerial(0xff, 0x8a, 0x01), nil),
		"a serial that is not an integer": reshape(t, der, k, func(f []asn1.RawValue) []asn1.RawValue {
			full, _ := asn1.Marshal([]byte{1, 2})
			f[1] = asn1.RawValue{FullBytes: full}
			return f
		}, nil),
		"an empty serial":  reshape(t, der, k, withSerial(), nil),
		"a version 1 body": reshape(t, der, k, func(f []asn1.RawValue) []asn1.RawValue { return f[1:] }, nil),
		"trailing data":    append(append([]byte{}, der...), 0x00),
		"the two algorithms differing": reshape(t, der, k, nil, func(c *certParts) {
			c.SigAlg = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}
		}),
		"a SHA-1 signature algorithm": reshape(t, der, k, func(f []asn1.RawValue) []asn1.RawValue {
			full, _ := asn1.Marshal(sha1RSA)
			f[2] = asn1.RawValue{FullBytes: full}
			return f
		}, func(c *certParts) { c.SigAlg = sha1RSA }),
		"a signature that is not whole bytes": reshape(t, der, k, nil, func(c *certParts) { c.Sig.BitLength-- }),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A serial written as a constructed value is not an integer, however its bytes read.
func TestAConstructedSerialIsRefused(t *testing.T) {
	der, k := aCertificate(t)
	odd := reshape(t, der, k, func(f []asn1.RawValue) []asn1.RawValue {
		full, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, IsCompound: true, Bytes: []byte{0x02, 0x01, 0x01}})
		f[1] = asn1.RawValue{FullBytes: full}
		return f
	}, nil)
	if _, err := Parse(odd); err == nil {
		t.Fatal("accepted")
	}
}
