// Package tpmcert reads the certificates of TPM makers that Go's X.509 reader refuses.
//
// Six of STMicroelectronics' issuer certificates in Microsoft's trusted TPM package
// encode their serial number with redundant leading zero bytes, which DER forbids and
// crypto/x509 rejects ("malformed serial number"). Nothing else about them is wrong, and
// the maker's chips' endorsement key certificates are issued under them, so a PC with such
// a chip could not be told to be a physical TPM at all.
//
// Parse accepts that one irregularity and nothing else: the serial is taken as the
// opaque INTEGER it is (this package never uses it), and every other field is read as
// strictly as crypto/x509 would, or refused. It is for certificates that are pinned by
// the SHA-256 of their bytes: the pin is what makes one trusted, never the parse. It does
// not check what building a chain would (key usage, name constraints, path length), so a
// caller checks the pin before calling Parse and never passes it a certificate it received.
package tpmcert

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Certificate is the part of a certificate a chain check needs.
type Certificate struct {
	Raw        []byte // the whole DER
	RawTBS     []byte // what the issuer signed
	RawIssuer  []byte
	RawSubject []byte
	Subject    pkix.Name
	NotBefore  time.Time
	NotAfter   time.Time
	IsCA       bool
	PublicKey  crypto.PublicKey

	SignatureAlgorithm x509.SignatureAlgorithm
	Signature          []byte
}

type validity struct{ NotBefore, NotAfter time.Time }

type tbsCertificate struct {
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     asn1.RawValue
	SigAlg     pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   validity
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	IssuerUID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type outer struct {
	TBS    asn1.RawValue
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	sigAlgs             = map[string]x509.SignatureAlgorithm{
		"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
		"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
		"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
		"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
		"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
		"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	}
)

// Parse reads one DER certificate. A certificate crypto/x509 reads is read the same here,
// so a caller need not try that first, but only the serial's leniency is intended.
func Parse(der []byte) (*Certificate, error) {
	var o outer
	if rest, err := asn1.Unmarshal(der, &o); err != nil {
		return nil, fmt.Errorf("tpmcert: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("tpmcert: trailing data after the certificate")
	}
	var t tbsCertificate
	if rest, err := asn1.Unmarshal(o.TBS.FullBytes, &t); err != nil {
		return nil, fmt.Errorf("tpmcert: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("tpmcert: trailing data in the certificate body")
	}
	if t.Version != 2 {
		return nil, fmt.Errorf("tpmcert: version %d is not a version 3 certificate", t.Version+1)
	}
	if t.Serial.Tag != asn1.TagInteger || t.Serial.Class != asn1.ClassUniversal || len(t.Serial.Bytes) == 0 {
		return nil, errors.New("tpmcert: the serial number is not an integer")
	}
	if !t.SigAlg.Algorithm.Equal(o.SigAlg.Algorithm) {
		return nil, errors.New("tpmcert: the two signature algorithms differ")
	}
	algo, ok := sigAlgs[o.SigAlg.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("tpmcert: signature algorithm %s is not accepted", o.SigAlg.Algorithm)
	}
	if o.Sig.BitLength%8 != 0 {
		return nil, errors.New("tpmcert: the signature is not whole bytes")
	}
	pub, err := x509.ParsePKIXPublicKey(t.PublicKey.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("tpmcert: public key: %w", err)
	}
	var name pkix.RDNSequence
	if rest, err := asn1.Unmarshal(t.Subject.FullBytes, &name); err != nil || len(rest) != 0 {
		return nil, errors.New("tpmcert: the subject is not readable")
	}
	c := &Certificate{
		Raw: der, RawTBS: o.TBS.FullBytes, RawIssuer: t.Issuer.FullBytes, RawSubject: t.Subject.FullBytes,
		NotBefore: t.Validity.NotBefore, NotAfter: t.Validity.NotAfter, PublicKey: pub,
		SignatureAlgorithm: algo, Signature: o.Sig.RightAlign(),
	}
	c.Subject.FillFromRDNSequence(&name)
	for _, e := range t.Extensions {
		if !e.Id.Equal(oidBasicConstraints) {
			continue
		}
		var bc struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}
		if rest, err := asn1.Unmarshal(e.Value, &bc); err != nil || len(rest) != 0 {
			return nil, errors.New("tpmcert: basic constraints are not readable")
		}
		c.IsCA = bc.IsCA
	}
	return c, nil
}

// CheckSignatureFrom reports whether parent's key made this certificate's signature.
func (c *Certificate) CheckSignatureFrom(parent crypto.PublicKey) error {
	return CheckSignature(c.SignatureAlgorithm, c.RawTBS, c.Signature, parent)
}

// CheckSignature checks signature over signed under key, with crypto/x509's rules, which
// refuse a weak hash.
func CheckSignature(algo x509.SignatureAlgorithm, signed, signature []byte, key crypto.PublicKey) error {
	return (&x509.Certificate{PublicKey: key}).CheckSignature(algo, signed, signature)
}
