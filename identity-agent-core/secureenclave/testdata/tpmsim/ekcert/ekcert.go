// Package ekcert gives the simulator tools an endorsement key certificate shaped as a
// manufacturer's is (TCG EK Credential Profile): an empty subject, and the TPM named in a
// critical subject alternative name holding one directoryName with its manufacturer, model
// and version. The core must accept that shape, which crypto/x509 alone refuses.
package ekcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Template is an endorsement key certificate template with the given serial and validity.
func Template(serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		NotBefore:          notBefore, NotAfter: notAfter,
		ExtraExtensions: []pkix.Extension{subjectAltName()}}
}

func subjectAltName() pkix.Extension {
	name, err := asn1.Marshal(pkix.RDNSequence{{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:FFFFF1D0"}, // the TCG's own vendor id for a simulator
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "ms-tpm-20-ref"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:00010000"},
	}})
	if err != nil {
		panic(err)
	}
	v, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: v}
}
