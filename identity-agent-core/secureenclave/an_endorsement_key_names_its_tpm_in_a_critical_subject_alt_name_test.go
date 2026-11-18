package secureenclave

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

// tcgSubjectAltName is the subject alternative name a real endorsement key certificate
// carries, critical because its subject is empty: one directoryName naming the TPM's
// manufacturer, model and version (TCG EK Credential Profile). attrs replaces the three
// attributes when given.
func tcgSubjectAltName(t *testing.T, attrs ...pkix.AttributeTypeAndValue) pkix.Extension {
	t.Helper()
	if len(attrs) == 0 {
		attrs = []pkix.AttributeTypeAndValue{
			{Type: oidTPMManufacturer, Value: "id:49465800"},
			{Type: oidTPMModel, Value: "SLB9670"},
			{Type: oidTPMVersion, Value: "id:00070055"},
		}
	}
	return subjectAltNameOf(t, directoryName(t, pkix.RDNSequence{pkix.RelativeDistinguishedNameSET(attrs)}))
}

func directoryName(t *testing.T, rdns pkix.RDNSequence) asn1.RawValue {
	t.Helper()
	name, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}
}

func subjectAltNameOf(t *testing.T, names ...asn1.RawValue) pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: v}
}

// The shape every real endorsement key certificate has is accepted under a pinned physical
// issuer: without the TCG rule crypto/x509 refuses it for an unhandled critical extension.
func TestARealShapedEndorsementKeyCertificateIsAcceptedUnderAPinnedIssuer(t *testing.T) {
	c := newEKChain(t, "IFX-KEYID-1")
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	leaf, err := x509.ParseCertificate(c.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Subject.Names) != 0 || len(leaf.UnhandledCriticalExtensions) != 1 || !leaf.UnhandledCriticalExtensions[0].Equal(oidSubjectAltName) {
		t.Fatalf("the test certificate is not shaped as a real one: subject %v, unhandled %v", leaf.Subject, leaf.UnhandledCriticalExtensions)
	}
	got, iss, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now)
	if err != nil {
		t.Fatalf("a real-shaped endorsement key certificate was refused: %v", err)
	}
	if iss.Class != TPMClassPhysical || len(got.UnhandledCriticalExtensions) != 0 {
		t.Fatalf("issuer %+v, unhandled %v", iss, got.UnhandledCriticalExtensions)
	}
	// The same certificate given straight to crypto/x509 is refused, which is what the rule is for.
	pool := x509.NewCertPool()
	pool.AddCert(c.root)
	inter := x509.NewCertPool()
	inter.AddCert(c.issuer)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: c.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	var unhandled x509.UnhandledCriticalExtension
	if !errors.As(err, &unhandled) {
		t.Fatalf("crypto/x509 alone was expected to refuse the critical SAN, got %v", err)
	}
}

func otherName(t *testing.T, id asn1.ObjectIdentifier) asn1.RawValue {
	t.Helper()
	inner, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x0c, 0x02, 'i', 'd'}})
	oid, _ := asn1.Marshal(id)
	v, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oid, v...)}
}

// Beside the TPM's directoryName, the device-identity otherNames go-attestation takes are taken.
func TestATPMsDirectoryNameWithADeviceIdentityOtherNameIsAccepted(t *testing.T) {
	tpm := directoryName(t, pkix.RDNSequence{{{Type: oidTPMManufacturer, Value: "id:49465800"}, {Type: oidTPMModel, Value: "SLB9670"}, {Type: oidTPMVersion, Value: "id:00070055"}}})
	for name, other := range map[string]asn1.ObjectIdentifier{"permanentIdentifier": oidPermanentIdentifier, "hardwareModuleName": oidHardwareModuleName} {
		t.Run(name, func(t *testing.T) {
			c := newEKChainWithLeafExtensions(t, "IFX-KEYID-1", []pkix.Extension{subjectAltNameOf(t, tpm, otherName(t, other))})
			withIssuers(t, []*x509.Certificate{c.issuer}, nil)
			if _, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now); err != nil {
				t.Fatal(err)
			}
		})
	}
	c := newEKChainWithLeafExtensions(t, "IFX-KEYID-1", []pkix.Extension{subjectAltNameOf(t, tpm, otherName(t, asn1.ObjectIdentifier{1, 2, 3, 4}))})
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	if _, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now); err == nil {
		t.Fatal("an otherName of another kind was taken")
	}
	c = newEKChainWithLeafExtensions(t, "IFX-KEYID-1", []pkix.Extension{subjectAltNameOf(t, otherName(t, oidPermanentIdentifier))})
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	if _, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now); err == nil {
		t.Fatal("a critical SAN with no directoryName was taken")
	}
}

// A critical SAN that holds anything but the TCG directoryName stays unhandled.
func TestACriticalSubjectAltNameWithOtherContentIsRefused(t *testing.T) {
	cases := map[string]pkix.Extension{
		"a DNS name beside the TPM's name": subjectAltNameOf(t,
			directoryName(t, pkix.RDNSequence{{{Type: oidTPMManufacturer, Value: "id:49465800"}, {Type: oidTPMModel, Value: "SLB9670"}, {Type: oidTPMVersion, Value: "id:00070055"}}}),
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("tpm.example")}),
		"a directoryName with a common name": tcgSubjectAltName(t,
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: "id:49465800"},
			pkix.AttributeTypeAndValue{Type: oidTPMModel, Value: "SLB9670"},
			pkix.AttributeTypeAndValue{Type: oidTPMVersion, Value: "id:00070055"},
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "anything"}),
		"no TPM version": tcgSubjectAltName(t,
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: "id:49465800"},
			pkix.AttributeTypeAndValue{Type: oidTPMModel, Value: "SLB9670"}),
		"the manufacturer twice": tcgSubjectAltName(t,
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: "id:49465800"},
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: "id:49465800"},
			pkix.AttributeTypeAndValue{Type: oidTPMModel, Value: "SLB9670"},
			pkix.AttributeTypeAndValue{Type: oidTPMVersion, Value: "id:00070055"}),
		"two directoryNames": subjectAltNameOf(t,
			directoryName(t, pkix.RDNSequence{{{Type: oidTPMManufacturer, Value: "id:49465800"}, {Type: oidTPMModel, Value: "SLB9670"}, {Type: oidTPMVersion, Value: "id:00070055"}}}),
			directoryName(t, pkix.RDNSequence{{{Type: oidTPMManufacturer, Value: "id:49465800"}, {Type: oidTPMModel, Value: "SLB9670"}, {Type: oidTPMVersion, Value: "id:00070055"}}})),
		"a manufacturer that is not a string": tcgSubjectAltName(t,
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: 7},
			pkix.AttributeTypeAndValue{Type: oidTPMModel, Value: "SLB9670"},
			pkix.AttributeTypeAndValue{Type: oidTPMVersion, Value: "id:00070055"}),
	}
	for name, ext := range cases {
		t.Run(name, func(t *testing.T) {
			c := newEKChainWithLeafExtensions(t, "IFX-KEYID-1", []pkix.Extension{ext})
			withIssuers(t, []*x509.Certificate{c.issuer}, nil)
			_, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now)
			if err == nil || !strings.Contains(err.Error(), "subject alternative name is not the TPM's") {
				t.Fatalf("accepted, or refused for another reason: %v", err)
			}
		})
	}
}

// A critical extension other than the SAN is never taken as handled, beside the TCG SAN or alone.
func TestAnotherCriticalExtensionIsRefused(t *testing.T) {
	other := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{0x05, 0x00}}
	for name, exts := range map[string][]pkix.Extension{
		"beside the TCG SAN": {tcgSubjectAltName(t), other},
		"alone":              {other},
	} {
		t.Run(name, func(t *testing.T) {
			c := newEKChainWithLeafExtensions(t, "IFX-KEYID-1", exts)
			withIssuers(t, []*x509.Certificate{c.issuer}, nil)
			_, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now)
			if err == nil || !strings.Contains(err.Error(), "unhandled critical extension") {
				t.Fatalf("accepted, or refused for another reason: %v", err)
			}
		})
	}
}
