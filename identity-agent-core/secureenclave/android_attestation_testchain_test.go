package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// A chain built the way the Keystore builds one, with a root the test holds, so
// the cases a real phone cannot be made to produce (a decrypt key, a software
// level, an imported key) can be checked. The real chains are in
// android_key_attestation_test.go.

type chainSpec struct {
	level        int  // 0 software, 1 TEE, 2 StrongBox
	attestSoft   bool // the attesting hardware's level; defaults to level
	challenge    string
	purposes     []int // hardware-enforced
	noAuth       bool
	imported     bool
	created      time.Time
	leafKey      *rsa.PublicKey
	rootKey      *ecdsa.PrivateKey // nil: a fresh one
	skipIntermed bool
	noOAEP       bool
	unlockedOnly bool
	dupPurpose   bool
	extraPadding int      // a second hardware-enforced padding beside OAEP; 0 none
	appPackage   string   // attestationApplicationId: the package; "" states none
	appDigests   [][]byte // ... and the signing certificate digests
}

// appIDDER is attestationApplicationId as the Keystore writes it.
func appIDDER(pkg string, digests [][]byte) []byte {
	set := func(body []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body}
	}
	info := mustDER(struct {
		Name    []byte
		Version int64
	}{[]byte(pkg), 1})
	var ds []byte
	for _, d := range digests {
		ds = append(ds, mustDER(d)...)
	}
	inner := mustDER(struct{ P, D asn1.RawValue }{set(info), set(ds)})
	return mustDER(inner) // an OCTET STRING holding the SEQUENCE
}

func explicit(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func mustDER(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func authListDER(items ...asn1.RawValue) asn1.RawValue {
	var body []byte
	for _, it := range items {
		body = append(body, mustDER(it)...)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}
}

func keyDescription(s chainSpec) []byte {
	var hw []asn1.RawValue
	if len(s.purposes) > 0 {
		var set []byte
		for _, p := range s.purposes {
			set = append(set, mustDER(p)...)
		}
		hw = append(hw, explicit(kmTagPurpose, mustDER(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: set})))
	}
	set := func(v int) []byte {
		return mustDER(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: mustDER(v)})
	}
	if !s.noOAEP {
		paddings := mustDER(kmPaddingOAEP)
		if s.extraPadding != 0 {
			paddings = append(paddings, mustDER(s.extraPadding)...)
		}
		hw = append(hw, explicit(kmTagDigest, set(kmDigestSHA256)),
			explicit(kmTagPadding, mustDER(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: paddings})))
	}
	if s.unlockedOnly {
		hw = append(hw, explicit(kmTagUnlockedDevice, mustDER(asn1.NullRawValue)))
	}
	if s.dupPurpose {
		hw = append(hw, explicit(kmTagPurpose, set(kmPurposeDecrypt)))
	}
	hw = append(hw, explicit(kmTagAlgorithm, mustDER(kmAlgorithmRSA)))
	if s.noAuth {
		hw = append(hw, explicit(kmTagNoAuthRequired, mustDER(asn1.NullRawValue)))
	}
	origin := kmOriginGen
	if s.imported {
		origin = 2
	}
	hw = append(hw, explicit(kmTagOrigin, mustDER(origin)))
	sw := []asn1.RawValue{explicit(kmTagCreationTime, mustDER(s.created.UnixMilli()))}
	if s.appPackage != "" {
		sw = append(sw, explicit(kmTagAppID, appIDDER(s.appPackage, s.appDigests)))
	}

	al := s.level
	if s.attestSoft {
		al = 0
	}
	return mustDER(struct {
		V      int
		AL     asn1.Enumerated
		KV     int
		KL     asn1.Enumerated
		Ch     []byte
		U      []byte
		SW, HW asn1.RawValue
	}{4, asn1.Enumerated(al), 4, asn1.Enumerated(s.level), []byte(s.challenge), nil, authListDER(sw...), authListDER(hw...)})
}

// builtChain returns the chain blob and the SPKI hash of the root to pin.
func builtChain(t *testing.T, s chainSpec) (chain []byte, root [sha256.Size]byte) {
	t.Helper()
	rootKey := s.rootKey
	if rootKey == nil {
		var err error
		if rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(tpl, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ca := func(n int64, cn string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: cn},
			NotBefore: s.created.Add(-24 * time.Hour), NotAfter: s.created.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	rootTpl := ca(1, "test attestation root")
	rootCert := mk(rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	signer, signerCert := any(rootKey), rootCert
	certs := [][]byte{}
	if !s.skipIntermed {
		ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ic := mk(ca(2, "test intermediate"), rootCert, &ik.PublicKey, rootKey)
		signer, signerCert = ik, ic
		certs = append(certs, ic.Raw)
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{Id: oidKeyDescription, Value: keyDescription(s)}}}
	leaf := mk(leafTpl, signerCert, s.leafKey, signer)
	all := append([][]byte{leaf.Raw}, certs...)
	all = append(all, rootCert.Raw)
	return JoinAttestationChain(all...), sha256.Sum256(rootCert.RawSubjectPublicKeyInfo)
}
