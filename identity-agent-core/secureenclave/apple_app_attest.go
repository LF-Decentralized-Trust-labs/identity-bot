package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// appleAppAttestRootPEM is the Apple App Attestation Root CA certificate,
// downloaded over TLS on 2026-11-13 from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
// (self-signed, valid to 2045-03-15, SHA-256 fingerprint
// 1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932).
// The root, not its hash, is pinned because Apple's attestation carries only
// the leaf and an intermediate: checking the intermediate's signature needs the
// root's key.
const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

var oidAppleAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

const (
	aaguidAppAttestProduction  = "appattest\x00\x00\x00\x00\x00\x00\x00"
	aaguidAppAttestDevelopment = "appattestdevelop"
)

// VerifyAppleAppAttest checks an Apple App Attest attestation object (the
// CBOR the device returns from attestKey) for the key the app asked for with
// challenge, for the app appID ("<team id>.<bundle id>"), following Apple's
// published steps. The Apple receipt is required to be present but is not
// checked: that needs a call to Apple.
func VerifyAppleAppAttest(attestationObject, challenge []byte, appID string, now time.Time) (*InstalledAppKeyFacts, error) {
	if appleAppAttestRootPEM == "" {
		return nil, notAttested("the Apple App Attestation root is not pinned in this build, so no Apple attestation can be trusted")
	}
	b, _ := pem.Decode([]byte(appleAppAttestRootPEM))
	if b == nil {
		return nil, notAttested("the pinned Apple App Attestation root does not parse")
	}
	root, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, notAttested("the pinned Apple App Attestation root does not parse: %v", err)
	}
	return verifyAppleAppAttest(attestationObject, challenge, appID, now, []*x509.Certificate{root})
}

func verifyAppleAppAttest(obj, challenge []byte, appID string, now time.Time, roots []*x509.Certificate) (*InstalledAppKeyFacts, error) {
	if len(roots) == 0 {
		return nil, notAttested("no Apple root is pinned")
	}
	if len(challenge) == 0 || appID == "" {
		return nil, notAttested("a challenge and an app identifier are both required")
	}
	top, err := cborDecodeAll(obj)
	if err != nil {
		return nil, notAttested("the attestation object is not valid CBOR: %v", err)
	}
	m, ok := top.(cborMap)
	if !ok {
		return nil, notAttested("the attestation object is not a map")
	}
	if f, ok := m.text("fmt").(string); !ok || f != "apple-appattest" {
		return nil, notAttested("the attestation format is not apple-appattest")
	}
	stmt, ok := m.text("attStmt").(cborMap)
	if !ok {
		return nil, notAttested("the attestation statement is missing")
	}
	if r, ok := stmt.text("receipt").([]byte); !ok || len(r) == 0 {
		return nil, notAttested("the attestation has no receipt")
	}
	x5c, ok := stmt.text("x5c").([]any)
	if !ok || len(x5c) < 2 || len(x5c) > 4 {
		return nil, notAttested("the certificate chain is missing or the wrong length")
	}
	certs := make([]*x509.Certificate, len(x5c))
	for i, e := range x5c {
		der, ok := e.([]byte)
		if !ok {
			return nil, notAttested("a chain entry is not a certificate")
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, notAttested("a chain certificate does not parse: %v", err)
		}
	}
	authData, ok := m.text("authData").([]byte)
	if !ok {
		return nil, notAttested("the authenticator data is missing")
	}

	// 1. The chain runs from the credential certificate to a pinned root.
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, notAttested("the chain does not lead to the pinned Apple root: %v", err)
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, notAttested("the credential key is not a P-256 key")
	}
	point, err := pub.ECDH()
	if err != nil {
		return nil, notAttested("the credential key is not a valid point")
	}
	keyHash := sha256.Sum256(point.Bytes())

	// 2-3. nonce = SHA256(authData || SHA256(challenge)) must be the one in the certificate.
	ch := sha256.Sum256(challenge)
	want := sha256.Sum256(append(append([]byte{}, authData...), ch[:]...))
	var got []byte
	n := 0
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidAppleAppAttestNonce) {
			n++
			var v struct {
				Nonce []byte `asn1:"tag:1,explicit"`
			}
			if rest, err := asn1.Unmarshal(e.Value, &v); err != nil || len(rest) != 0 {
				return nil, notAttested("the nonce extension does not parse")
			}
			got = v.Nonce
		}
	}
	if n != 1 {
		return nil, notAttested("the credential certificate must carry the nonce extension exactly once")
	}
	if !bytes.Equal(got, want[:]) {
		return nil, notAttested("the nonce is not the one for this challenge")
	}

	// 4-7. authenticator data.
	if len(authData) < 55 {
		return nil, notAttested("the authenticator data is too short")
	}
	rp := sha256.Sum256([]byte(appID))
	if !bytes.Equal(authData[:32], rp[:]) {
		return nil, notAttested("the attestation is for a different app")
	}
	if authData[32]&0x40 == 0 {
		return nil, notAttested("the authenticator data carries no credential")
	}
	if binary.BigEndian.Uint32(authData[33:37]) != 0 {
		return nil, notAttested("the counter is not zero: this is not a fresh attestation")
	}
	switch string(authData[37:53]) {
	case aaguidAppAttestProduction:
	case aaguidAppAttestDevelopment:
		if !isDevBuild() {
			return nil, notAttested("a development-environment attestation is refused in a production build")
		}
	default:
		return nil, notAttested("the authenticator is not App Attest")
	}
	idLen := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+idLen {
		return nil, notAttested("the credential id runs past the authenticator data")
	}
	if !bytes.Equal(authData[55:55+idLen], keyHash[:]) {
		return nil, notAttested("the credential id is not the hash of the credential key")
	}
	if rest := authData[55+idLen:]; len(rest) > 0 {
		k, err := cborDecodeAll(rest)
		if err != nil {
			return nil, notAttested("the credential key does not parse: %v", err)
		}
		cm, ok := k.(cborMap)
		if !ok {
			return nil, notAttested("the credential key is not a COSE map")
		}
		x, _ := cm.int(-2).([]byte)
		y, _ := cm.int(-3).([]byte)
		if kty, _ := cm.int(1).(int64); kty != 2 || len(x) != 32 || len(y) != 32 ||
			new(big.Int).SetBytes(x).Cmp(pub.X) != 0 || new(big.Int).SetBytes(y).Cmp(pub.Y) != 0 {
			return nil, notAttested("the key in the authenticator data is not the certificate's key")
		}
	}
	return &InstalledAppKeyFacts{Public: pub, Platform: "apple", Level: "secure_enclave",
		AppleAppID: appID, AppIDPresent: true}, nil
}

// ---- a minimal strict CBOR decoder (RFC 8949), only what attestation uses ----

type cborPair struct{ k, v any }
type cborMap []cborPair

func (m cborMap) text(k string) any {
	for _, p := range m {
		if s, ok := p.k.(string); ok && s == k {
			return p.v
		}
	}
	return nil
}

func (m cborMap) int(k int64) any {
	for _, p := range m {
		if i, ok := p.k.(int64); ok && i == k {
			return p.v
		}
	}
	return nil
}

var errCBOR = errors.New("malformed or unsupported CBOR")

func cborDecodeAll(b []byte) (any, error) {
	v, rest, err := cborDecode(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after CBOR item")
	}
	return v, nil
}

// cborDecode reads one item. It refuses indefinite lengths, non-minimal
// integer encodings, tags, floats, simple values, duplicate map keys, and
// nesting deeper than 8.
func cborDecode(b []byte, depth int) (any, []byte, error) {
	if depth > 8 || len(b) == 0 {
		return nil, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		n := 1 << (info - 24)
		if len(b) < n {
			return nil, nil, errCBOR
		}
		for _, c := range b[:n] {
			arg = arg<<8 | uint64(c)
		}
		b = b[n:]
		if (info == 24 && arg < 24) || (info == 25 && arg < 1<<8) || (info == 26 && arg < 1<<16) || (info == 27 && arg < 1<<32) {
			return nil, nil, errCBOR
		}
	default:
		return nil, nil, errCBOR
	}
	switch major {
	case 0:
		if arg > 1<<62 {
			return nil, nil, errCBOR
		}
		return int64(arg), b, nil
	case 1:
		if arg > 1<<62 {
			return nil, nil, errCBOR
		}
		return -1 - int64(arg), b, nil
	case 2, 3:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		s := b[:arg]
		if major == 3 {
			return string(s), b[arg:], nil
		}
		return append([]byte{}, s...), b[arg:], nil
	case 4:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var v any
			var err error
			if v, b, err = cborDecode(b, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, b, nil
	case 5:
		if arg > uint64(len(b)) {
			return nil, nil, errCBOR
		}
		out := make(cborMap, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var k, v any
			var err error
			if k, b, err = cborDecode(b, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case string, int64:
			default:
				return nil, nil, errCBOR
			}
			for _, p := range out {
				if p.k == k {
					return nil, nil, errors.New("duplicate CBOR map key")
				}
			}
			if v, b, err = cborDecode(b, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, cborPair{k, v})
		}
		return out, b, nil
	}
	return nil, nil, errCBOR
}
