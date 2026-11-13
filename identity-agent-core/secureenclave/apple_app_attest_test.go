package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}
func cbBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cbText(s string) []byte  { return append(cborHead(3, len(s)), s...) }

type appleSpec struct {
	challenge, nonceFor []byte
	appID, authAppID    string
	counter             uint32
	aaguid              string
	credID              []byte
	noReceipt           bool
}

// appleAttestation builds an object like Apple's and returns the root to pin.
func appleAttestation(t *testing.T, s appleSpec) ([]byte, *x509.Certificate) {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	mk := func(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	now := time.Now()
	ca := func(n int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "t"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
	}
	rk, ik, lk := gen(), gen(), gen()
	rootTpl := ca(1)
	root := mk(rootTpl, rootTpl, &rk.PublicKey, rk)
	inter := mk(ca(2), root, &ik.PublicKey, rk)

	point, _ := lk.PublicKey.ECDH()
	keyHash := sha256.Sum256(point.Bytes())
	credID := s.credID
	if credID == nil {
		credID = keyHash[:]
	}
	authApp := s.authAppID
	if authApp == "" {
		authApp = s.appID
	}
	rp := sha256.Sum256([]byte(authApp))
	aaguid := s.aaguid
	if aaguid == "" {
		aaguid = aaguidAppAttestProduction
	}
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, 0x40)
	ad = binary.BigEndian.AppendUint32(ad, s.counter)
	ad = append(ad, aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(credID)))
	ad = append(ad, credID...)
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01} // kty 2, alg -7, crv 1
	cose = append(cose, 0x21)
	cose = append(cose, cbBytes(lk.PublicKey.X.FillBytes(make([]byte, 32)))...)
	cose = append(cose, 0x22)
	cose = append(cose, cbBytes(lk.PublicKey.Y.FillBytes(make([]byte, 32)))...)
	ad = append(ad, cose...)

	nonceChal := s.nonceFor
	if nonceChal == nil {
		nonceChal = s.challenge
	}
	ch := sha256.Sum256(nonceChal)
	nonce := sha256.Sum256(append(append([]byte{}, ad...), ch[:]...))
	ext, _ := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonce[:]})
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAppleAppAttestNonce, Value: ext}}}
	leaf := mk(leafTpl, inter, &lk.PublicKey, ik)

	var o []byte
	o = append(o, 0xa3)
	o = append(o, cbText("fmt")...)
	o = append(o, cbText("apple-appattest")...)
	o = append(o, cbText("attStmt")...)
	if s.noReceipt {
		o = append(o, 0xa1)
	} else {
		o = append(o, 0xa2)
	}
	o = append(o, cbText("x5c")...)
	o = append(o, 0x82)
	o = append(o, cbBytes(leaf.Raw)...)
	o = append(o, cbBytes(inter.Raw)...)
	if !s.noReceipt {
		o = append(o, cbText("receipt")...)
		o = append(o, cbBytes([]byte("receipt-bytes"))...)
	}
	o = append(o, cbText("authData")...)
	o = append(o, cbBytes(ad)...)
	return o, root
}

func TestAppleAppAttest(t *testing.T) {
	chal := []byte("challenge-from-core")
	const app = "TEAM123456.org.example.app"
	good := appleSpec{challenge: chal, appID: app}
	dev := func(v bool) {
		p := isDevBuild
		isDevBuild = func() bool { return v }
		t.Cleanup(func() { isDevBuild = p })
	}

	t.Run("accepts a good attestation", func(t *testing.T) {
		dev(false)
		obj, root := appleAttestation(t, good)
		f, err := verifyAppleAppAttest(obj, chal, app, time.Now(), []*x509.Certificate{root})
		if err != nil {
			t.Fatal(err)
		}
		if f.Platform != "apple" || f.Level != "secure_enclave" || f.AppleAppID != app || !f.AppIDPresent || f.Public == nil {
			t.Fatalf("facts: %+v", f)
		}
	})

	refused := map[string]struct {
		spec  appleSpec
		chal  []byte
		appID string
		dev   bool
	}{
		"wrong challenge":       {good, []byte("other"), app, false},
		"wrong app id":          {good, chal, "TEAM123456.org.other", false},
		"counter not zero":      {appleSpec{challenge: chal, appID: app, counter: 1}, chal, app, false},
		"credential id differs": {appleSpec{challenge: chal, appID: app, credID: bytes.Repeat([]byte{7}, 32)}, chal, app, false},
		"develop in production": {appleSpec{challenge: chal, appID: app, aaguid: aaguidAppAttestDevelopment}, chal, app, false},
		"unknown aaguid":        {appleSpec{challenge: chal, appID: app, aaguid: "notappattest-xxx"}, chal, app, true},
		"no receipt":            {appleSpec{challenge: chal, appID: app, noReceipt: true}, chal, app, false},
		"empty challenge":       {good, nil, app, false},
	}
	for name, c := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			dev(c.dev)
			obj, root := appleAttestation(t, c.spec)
			_, err := verifyAppleAppAttest(obj, c.chal, c.appID, time.Now(), []*x509.Certificate{root})
			if !errors.Is(err, ErrNotAttested) {
				t.Fatalf("want ErrNotAttested, got %v", err)
			}
		})
	}

	t.Run("refuses a certificate whose nonce was made over another challenge", func(t *testing.T) {
		dev(false)
		obj, root := appleAttestation(t, appleSpec{challenge: chal, appID: app, nonceFor: []byte("other")})
		if _, err := verifyAppleAppAttest(obj, chal, app, time.Now(), []*x509.Certificate{root}); !errors.Is(err, ErrNotAttested) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("refuses an unpinned root", func(t *testing.T) {
		dev(false)
		obj, _ := appleAttestation(t, good)
		_, other := appleAttestation(t, good)
		if _, err := verifyAppleAppAttest(obj, chal, app, time.Now(), []*x509.Certificate{other}); !errors.Is(err, ErrNotAttested) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("refuses an expired chain", func(t *testing.T) {
		dev(false)
		obj, root := appleAttestation(t, good)
		if _, err := verifyAppleAppAttest(obj, chal, app, time.Now().Add(48*time.Hour), []*x509.Certificate{root}); !errors.Is(err, ErrNotAttested) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("accepts develop only in a dev build", func(t *testing.T) {
		dev(true)
		obj, root := appleAttestation(t, appleSpec{challenge: chal, appID: app, aaguid: aaguidAppAttestDevelopment})
		if _, err := verifyAppleAppAttest(obj, chal, app, time.Now(), []*x509.Certificate{root}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the public entry point refuses a chain that does not end at Apple's pinned root", func(t *testing.T) {
		obj, _ := appleAttestation(t, good)
		if _, err := VerifyAppleAppAttest(obj, chal, app, time.Now()); !errors.Is(err, ErrNotAttested) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the pinned root is Apple's, self-signed", func(t *testing.T) {
		b, _ := pem.Decode([]byte(appleAppAttestRootPEM))
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil || c.CheckSignatureFrom(c) != nil || c.Subject.CommonName != "Apple App Attestation Root CA" {
			t.Fatalf("the pinned root is not Apple's self-signed root: %v", err)
		}
		if sum := sha256.Sum256(c.Raw); hex.EncodeToString(sum[:]) != "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932" {
			t.Fatal("the pinned root's fingerprint is not the one noted when it was downloaded")
		}
	})
}

func TestAppleCBORIsStrict(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":                {},
		"trailing":             {0x01, 0x00},
		"indefinite array":     {0x9f, 0xff},
		"non-minimal int":      {0x18, 0x05},
		"truncated bytes":      {0x45, 1, 2},
		"tag":                  {0xc1, 0x01},
		"float":                {0xf9, 0, 0},
		"duplicate key":        {0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
		"bytes as a map key":   {0xa1, 0x41, 1, 0x01},
		"huge declared length": {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := cborDecodeAll(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := cborDecodeAll(bytes.Repeat([]byte{0x81}, 20)); err == nil {
		t.Error("deep nesting accepted")
	}
	if _, err := cborDecodeAll(bytes.Repeat([]byte{0xff, 0x00}, 3)); err == nil {
		t.Error("garbage accepted")
	}
}
