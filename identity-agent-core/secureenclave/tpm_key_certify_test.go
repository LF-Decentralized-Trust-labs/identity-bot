package secureenclave

// Synthetic TPM structures, built to the TCG layout by the helpers below. No
// TPM produced any of this: it proves the verifier agrees with the layout the
// tests were written from, and that each refusal fires, not that a real TPM's
// output parses. See the file header of tpm_key_certify.go.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func tpm16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
func tpm32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
func tpm2B(b []byte) []byte { return append(tpm16(len(b)), b...) }
func cat(parts ...[]byte) []byte {
	var o []byte
	for _, p := range parts {
		o = append(o, p...)
	}
	return o
}
func pad32(b *big.Int) []byte { return b.FillBytes(make([]byte, 32)) }

const (
	attrKeyGood = tpmAttrFixedTPM | tpmAttrFixedParent | tpmAttrSensitiveDataOrig | tpmAttrSign
	attrAKGood  = attrKeyGood | tpmAttrRestricted
)

// eccPublic builds a TPM2B_PUBLIC for a P-256 key; scheme is ECDSA/SHA-256.
func eccPublic(attrs uint32, pub *ecdsa.PublicKey) []byte {
	area := cat(tpm16(tpmAlgECC), tpm16(tpmAlgSHA256), tpm32(attrs), tpm2B(nil),
		tpm16(tpmAlgNull), tpm16(tpmAlgECDSA), tpm16(tpmAlgSHA256), tpm16(tpmCurveP256), tpm16(tpmAlgNull),
		tpm2B(pad32(pub.X)), tpm2B(pad32(pub.Y)))
	return tpm2B(area)
}

func rsaPublic(attrs uint32, pub *rsa.PublicKey, scheme int) []byte {
	area := cat(tpm16(tpmAlgRSA), tpm16(tpmAlgSHA256), tpm32(attrs), tpm2B(nil),
		tpm16(tpmAlgNull), tpm16(scheme), tpm16(tpmAlgSHA256), tpm16(2048), tpm32(0),
		tpm2B(pub.N.Bytes()))
	return tpm2B(area)
}

func nameOf(t *testing.T, tpm2bPublic []byte) []byte {
	p, err := parseTPM2BPublic(tpm2bPublic)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := p.name()
	return n
}

func certifyInfo(extra, name []byte) []byte {
	return cat(tpm32(tpmGeneratedValue), tpm16(tpmSTAttestCertify), tpm2B([]byte("signer")), tpm2B(extra),
		make([]byte, 17), make([]byte, 8), tpm2B(name), tpm2B([]byte("qualified")))
}

type tpmFixture struct {
	root          *x509.Certificate
	rootK         *ecdsa.PrivateKey
	key           *ecdsa.PrivateKey
	ak            *ecdsa.PrivateKey
	ek            *ecdsa.PrivateKey
	chal, credKey []byte
	keyPub        []byte
	akPub         []byte
	ekCert        []byte
	now           time.Time
	// tweaks
	info, sig, cred []byte
}

func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func ekCertFor(t *testing.T, ek *ecdsa.PublicKey, ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "EK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment, UnknownExtKeyUsage: nil}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, ek, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newFixture(t *testing.T, keyAttrs, akAttrs uint32) *tpmFixture {
	f := &tpmFixture{now: time.Now(), chal: []byte("core-chosen-challenge"), credKey: bytes.Repeat([]byte{0x5c}, TPMCredentialKeyLen)}
	f.root, f.rootK = newCA(t, "Test TPM Root")
	f.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.ak, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.ek, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.keyPub = eccPublic(keyAttrs, &f.key.PublicKey)
	f.akPub = eccPublic(akAttrs, &f.ak.PublicKey)
	f.ekCert = ekCertFor(t, &f.ek.PublicKey, f.root, f.rootK)
	return f
}

func ecdsaSig(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return cat(tpm16(tpmAlgECDSA), tpm16(tpmAlgSHA256), tpm2B(r.Bytes()), tpm2B(s.Bytes()))
}

func (f *tpmFixture) evidence(t *testing.T) []byte {
	info := f.info
	if info == nil {
		info = certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
	}
	sig := f.sig
	if sig == nil {
		sig = ecdsaSig(t, f.ak, info)
	}
	cred := f.cred
	if cred == nil {
		ekDER, _ := x509.MarshalPKIXPublicKey(&f.ek.PublicKey)
		cred = tpmCredentialSecret(f.credKey, nameOf(t, f.akPub), ekDER)
	}
	b, err := json.Marshal(tpmKeyCertifyEvidence{KeyPublic: f.keyPub, CertifyInfo: info, CertifySignature: sig,
		AKPublic: f.akPub, EKCert: f.ekCert, CredentialSecret: cred})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *tpmFixture) verify(t *testing.T, roots []*x509.Certificate) (*InstalledAppKeyFacts, error) {
	return verifyTPMKeyCertify(f.evidence(t), f.chal, f.credKey, f.now, roots)
}

func wantRefused(t *testing.T, f *InstalledAppKeyFacts, err error) {
	t.Helper()
	if err == nil || f != nil || !errors.Is(err, ErrNotAttested) {
		t.Fatalf("want ErrNotAttested refusal, got facts=%v err=%v", f, err)
	}
}

func TestTPMKeyCertifyAccepts(t *testing.T) {
	f := newFixture(t, attrKeyGood, attrAKGood)
	got, err := f.verify(t, []*x509.Certificate{f.root})
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != "tpm" || got.Level != "tpm" || got.AppIDPresent || len(got.AppPackages) != 0 || got.AppleAppID != "" {
		t.Fatalf("facts %+v", got)
	}
	if !got.Public.Equal(&f.key.PublicKey) {
		t.Fatal("wrong public key returned")
	}
}

func TestTPMKeyCertifyAcceptsRSAAttestationKeys(t *testing.T) {
	for _, scheme := range []int{tpmAlgRSASSA, tpmAlgRSAPSS} {
		f := newFixture(t, attrKeyGood, attrAKGood)
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		f.akPub = rsaPublic(attrAKGood, &rk.PublicKey, scheme)
		info := certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
		d := sha256.Sum256(info)
		var s []byte
		if scheme == tpmAlgRSASSA {
			s, _ = rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, d[:])
		} else {
			s, _ = rsa.SignPSS(rand.Reader, rk, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		f.info, f.sig = info, cat(tpm16(scheme), tpm16(tpmAlgSHA256), tpm2B(s))
		if _, err := f.verify(t, []*x509.Certificate{f.root}); err != nil {
			t.Fatalf("scheme %x: %v", scheme, err)
		}
	}
}

func TestTPMKeyCertifyFailsClosedWithNoRoots(t *testing.T) {
	f := newFixture(t, attrKeyGood, attrAKGood)
	got, err := f.verify(t, nil)
	wantRefused(t, got, err)
	// The shipped variable is empty, so the public entry point refuses too.
	got, err = VerifyTPMKeyCertify(f.evidence(t), f.chal, f.credKey, f.now)
	wantRefused(t, got, err)
}

func TestTPMKeyCertifyRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, f *tpmFixture) []*x509.Certificate{
		"non-restricted AK": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.akPub = eccPublic(attrAKGood&^tpmAttrRestricted, &f.ak.PublicKey)
			return nil
		},
		"AK not fixedTPM": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.akPub = eccPublic(attrAKGood&^tpmAttrFixedTPM, &f.ak.PublicKey)
			return nil
		},
		"key not fixedTPM": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood&^tpmAttrFixedTPM, &f.key.PublicKey)
			return nil
		},
		"key not fixedParent": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood&^tpmAttrFixedParent, &f.key.PublicKey)
			return nil
		},
		"imported key (no sensitiveDataOrigin)": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood&^tpmAttrSensitiveDataOrig, &f.key.PublicKey)
			return nil
		},
		"key can decrypt": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood|tpmAttrDecrypt, &f.key.PublicKey)
			return nil
		},
		"key restricted": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood|tpmAttrRestricted, &f.key.PublicKey)
			return nil
		},
		"key cannot sign": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.keyPub = eccPublic(attrKeyGood&^tpmAttrSign, &f.key.PublicKey)
			return nil
		},
		"wrong challenge": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.info = certifyInfo(tpmCertifyExtraData([]byte("someone else's")), nameOf(t, f.keyPub))
			return nil
		},
		"name mismatch": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			f.info = certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, eccPublic(attrKeyGood, &other.PublicKey)))
			return nil
		},
		"bad magic": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.info = certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
			f.info[0] ^= 0xFF
			return nil
		},
		"wrong attest type": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.info = certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
			f.info[5] = 0x18 // ATTEST_QUOTE
			return nil
		},
		"trailing bytes in certify info": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.info = append(certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub)), 0)
			return nil
		},
		"bad signature": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			info := certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
			f.info, f.sig = info, ecdsaSig(t, other, info)
			return nil
		},
		"unpinned EK root": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			other, _ := newCA(t, "Some Other Root")
			return []*x509.Certificate{other}
		},
		"AK not bound to the EK": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.cred = tpmCredentialSecret([]byte("other challenge"), nameOf(t, f.akPub), []byte("x"))
			return nil
		},
		"AK equals the key": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.akPub = eccPublic(attrAKGood, &f.key.PublicKey)
			return nil
		},
		"expired EK certificate": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			f.now = time.Now().Add(72 * time.Hour)
			return nil
		},
		"garbage public area": func(t *testing.T, f *tpmFixture) []*x509.Certificate {
			info := certifyInfo(tpmCertifyExtraData(f.chal), nameOf(t, f.keyPub))
			f.info, f.sig = info, ecdsaSig(t, f.ak, info)
			f.keyPub = []byte{0, 5, 1}
			return nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, attrKeyGood, attrAKGood)
			roots := mutate(t, f)
			if roots == nil {
				roots = []*x509.Certificate{f.root}
			}
			got, err := f.verify(t, roots)
			wantRefused(t, got, err)
		})
	}
}

func TestTPMKeyCertifyRefusesMalformedDocuments(t *testing.T) {
	f := newFixture(t, attrKeyGood, attrAKGood)
	roots := []*x509.Certificate{f.root}
	for name, ev := range map[string][]byte{
		"empty":         nil,
		"not json":      []byte("nope"),
		"unknown field": []byte(`{"extra":1}`),
		"missing parts": []byte(`{}`),
		"trailing":      append(f.evidence(t), []byte(`{}`)...),
	} {
		got, err := verifyTPMKeyCertify(ev, f.chal, f.credKey, f.now, roots)
		if err == nil || got != nil || !errors.Is(err, ErrNotAttested) {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
	}
	got, err := verifyTPMKeyCertify(f.evidence(t), nil, f.credKey, f.now, roots)
	wantRefused(t, got, err)
}

// With roots pinned, software that holds only what is public cannot open it:
// a genuine EK certificate, an AK of its own, and a credential made from the
// challenge (which the app holds) or from the AK and EK alone (public) is
// refused, and so is a core that issued no secret key.
func TestPinningTPMRootsAloneDoesNotOpenTheCheck(t *testing.T) {
	f := newFixture(t, attrKeyGood, attrAKGood)
	roots := []*x509.Certificate{f.root}
	ekDER, _ := x509.MarshalPKIXPublicKey(&f.ek.PublicKey)
	akName := nameOf(t, f.akPub)
	for name, cred := range map[string][]byte{
		"made with the challenge the app holds": tpmCredentialSecret(f.chal, akName, ekDER),
		"made with a public hash":               tpmCredentialSecret(sha256Of(f.chal), akName, ekDER),
		"made with no key":                      tpmCredentialSecret(nil, akName, ekDER),
	} {
		t.Run(name, func(t *testing.T) {
			f.cred = cred
			got, err := f.verify(t, roots)
			wantRefused(t, got, err)
		})
	}
	f.cred = nil
	if _, err := f.verify(t, roots); err != nil {
		t.Fatalf("the credential made with the core's key was refused: %v", err)
	}
	for name, key := range map[string][]byte{"no key": nil, "a short key": []byte("short"), "the challenge itself": f.chal} {
		t.Run("issued "+name, func(t *testing.T) {
			f.credKey = key
			f.cred = tpmCredentialSecret(key, akName, ekDER)
			got, err := f.verify(t, roots)
			wantRefused(t, got, err)
		})
	}
}

func sha256Of(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// The expected bytes below were computed outside this package (Python hashlib
// and hmac over the documented layout), not with the helpers under test, so a
// change to what the helpers hash, including dropping the challenge, fails here
// even though every other test builds its expectation with the same helpers.
// They also pin the wire strings "identity-agent-tpm-key-certify-v1" and
// "identity-agent-tpm-credential-v1".

func TestTPMCertifyExtraDataFixedVector(t *testing.T) {
	got := tpmCertifyExtraData([]byte("fixed challenge 01"))
	want := mustHexTPM(t, "943c8317e3fd5ae407b901d6a0438c71d4af426ea99a9d635adf414504b02182")
	if !bytes.Equal(got, want) {
		t.Fatalf("tpmCertifyExtraData = %x, want %x", got, want)
	}
	if bytes.Equal(tpmCertifyExtraData([]byte("fixed challenge 02")), want) {
		t.Fatal("a different challenge produced the same qualifying data")
	}
}

func TestTPMCredentialSecretFixedVector(t *testing.T) {
	akName := mustHexTPM(t, "000b11111111111111111111111111111111111111111111111111111111111111111111")
	got := tpmCredentialSecret([]byte("fixed credential key 32 bytes!!!"), akName, []byte("fixed-ek-public-der"))
	want := mustHexTPM(t, "36bb13ecc46cd6b794a8c26bd182ec40a70ee848d0b70688a7a064ac2e04a83d")
	if !bytes.Equal(got, want) {
		t.Fatalf("tpmCredentialSecret = %x, want %x", got, want)
	}
}

func mustHexTPM(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
