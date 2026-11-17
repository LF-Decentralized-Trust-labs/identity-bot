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
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"identity-agent-core/tpmcert"
)

// The seven issuers (six STMicroelectronics, one Qualcomm) that tools/tpmroots used to skip.
// The six STMicroelectronics ones encode their serial number with redundant leading zeros, which
// crypto/x509 refuses; they are pinned by the SHA-256 of their bytes in tpmlenient. The Qualcomm
// one is ordinary DER in a PEM file with bare carriage returns for line ends, and is an ordinary
// pinned issuer. Each row is a vector: the pin, and who it must be.
var formerlySkippedIssuers = []struct {
	sha256, cn, rootCN string
	lenient            bool
}{
	{"0df3b459c9e675272ff7611f768abbbc3e30a343d391f6acb711a0d0aabab113", "STM TPM ECC Intermediate CA 01", "STM TPM ECC Root CA 01", true},
	{"f29c461aaf0e64c8b3b99761c81653ed241f57087e420a313e7e076c7ec047c3", "STM TPM EK Intermediate CA 01", "STM TPM EK Root CA", true},
	{"9c84ecf27fba4e86538a34e3a1e60cd7853ef921cbcf28f95d9a63122a5cf5e8", "STM TPM EK Intermediate CA 02", "STM TPM EK Root CA", true},
	{"9ca3a6c02f4073ac9518ee5f46d1916c945d4fad381447064addf2a5c634f93e", "STM TPM EK Intermediate CA 03", "STM TPM EK Root CA", true},
	{"5cfcd07e257a99bace95b5805ba5363997b3fb5d5cfaff5a58d36c1db767d42a", "STM TPM EK Intermediate CA 04", "STM TPM EK Root CA", true},
	{"2fe2ef243480b4b1d78639a4d9822e80c01781edde1ea36040a946e77c37497d", "STM TPM EK Intermediate CA 05", "STM TPM EK Root CA", true},
	{"da6b3df727f506a3ec9ce2556eb565f0d0f06debe8335d413535ecb5c131fcb0", "Qualcomm WES EK Provisioning SubCA 2 (Glymur family)", "Qualcomm WES Secure Provisioning Root v2", false},
}

// A TPM chip whose endorsement key certificate chains through one of these is a physical chip's:
// each is pinned, is a CA, is valid now, and was signed by a pinned root, which is checked here
// with the real bytes.
func TestTheIssuersThatWereSkippedArePinnedAndSignedByAPinnedRoot(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, v := range formerlySkippedIssuers {
		t.Run(v.cn, func(t *testing.T) {
			raw, err := fs.ReadFile(tpmRootFiles, dirOf(v.lenient)+"/"+v.sha256+".pem")
			if err != nil {
				t.Fatalf("not pinned: %v", err)
			}
			b, _ := pem.Decode(raw)
			if b == nil {
				t.Fatal("not PEM")
			}
			if h := sha256.Sum256(b.Bytes); hex.EncodeToString(h[:]) != v.sha256 {
				t.Fatalf("the file is not the bytes it is named for")
			}
			_, goErr := x509.ParseCertificate(b.Bytes)
			if (goErr != nil) != v.lenient {
				t.Fatalf("crypto/x509 reading it: %v (lenient=%v)", goErr, v.lenient)
			}
			c, err := tpmcert.Parse(b.Bytes)
			if err != nil {
				t.Fatalf("tpmcert: %v", err)
			}
			if c.Subject.CommonName != v.cn || !c.IsCA || now.Before(c.NotBefore) || now.After(c.NotAfter) {
				t.Fatalf("subject %q, CA %v, valid %v to %v", c.Subject.CommonName, c.IsCA, c.NotBefore, c.NotAfter)
			}
			if !underPinnedRoot(c, tpmManufacturerRoots, now) {
				t.Fatalf("not signed by a pinned root")
			}
			var root *x509.Certificate
			for _, r := range tpmManufacturerRoots {
				if bytes.Equal(r.RawSubject, c.RawIssuer) {
					root = r
				}
			}
			if root == nil || root.Subject.CommonName != v.rootCN {
				t.Fatalf("issued by %v, want %q", root, v.rootCN)
			}
		})
	}
}

func dirOf(lenient bool) string {
	if lenient {
		return "tpmlenient"
	}
	return "tpmintermediates"
}

// What is in tpmlenient is only what crypto/x509 refuses: an issuer it can read belongs with the
// others, so it is judged by the same chain rules.
func TestNothingCryptoX509CanReadIsKeptAsALenientIssuer(t *testing.T) {
	if len(tpmLenientIssuers) != 6 {
		t.Fatalf("%d lenient issuers pinned, want the six STMicroelectronics ones", len(tpmLenientIssuers))
	}
	for _, c := range tpmLenientIssuers {
		if _, err := x509.ParseCertificate(c.Raw); err == nil {
			t.Errorf("%s is readable by crypto/x509", c.Subject.CommonName)
		}
		if !strings.HasPrefix(c.Subject.CommonName, "STM ") {
			t.Errorf("unexpected lenient issuer %q", c.Subject.CommonName)
		}
	}
}

// ---- a chain of our own through an issuer crypto/x509 refuses ----

type lenientChain struct {
	root       *x509.Certificate
	rootKey    *ecdsa.PrivateKey
	issuer     *tpmcert.Certificate
	issuerKey  *ecdsa.PrivateKey
	issuerCert *x509.Certificate // the same issuer as crypto/x509 could read it, to sign leaves with
	now        time.Time
}

func newLenientChain(t *testing.T) lenientChain {
	t.Helper()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1}}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "STM TPM EK Intermediate CA 99"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{2}, AuthorityKeyId: []byte{1}}
	good, err := x509.CreateCertificate(rand.Reader, tmpl, root, &issuerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, _ := x509.ParseCertificate(good)
	der := withRedundantSerial(t, good, rootKey)
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("the fixture issuer is readable by crypto/x509")
	}
	li, err := tpmcert.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return lenientChain{root, rootKey, li, issuerKey, issuerCert, now}
}

// withRedundantSerial re-encodes the serial of a certificate (a one-byte INTEGER) with leading
// zeros, as the STMicroelectronics ones are, and signs it again with parentKey.
func withRedundantSerial(t *testing.T, der []byte, parentKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	type outer struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	var o outer
	if _, err := asn1.Unmarshal(der, &o); err != nil {
		t.Fatal(err)
	}
	var serial = []byte{0x02, 0x01, 0x03}
	var padded = []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x03}
	if bytes.Count(o.TBS.Bytes, serial) < 1 {
		t.Fatal("serial not found")
	}
	body := bytes.Replace(o.TBS.Bytes, serial, padded, 1)
	tbs, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	h := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, parentKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(outer{asn1.RawValue{FullBytes: tbs}, o.SigAlg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (c lenientChain) leaf(t *testing.T, signer *ecdsa.PrivateKey, notAfter time.Time, ek bool) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{}, NotBefore: c.now.Add(-time.Hour), NotAfter: notAfter}
	if ek {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{tpmEKCertificateEKU}
		tmpl.ExtraExtensions = []pkix.Extension{tcgSubjectAltName(t)}
	}
	parent := *c.issuerCert
	parent.PublicKey = &signer.PublicKey // a signer that is not the issuer's key still names the issuer
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &parent, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func withLenient(t *testing.T, issuers ...*tpmcert.Certificate) {
	t.Helper()
	old := tpmLenientIssuers
	tpmLenientIssuers = issuers
	t.Cleanup(func() { tpmLenientIssuers = old })
}

// The case the change is for: an endorsement key certificate issued by an issuer crypto/x509 will
// not read is accepted as a physical chip's, and names that issuer.
func TestAnEndorsementKeyUnderAnIssuerGoCannotReadIsAccepted(t *testing.T) {
	c := newLenientChain(t)
	withIssuers(t, nil, nil)
	withLenient(t, c.issuer)
	leaf := c.leaf(t, c.issuerKey, c.now.Add(time.Hour), true)
	if _, _, err := verifyEKCertificateIssuer(leaf, nil, nil, c.now); err == nil {
		t.Fatal("accepted with no pinned root")
	}
	_, iss, err := verifyEKCertificateIssuer(leaf, nil, []*x509.Certificate{c.root}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c.issuer.Raw)
	if iss.Class != TPMClassPhysical || iss.SHA256 != hex.EncodeToString(h[:]) || !strings.Contains(iss.Subject, "STM TPM EK Intermediate CA 99") {
		t.Fatalf("issuer = %+v", iss)
	}
}

// A front end sends the issuers its TPM carries, the one crypto/x509 will not read among them.
// That certificate is passed over, and the chain is still accepted through the pinned copy.
func TestAnUnreadableIssuerTheFrontEndSendsIsPassedOver(t *testing.T) {
	c := newLenientChain(t)
	withIssuers(t, nil, nil)
	withLenient(t, c.issuer)
	leaf := c.leaf(t, c.issuerKey, c.now.Add(time.Hour), true)
	_, iss, err := verifyEKCertificateIssuer(leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Class != TPMClassPhysical {
		t.Fatalf("issuer = %+v", iss)
	}
	// Sent but not pinned, it is still not trusted.
	withLenient(t)
	if _, _, err := verifyEKCertificateIssuer(leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now); err == nil {
		t.Fatal("an unpinned issuer the front end sent was trusted")
	}
}

// Each thing the chain check rests on, taken away in turn, is refused.
func TestAnIssuerGoCannotReadIsHeldToTheSameChainRules(t *testing.T) {
	c := newLenientChain(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	roots := []*x509.Certificate{c.root}
	for name, tc := range map[string]struct {
		leaf  []byte
		roots []*x509.Certificate
		now   time.Time
	}{
		"signed by a key that is not the issuer's": {c.leaf(t, other, c.now.Add(time.Hour), true), roots, c.now},
		"the leaf has expired":                     {c.leaf(t, c.issuerKey, c.now.Add(time.Hour), true), roots, c.now.Add(2 * time.Hour)},
		"the leaf is not an endorsement key":       {c.leaf(t, c.issuerKey, c.now.Add(time.Hour), false), roots, c.now},
		"the issuer is not under a pinned root":    {c.leaf(t, c.issuerKey, c.now.Add(time.Hour), true), nil, c.now},
	} {
		t.Run(name, func(t *testing.T) {
			withIssuers(t, nil, nil)
			withLenient(t, c.issuer)
			if _, _, err := verifyEKCertificateIssuer(tc.leaf, nil, tc.roots, tc.now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("the issuer is not pinned", func(t *testing.T) {
		withIssuers(t, nil, nil)
		withLenient(t)
		if _, _, err := verifyEKCertificateIssuer(c.leaf(t, c.issuerKey, c.now.Add(time.Hour), true), nil, roots, c.now); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("the issuer's own signature is not the root's", func(t *testing.T) {
		withIssuers(t, nil, nil)
		forged := newLenientChain(t) // another root signed this issuer
		withLenient(t, forged.issuer)
		if _, _, err := verifyEKCertificateIssuer(forged.leaf(t, forged.issuerKey, forged.now.Add(time.Hour), true), nil, roots, forged.now); err == nil {
			t.Fatal("accepted an issuer a pinned root did not sign")
		}
	})
}

// tpmcert accepts the redundant serial and nothing else that crypto/x509 would refuse.
func TestTpmcertRefusesWhatIsNotOnlyASerialIrregularity(t *testing.T) {
	c := newLenientChain(t)
	if _, err := tpmcert.Parse(append(append([]byte{}, c.issuer.Raw...), 0)); err == nil {
		t.Error("accepted trailing data")
	}
	if _, err := tpmcert.Parse(c.issuer.Raw[:len(c.issuer.Raw)-3]); err == nil {
		t.Error("accepted a truncated certificate")
	}
	if err := c.issuer.CheckSignatureFrom(&c.issuerKey.PublicKey); err == nil {
		t.Error("the issuer's signature verified under its own key, not its parent's")
	}
	if err := c.issuer.CheckSignatureFrom(c.root.PublicKey); err != nil {
		t.Errorf("the issuer's signature under its parent: %v", err)
	}
}
