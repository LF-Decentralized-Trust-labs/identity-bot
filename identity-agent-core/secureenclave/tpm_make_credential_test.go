package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type tpmExchangeVector struct {
	EKType        string          `json:"ek_type"`
	Root          []byte          `json:"root"`
	Challenge     []byte          `json:"challenge"`
	CredentialKey []byte          `json:"credential_key"`
	Now           time.Time       `json:"now"`
	EKPublic      []byte          `json:"ek_public"`
	Credential    TPMCredential   `json:"credential"`
	Evidence      json.RawMessage `json:"evidence"`
}

func loadTPMExchange(t *testing.T, name string) (tpmExchangeVector, []*x509.Certificate) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var v tpmExchangeVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	return v, []*x509.Certificate{root}
}

// What a software TPM (the reference implementation, not this code) produced:
// the credential the core made for its EK and AK, which that TPM opened with
// TPM2_ActivateCredential, and the evidence built on what it released. Every
// check in verifyTPMKeyCertify passes on it, for an RSA and an ECC endorsement
// key. This is the case that fails if the core's credential layout or its
// derivation of what is inside drifts from the TPM's.
func TestTheCoreAcceptsWhatARealTPMImplementationMade(t *testing.T) {
	for _, name := range []string{"tpm_credential_exchange_rsa.json", "tpm_credential_exchange_ecc.json"} {
		t.Run(name, func(t *testing.T) {
			v, roots := loadTPMExchange(t, name)
			facts, err := verifyTPMKeyCertify(v.Evidence, v.Challenge, v.CredentialKey, v.Now, roots)
			if err != nil {
				t.Fatalf("a genuine exchange was refused: %v", err)
			}
			if facts.Platform != "tpm" || facts.Public == nil {
				t.Fatalf("facts = %+v", facts)
			}
			// The evidence of a test root's EK is not a manufacturer's: the pinned roots
			// (Microsoft's list) refuse it, in words.
			if len(tpmManufacturerRoots) == 0 {
				t.Fatal("no manufacturer root is pinned")
			}
			if _, err := VerifyTPMKeyCertify(v.Evidence, v.Challenge, v.CredentialKey, v.Now); err == nil || !strings.Contains(err.Error(), "does not chain to a pinned TPM manufacturer root") {
				t.Fatalf("an EK certificate under a test root must be refused against the pinned roots, got %v", err)
			}
		})
	}
}

// The credential is keyed by what only the core holds: the same evidence under
// another credential key, or another challenge, is refused.
func TestTheCredentialIsTheCoresAlone(t *testing.T) {
	v, roots := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	other := append([]byte(nil), v.CredentialKey...)
	other[0] ^= 1
	if _, err := verifyTPMKeyCertify(v.Evidence, v.Challenge, other, v.Now, roots); err == nil {
		t.Fatal("evidence for one credential key was taken under another")
	}
	if _, err := verifyTPMKeyCertify(v.Evidence, append([]byte("x"), v.Challenge...), v.CredentialKey, v.Now, roots); err == nil {
		t.Fatal("evidence for one challenge was taken for another")
	}
}

// The core makes a credential only for an EK whose certificate chains to a pinned
// root, and for the key the certificate names.
func TestTheCoreMakesACredentialOnlyForACertifiedEndorsementKey(t *testing.T) {
	v, roots := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	var ev tpmKeyCertifyEvidence
	if err := json.Unmarshal(v.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	make_ := func(ekPub, cert []byte, rts []*x509.Certificate) error {
		_, err := makeTPMCredential(ekPub, cert, nil, ev.AKPublic, v.CredentialKey, v.Now, rts, zeroReader{})
		return err
	}
	if err := make_(v.EKPublic, ev.EKCert, roots); err != nil {
		t.Fatalf("a certified EK was refused: %v", err)
	}
	if err := make_(v.EKPublic, ev.EKCert, nil); err == nil {
		t.Fatal("a credential was made with no root pinned")
	}
	// Another EK public area than the certificate's key.
	other, _ := loadTPMExchange(t, "tpm_credential_exchange_ecc.json")
	if err := make_(other.EKPublic, ev.EKCert, roots); err == nil {
		t.Fatal("a credential was made for a public area that is not the certificate's key")
	}
	var ecEv tpmKeyCertifyEvidence
	ecc, eccRoots := loadTPMExchange(t, "tpm_credential_exchange_ecc.json")
	if err := json.Unmarshal(ecc.Evidence, &ecEv); err != nil {
		t.Fatal(err)
	}
	if _, err := makeTPMCredential(ecc.EKPublic, ecEv.EKCert, nil, ecEv.AKPublic, ecc.CredentialKey, ecc.Now, eccRoots, zeroReader{}); err != nil {
		t.Fatalf("a certified ECC EK was refused: %v", err)
	}
	// A weak credential key.
	if _, err := makeTPMCredential(v.EKPublic, ev.EKCert, nil, ev.AKPublic, v.Challenge[:8], v.Now, roots, zeroReader{}); err == nil {
		t.Fatal("a credential was made with a short key")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

// The roots are the committed PEM files, and a bad file stops the program at
// start rather than being skipped, which would pin fewer roots than were meant.
func TestThePinnedRootsAreTheCommittedFilesAndABadOneStopsTheStart(t *testing.T) {
	v, _ := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	good := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.Root})
	roots := pinnedTPMRoots(fstest.MapFS{"tpmroots/a.pem": {Data: good}, "tpmroots/README.md": {Data: []byte("x")}})
	if len(roots) != 1 || !roots[0].Equal(mustParse(t, v.Root)) {
		t.Fatalf("roots = %d", len(roots))
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a file that is not a certificate was skipped")
		}
	}()
	pinnedTPMRoots(fstest.MapFS{"tpmroots/bad.pem": {Data: []byte("nope")}})
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A certificate a manufacturer's CA signed that is not an endorsement key certificate
// (no TCG usage, or a CA) is refused, though it chains to a pinned root.
func TestACertificateThatIsNotAnEndorsementKeyCertificateIsRefused(t *testing.T) {
	v, roots := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	var ev tpmKeyCertifyEvidence
	if err := json.Unmarshal(v.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyEKCertificate(ev.EKCert, nil, roots, v.Now); err != nil {
		t.Fatalf("a real EK certificate was refused: %v", err)
	}
	ca, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "r"}, NotBefore: v.Now.Add(-time.Hour),
		NotAfter: v.Now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootT, rootT, &ca.PublicKey, ca)
	root := mustParse(t, rootDER)
	leaf := func(tmpl *x509.Certificate) []byte {
		tmpl.SerialNumber, tmpl.Subject = big.NewInt(2), pkix.Name{CommonName: "l"}
		tmpl.NotBefore, tmpl.NotAfter = v.Now.Add(-time.Hour), v.Now.Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &ca.PublicKey, ca)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for name, der := range map[string][]byte{
		"no TCG usage": leaf(&x509.Certificate{}),
		"a CA":         leaf(&x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}}}),
	} {
		if _, err := verifyEKCertificate(der, nil, []*x509.Certificate{root}, v.Now); err == nil {
			t.Errorf("%s: a certificate under a pinned root was taken as an endorsement key's", name)
		}
	}
}

// The pinned package is internally consistent: its issuers chain, through each other, to its
// roots (a real manufacturer chain, not a test root), though not every maker's do, and some
// are expired. The count below is what the package of 2026-10-23 gave; a different package is
// a different number, to be read when it is pinned.
func TestThePinnedIssuersChainToThePinnedRoots(t *testing.T) {
	roots := x509.NewCertPool()
	for _, r := range tpmManufacturerRoots {
		roots.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range tpmManufacturerIssuers {
		inter.AddCert(c)
	}
	ok := 0
	for _, c := range tpmManufacturerIssuers {
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			ok++
		}
	}
	t.Logf("%d of %d pinned issuers chain to a pinned root", ok, len(tpmManufacturerIssuers))
	if ok < len(tpmManufacturerIssuers)/2 {
		t.Fatalf("only %d of %d pinned issuers chain to a pinned root: the pin is not what a chain needs", ok, len(tpmManufacturerIssuers))
	}
}
