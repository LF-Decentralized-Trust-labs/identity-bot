package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A chain of our own: a root, an issuer under it, and an endorsement key certificate under
// that, so each rule of physicalIssuer can be tried against the case it exists for.
type ekChain struct {
	root, issuer *x509.Certificate
	leaf         []byte
	rootLeaf     []byte // an endorsement key certificate the root itself signed
	now          time.Time
}

func newEKChain(t *testing.T, issuerCN string) ekChain {
	t.Helper()
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, serial int64) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: ca, BasicConstraintsValid: true, SubjectKeyId: []byte{byte(serial)}}
		if ca {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{tpmEKCertificateEKU}
		}
		signer, signerKey := tmpl, k
		if parent != nil {
			signer, signerKey = parent, parentKey
			tmpl.AuthorityKeyId = parent.SubjectKeyId
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	root, rootKey, _ := mk("root", nil, nil, true, 1)
	issuer, issuerKey, _ := mk(issuerCN, root, rootKey, true, 2)
	_, _, leaf := mk("ek", issuer, issuerKey, false, 3)
	_, _, rootLeaf := mk("ek", root, rootKey, false, 4)
	return ekChain{root, issuer, leaf, rootLeaf, now}
}

// withIssuers sets the package's issuers for one test.
func withIssuers(t *testing.T, physical, virtual []*x509.Certificate) {
	t.Helper()
	p, v := tpmManufacturerIssuers, tpmVirtualIssuers
	tpmManufacturerIssuers, tpmVirtualIssuers = physical, virtual
	t.Cleanup(func() { tpmManufacturerIssuers, tpmVirtualIssuers = p, v })
}

func TestAChipsEndorsementKeyIsAcceptedAndNamesItsIssuer(t *testing.T) {
	c := newEKChain(t, "IFX-KEYID-1")
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	_, iss, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Class != TPMClassPhysical || !strings.Contains(iss.Subject, "IFX-KEYID-1") || iss.SHA256 != sha256Hex(c.issuer) {
		t.Fatalf("issuer = %+v", iss)
	}
}

// The case the review found: Microsoft's root also anchors the issuer of its own software TPM.
func TestAVirtualTPMsEndorsementKeyIsRefusedThoughItChainsToAPinnedRoot(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	withIssuers(t, nil, []*x509.Certificate{c.issuer}) // the package marks it virtual, so it is not among the physical
	_, _, err := verifyEKCertificateIssuer(c.leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now)
	if err == nil || !strings.Contains(err.Error(), "virtual or cloud") {
		t.Fatalf("a virtual TPM's key was not refused as one: %v", err)
	}
}

// Marked virtual wins even if the same issuer is somehow also pinned as physical.
func TestAVirtualIssuerIsRefusedEvenIfAlsoListedAsPhysical(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	withIssuers(t, []*x509.Certificate{c.issuer}, []*x509.Certificate{c.issuer})
	if _, _, err := verifyEKCertificateIssuer(c.leaf, nil, []*x509.Certificate{c.root}, c.now); err == nil {
		t.Fatal("accepted")
	}
}

// A certificate nothing classifies is not trusted: an issuer a front end sends, that the
// package does not pin, does not make a chain acceptable by being sent.
func TestAnIssuerTheFrontEndSendsButNothingPinsIsNotTrusted(t *testing.T) {
	c := newEKChain(t, "Unknown-KEYID-1")
	withIssuers(t, nil, nil)
	_, _, err := verifyEKCertificateIssuer(c.leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now)
	if err == nil || !strings.Contains(err.Error(), "not pinned as a physical") {
		t.Fatalf("an unclassified issuer was trusted: %v", err)
	}
}

// A root that issues through pinned issuers is trusted only through them; one with none
// beneath it may issue directly.
func TestARootWithPinnedIssuersUnderItDoesNotIssueDirectly(t *testing.T) {
	c := newEKChain(t, "IFX-KEYID-1")
	roots := []*x509.Certificate{c.root}
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	if _, _, err := verifyEKCertificateIssuer(c.rootLeaf, nil, roots, c.now); err == nil {
		t.Fatal("a key the root signed directly was accepted though the root issues through a pinned issuer")
	}
	withIssuers(t, nil, nil)
	if _, iss, err := verifyEKCertificateIssuer(c.rootLeaf, nil, roots, c.now); err != nil || iss.Class != TPMClassPhysical {
		t.Fatalf("a root with no pinned issuers under it should issue directly: %v", err)
	}
}

// What the committed package holds: nothing marked virtual is also trusted, and every
// certificate marked virtual is one this reading means (Microsoft's own TPM, MSFT).
func TestThePinnedPackageKeepsVirtualIssuersApartFromPhysicalOnes(t *testing.T) {
	if len(tpmVirtualIssuers) == 0 {
		t.Fatal("no virtual issuer is pinned: the package of 2026-10-23 has Microsoft's MSFT issuers")
	}
	physical := map[string]bool{}
	for _, c := range append(append([]*x509.Certificate{}, tpmManufacturerRoots...), tpmManufacturerIssuers...) {
		physical[sha256Hex(c)] = true
	}
	for _, c := range tpmVirtualIssuers {
		if physical[sha256Hex(c)] {
			t.Errorf("%s is both virtual and physical", c.Subject)
		}
		if !strings.Contains(strings.ToUpper(c.Subject.CommonName), "MSFT-") {
			t.Errorf("%s is pinned as virtual but is not an MSFT issuer", c.Subject)
		}
	}
	for _, c := range tpmManufacturerIssuers {
		if strings.Contains(strings.ToUpper(c.Subject.CommonName), "MSFT-") || strings.Contains(strings.ToUpper(c.Subject.CommonName), "-WEC-") {
			t.Errorf("%s is trusted as physical", c.Subject)
		}
	}
}

// x509 may build more than one chain for one key, in no set order: one through a copy of the
// issuer the front end sent (same name and key, not the pinned bytes) and one through the
// pinned issuer. The copy's chain must not hide the pinned one, whichever comes first.
func TestAChainThroughAnUnpinnedCopyDoesNotHideOneThroughThePinnedIssuer(t *testing.T) {
	c := newEKChain(t, "IFX-KEYID-1")
	unpinned := &x509.Certificate{Raw: []byte("not pinned"), Subject: c.issuer.Subject}
	pinnedChain := []*x509.Certificate{{}, c.issuer, c.root}
	copyChain := []*x509.Certificate{{}, unpinned, c.root}
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	for _, chains := range [][][]*x509.Certificate{{copyChain, pinnedChain}, {pinnedChain, copyChain}} {
		iss, err := physicalIssuer(chains, []*x509.Certificate{c.root})
		if err != nil || iss.SHA256 != sha256Hex(c.issuer) {
			t.Fatalf("the pinned issuer's chain was not accepted: %v", err)
		}
	}
	if _, err := physicalIssuer([][]*x509.Certificate{copyChain}, []*x509.Certificate{c.root}); err == nil {
		t.Fatal("a chain only through an unpinned copy was accepted")
	}
}
