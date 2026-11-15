package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The owner's separate opt-in to virtual and cloud TPMs. A virtual TPM is one
// whose endorsement key is certified by an issuer the package pins as virtual; with the
// opt-in it passes and the proof says it is virtual; without it, it is refused as before.

func TestAVirtualTPMIsAcceptedAndSaidToBeVirtualWhenTheOwnerOptedIn(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	withIssuers(t, nil, []*x509.Certificate{c.issuer})
	_, iss, err := verifyEKCertificateClass(c.leaf, nil, []*x509.Certificate{c.root}, c.now, true)
	if err != nil {
		t.Fatal(err)
	}
	if iss.Class != TPMClassVirtual || !strings.Contains(iss.Subject, "MSFT-KEYID-1") || iss.SHA256 != sha256Hex(c.issuer) {
		t.Fatalf("issuer = %+v", iss)
	}
}

// The package's pinned virtual issuers join the chain on their own: a front end need not send
// them, and without the opt-in the refusal still says virtual rather than "no chain".
func TestAVirtualTPMsIssuerNeedNotBeSentToBeKnown(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	withIssuers(t, nil, []*x509.Certificate{c.issuer})
	roots := []*x509.Certificate{c.root}
	if _, iss, err := verifyEKCertificateClass(c.leaf, nil, roots, c.now, true); err != nil || iss.Class != TPMClassVirtual {
		t.Fatalf("opted in, issuer not sent: %v", err)
	}
	if _, _, err := verifyEKCertificateClass(c.leaf, nil, roots, c.now, false); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("not opted in, issuer not sent: %v", err)
	}
}

// Without the opt-in the answer is the old one, through every entry point.
func TestAVirtualTPMIsRefusedAsVirtualWhenTheOwnerDidNotOptIn(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	withIssuers(t, nil, []*x509.Certificate{c.issuer})
	if _, _, err := verifyEKCertificateIssuer(c.leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("verifyEKCertificateIssuer: %v", err)
	}
	if _, _, err := verifyEKCertificateClass(c.leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now, false); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("verifyEKCertificateClass: %v", err)
	}
}

// The opt-in is for virtual TPMs, not for whatever a front end sends: an issuer nothing pins
// is trusted as neither class, whether or not its name says MSFT.
func TestTheOptInDoesNotTrustAnIssuerTheFrontEndSendsButNothingPins(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-9")
	withIssuers(t, nil, nil)
	_, _, err := verifyEKCertificateClass(c.leaf, [][]byte{c.issuer.Raw}, []*x509.Certificate{c.root}, c.now, true)
	if err == nil || errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("an unpinned issuer was trusted, or called virtual: %v", err)
	}
}

// A physical chip is still physical when the owner opted in: the opt-in does not demote it.
func TestAPhysicalChipStillSaysPhysicalWhenTheOwnerOptedInToVirtual(t *testing.T) {
	c := newEKChain(t, "IFX-KEYID-1")
	withIssuers(t, []*x509.Certificate{c.issuer}, nil)
	_, iss, err := verifyEKCertificateClass(c.leaf, nil, []*x509.Certificate{c.root}, c.now, true)
	if err != nil || iss.Class != TPMClassPhysical {
		t.Fatalf("%+v %v", iss, err)
	}
}

// A key that has any chain through a virtual issuer is reported as virtual, never as the
// stronger class, whichever chain x509 lists first.
func TestAKeyWithAVirtualChainIsNeverReportedPhysical(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	phys := &x509.Certificate{Raw: []byte("physical"), Subject: pkix.Name{CommonName: "IFX-KEYID-1"}}
	withIssuers(t, []*x509.Certificate{phys}, []*x509.Certificate{c.issuer})
	roots := []*x509.Certificate{c.root}
	virtualChain := []*x509.Certificate{{}, c.issuer, c.root}
	physicalChain := []*x509.Certificate{{}, phys, c.root}
	for _, chains := range [][][]*x509.Certificate{{virtualChain, physicalChain}, {physicalChain, virtualChain}} {
		iss, err := classifyIssuer(chains, roots, true)
		if err != nil || iss.Class != TPMClassVirtual {
			t.Fatalf("%+v %v", iss, err)
		}
		if _, err := classifyIssuer(chains, roots, false); !errors.Is(err, ErrVirtualTPM) {
			t.Fatalf("not opted in: %v", err)
		}
	}
}

// Only the issuer directly above the leaf is the one that vouched for the chip. A virtual
// issuer further up, with an unpinned issuer under it, is not a pinned virtual TPM.
func TestAVirtualIssuerHighInTheChainDoesNotVouchForAnUnpinnedIssuerUnderIt(t *testing.T) {
	c := newEKChain(t, "MSFT-KEYID-1")
	sub := &x509.Certificate{Raw: []byte("sub"), Subject: pkix.Name{CommonName: "Somebody-Else"}}
	withIssuers(t, nil, []*x509.Certificate{c.issuer})
	_, err := classifyIssuer([][]*x509.Certificate{{{}, sub, c.issuer, c.root}}, []*x509.Certificate{c.root}, true)
	if err == nil || errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("accepted, or called virtual: %v", err)
	}
	if !strings.Contains(err.Error(), "not pinned as a virtual") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// Every issuer the package pins as virtual chains to a pinned root: if one did not, an owner
// who opted in would still see that virtual TPM refused as "no chain".
func TestEveryPinnedVirtualIssuerChainsToAPinnedRoot(t *testing.T) {
	pool := x509.NewCertPool()
	for _, r := range tpmManufacturerRoots {
		pool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, ic := range tpmManufacturerIssuers {
		inter.AddCert(ic)
	}
	for _, ic := range tpmVirtualIssuers {
		inter.AddCert(ic)
	}
	for _, v := range tpmVirtualIssuers {
		// The issuer is a CA: its own chain is checked at the time it was pinned (it may have
		// lapsed since, which is the update's business, not this test's).
		if _, err := v.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: v.NotBefore.Add(time.Hour),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Errorf("%s does not chain to a pinned root: %v", v.Subject, err)
		}
	}
}

// The credential exchange passes the class the later proof will, so an opted-in virtual
// TPM is not stopped at the exchange's first step; without the opt-in it is stopped there.
func TestTheCredentialIsMadeForAVirtualTPMOnlyWhenTheOwnerOptedIn(t *testing.T) {
	v, _ := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	var ev tpmKeyCertifyEvidence
	if err := json.Unmarshal(v.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	genuine, err := x509.ParseCertificate(ev.EKCert)
	if err != nil {
		t.Fatal(err)
	}
	// The same endorsement key, certified instead by a (test) virtual issuer under a root of ours.
	now := v.Now
	mk := func(cn string, ca bool, pub any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
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
			signer, signerKey, tmpl.AuthorityKeyId = parent, parentKey, parent.SubjectKeyId
		}
		if pub == nil {
			pub = &k.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rootKey := mk("root", true, nil, nil, nil, 1)
	issuer, issuerKey := mk("MSFT-KEYID-1", true, nil, root, rootKey, 2)
	leaf, _ := mk("ek", false, genuine.PublicKey, issuer, issuerKey, 3)
	withIssuers(t, nil, []*x509.Certificate{issuer})
	roots := []*x509.Certificate{root}

	_, err = makeTPMCredentialClasses(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now, roots, zeroReader{}, false)
	if !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("not opted in: %v", err)
	}
	if _, err = makeTPMCredentialClasses(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now, roots, zeroReader{}, true); err != nil {
		t.Fatalf("opted in: %v", err)
	}
	// And the same function with the opt-in off for the physical entry point.
	if _, err = makeTPMCredential(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now, roots, zeroReader{}); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("makeTPMCredential must stay physical-only: %v", err)
	}
}

// The public entry points, end to end on what a software TPM produced: the evidence's
// endorsement certificate is swapped for one our own virtual issuer made for the same key,
// which the credential and the TPM's signatures do not cover.
func TestThePublicEntryPointsTakeAVirtualTPMOnlyWithTheOwnersOptIn(t *testing.T) {
	v, _ := loadTPMExchange(t, "tpm_credential_exchange_rsa.json")
	var ev tpmKeyCertifyEvidence
	if err := json.Unmarshal(v.Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	genuine, _ := x509.ParseCertificate(ev.EKCert)
	now := v.Now
	mk := func(cn string, ca bool, pub any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
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
			signer, signerKey, tmpl.AuthorityKeyId = parent, parentKey, parent.SubjectKeyId
		}
		if pub == nil {
			pub = &k.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rootKey := mk("root", true, nil, nil, nil, 1)
	issuer, issuerKey := mk("MSFT-KEYID-1", true, nil, root, rootKey, 2)
	leaf, _ := mk("ek", false, genuine.PublicKey, issuer, issuerKey, 3)
	ev.EKCert, ev.EKChain = leaf.Raw, nil
	evidence, _ := json.Marshal(ev)

	pm, pi, pr := tpmManufacturerRoots, tpmManufacturerIssuers, tpmVirtualIssuers
	tpmManufacturerRoots, tpmManufacturerIssuers, tpmVirtualIssuers = []*x509.Certificate{root}, nil, []*x509.Certificate{issuer}
	t.Cleanup(func() { tpmManufacturerRoots, tpmManufacturerIssuers, tpmVirtualIssuers = pm, pi, pr })

	if _, err := VerifyTPMKeyCertify(evidence, v.Challenge, v.CredentialKey, now); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("VerifyTPMKeyCertify: %v", err)
	}
	if _, err := VerifyTPMKeyCertifyClasses(evidence, v.Challenge, v.CredentialKey, now, false); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("VerifyTPMKeyCertifyClasses(false): %v", err)
	}
	facts, err := VerifyTPMKeyCertifyClasses(evidence, v.Challenge, v.CredentialKey, now, true)
	if err != nil {
		t.Fatalf("VerifyTPMKeyCertifyClasses(true): %v", err)
	}
	if facts.EKIssuer == nil || facts.EKIssuer.Class != TPMClassVirtual {
		t.Fatalf("the proof does not say virtual: %+v", facts.EKIssuer)
	}
	// What the opt-in allows is the class, not a weaker proof: a wrong challenge is still refused.
	if _, err := VerifyTPMKeyCertifyClasses(evidence, append([]byte("x"), v.Challenge...), v.CredentialKey, now, true); err == nil {
		t.Fatal("an opted-in proof was accepted for another challenge")
	}
	if _, err := MakeTPMCredential(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("MakeTPMCredential: %v", err)
	}
	if _, err := MakeTPMCredentialClasses(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now, true); err != nil {
		t.Fatalf("MakeTPMCredentialClasses(true): %v", err)
	}
	if _, err := MakeTPMCredentialClasses(v.EKPublic, leaf.Raw, nil, ev.AKPublic, v.CredentialKey, now, false); !errors.Is(err, ErrVirtualTPM) {
		t.Fatalf("MakeTPMCredentialClasses(false): %v", err)
	}
}
