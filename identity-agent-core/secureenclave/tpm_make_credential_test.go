package secureenclave

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
			// The hardware key's evidence is the TPM's, and a core whose pinned
			// roots are empty (as this build's are) takes none of it.
			if _, err := VerifyTPMKeyCertify(v.Evidence, v.Challenge, v.CredentialKey, v.Now); err == nil || !strings.Contains(err.Error(), "no TPM manufacturer roots") {
				t.Fatalf("with no pinned roots the evidence must be refused in words, got %v", err)
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
