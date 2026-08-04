package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The CA private key lives beside the certificate. Nothing handed to a workload
// may name the directory that contains it — only the certificate file itself.
func TestNothingMountedIntoAContainerCanReachTheCAKey(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewCertManager(dir)
	if err != nil {
		t.Fatalf("creating cert manager: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "ca.key")); err != nil {
		t.Fatalf("expected a CA key on disk to test against: %v", err)
	}

	instanceDir := t.TempDir()
	if _, err := cm.ExportNSSDir(instanceDir); err != nil {
		t.Fatalf("exporting: %v", err)
	}

	ni := &NetworkIsolation{instanceID: "0123456789ab", networkName: "n", hostIP: "10.0.0.1"}
	cfg := ni.ContainerCreateConfig(&AppManifest{}, "http://127.0.0.1:1", 5050, instanceDir)

	binds, _ := cfg["HostConfig"].(map[string]interface{})["Binds"].([]string)
	if len(binds) == 0 {
		t.Fatal("expected the certificate to be mounted")
	}
	for _, b := range binds {
		src := strings.SplitN(b, ":", 2)[0]
		// A file source can expose only itself. A directory source exposes
		// everything in it, which is how a CA key escapes into a container.
		info, err := os.Stat(src)
		if err != nil {
			continue // rendered path for a directory the test did not create
		}
		if !info.IsDir() {
			continue
		}
		entries, _ := os.ReadDir(src)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".key") {
				t.Fatalf("bind %q mounts a directory containing %q", b, e.Name())
			}
		}
	}

	// And state the positive case: the certificate does reach the container.
	var sawCert bool
	for _, b := range binds {
		if strings.Contains(b, caCertFileName) {
			sawCert = true
		}
	}
	if !sawCert {
		t.Fatal("the CA certificate was not mounted at all")
	}
}

// A CA that can issue an intermediate can delegate forgery. This one issues
// leaves and nothing else, and the constraint has to survive verification
// rather than merely appear in the template.
func TestTheCACannotIssueAnIntermediate(t *testing.T) {
	cm, err := NewCertManager(t.TempDir())
	if err != nil {
		t.Fatalf("creating cert manager: %v", err)
	}
	if !cm.caCert.MaxPathLenZero || cm.caCert.MaxPathLen != 0 {
		t.Fatalf("expected pathlen 0, got MaxPathLen=%d MaxPathLenZero=%v",
			cm.caCert.MaxPathLen, cm.caCert.MaxPathLenZero)
	}

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "forged intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, cm.caCert, &interKey.PublicKey, cm.caKey)
	if err != nil {
		t.Fatalf("building the intermediate: %v", err)
	}
	inter, _ := x509.ParseCertificate(interDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("building the leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(cm.caCert)
	inters := x509.NewCertPool()
	inters.AddCert(inter)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		DNSName:       "example.com",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("a chain through an intermediate verified; the CA is not path-limited")
	}

	// The limit must bite only on the extra hop: a leaf signed directly by the
	// CA still has to verify, or the change has broken interception outright.
	directKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	directDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, cm.caCert, &directKey.PublicKey, cm.caKey)
	if err != nil {
		t.Fatalf("building the direct leaf: %v", err)
	}
	direct, _ := x509.ParseCertificate(directDER)
	if _, err := direct.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("a leaf signed directly by the CA must still verify: %v", err)
	}
}

// Two installations must never share a CA. A shared interception key is the
// single failure that turns one compromised host into all of them.
func TestTwoInstallationsGetDifferentCAs(t *testing.T) {
	a, err := NewCertManager(t.TempDir())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := NewCertManager(t.TempDir())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a.caCert.Equal(b.caCert) {
		t.Fatal("two installations produced the same CA certificate")
	}
	if a.caKey.PublicKey.Equal(&b.caKey.PublicKey) {
		t.Fatal("two installations produced the same CA key")
	}
}
