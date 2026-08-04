package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CertManager struct {
	dataDir   string
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	certCache map[string]*tls.Certificate
	mu        sync.RWMutex
}

func NewCertManager(dataDir string) (*CertManager, error) {
	certDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	cm := &CertManager{
		dataDir:   certDir,
		certCache: make(map[string]*tls.Certificate),
	}

	if err := cm.loadOrCreateCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return cm, nil
}

func (cm *CertManager) loadOrCreateCA() error {
	caCertPath := filepath.Join(cm.dataDir, "ca.crt")
	caKeyPath := filepath.Join(cm.dataDir, "ca.key")

	certData, certErr := os.ReadFile(caCertPath)
	keyData, keyErr := os.ReadFile(caKeyPath)

	if certErr == nil && keyErr == nil {
		certBlock, _ := pem.Decode(certData)
		if certBlock == nil {
			return fmt.Errorf("failed to decode CA certificate PEM")
		}
		caCert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return fmt.Errorf("failed to decode CA key PEM")
		}
		caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA key: %w", err)
		}

		cm.caCert = caCert
		cm.caKey = caKey
		return nil
	}

	return cm.createCA(caCertPath, caKeyPath)
}

func (cm *CertManager) createCA(certPath, keyPath string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	caCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Identity Agent"},
			CommonName:    "Identity Agent Sandbox CA",
			Country:       []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// This CA issues leaf certificates and nothing else, so it has no reason
		// to be able to issue an intermediate. MaxPathLenZero is what actually
		// says zero here — a bare MaxPathLen of 0 is Go's "unset", and would
		// leave the chain depth unbounded.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse created CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = caKey
	return nil
}

func (cm *CertManager) CACertPath() string {
	return filepath.Join(cm.dataDir, "ca.crt")
}

func (cm *CertManager) CACertPEM() ([]byte, error) {
	return os.ReadFile(cm.CACertPath())
}

func (cm *CertManager) CACertificate() *x509.Certificate {
	return cm.caCert
}

func (cm *CertManager) GenerateHostCert(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	if cert, ok := cm.certCache[host]; ok {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cert, ok := cm.certCache[host]; ok {
		return cert, nil
	}

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	hostTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Identity Agent Sandbox"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		hostTemplate.IPAddresses = []net.IP{ip}
	} else {
		hostTemplate.DNSNames = []string{host}
	}

	hostCertDER, err := x509.CreateCertificate(rand.Reader, hostTemplate, cm.caCert, &hostKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{hostCertDER, cm.caCert.Raw},
		PrivateKey:  hostKey,
	}

	cm.certCache[host] = cert
	return cert, nil
}

// caCertFileName is the name the exported CA certificate is written under.
// Anything that hands the certificate to a workload names this file, so that a
// directory holding the CA private key can never be mounted by mistake.
const caCertFileName = "identity-agent-ca.crt"

func (cm *CertManager) ExportNSSDir(instanceDir string) (string, error) {
	nssDir := filepath.Join(instanceDir, "nss")
	if err := os.MkdirAll(nssDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create NSS directory: %w", err)
	}

	caCertPEM, err := cm.CACertPEM()
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert: %w", err)
	}

	certDest := filepath.Join(nssDir, caCertFileName)
	if err := os.WriteFile(certDest, caCertPEM, 0644); err != nil {
		return "", fmt.Errorf("failed to write CA cert to NSS dir: %w", err)
	}

	return nssDir, nil
}

func (cm *CertManager) ClearCache() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.certCache = make(map[string]*tls.Certificate)
}
