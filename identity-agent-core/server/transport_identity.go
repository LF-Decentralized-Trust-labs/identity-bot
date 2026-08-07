package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// The key this agent is reached over, held by the agent itself.
//
// Today an agent is reached through a proxy that terminates TLS on its behalf,
// which means the machine's operator holds the key and reads every request and
// response in the clear. Its disk is now encrypted against that same operator,
// which makes the asymmetry stark: the data is protected at rest and published
// on the wire.
//
// So the agent holds its own key. It is generated here, never leaves, and lives
// on the encrypted volume — so it is protected by the same measurement-derived
// key as everything else, and an operator who takes the disk gets neither.
//
// A self-signed certificate, deliberately. A certificate authority vouches that
// somebody controls a name; that is not the question worth answering here. The
// question is whether this is the sealed machine you meant, and that is
// answered by the attestation carrying this key's fingerprint — which is
// stronger, because it names the exact software rather than the host.
//
// It is also why the fingerprint is what the attestation binds to rather than
// the agent's identifier. A report bound to an identifier lets anybody holding
// a list of identifiers ask "is it this one?" of every instance. A fingerprint
// is already visible to anyone who connects, so binding to it confirms nothing
// that was not already on offer.

const (
	transportKeyFile  = "transport-key.pem"
	transportCertFile = "transport-cert.pem"
)

// TransportIdentity is the key and certificate an agent is reached over.
type TransportIdentity struct {
	CertPEM []byte
	KeyPEM  []byte
	// FingerprintB64 is SHA-256 over the certificate, which is what an
	// attestation binds to and what a client compares against the connection it
	// is actually on.
	FingerprintB64 string
}

// LoadOrCreateTransportIdentity returns this agent's transport key, making one
// on first use.
//
// Kept rather than regenerated, because the fingerprint is what clients pin. A
// key that changed on every restart would make every reconnection look like an
// interception, and would train people to accept a changed fingerprint — which
// is the one habit that makes pinning worthless.
func LoadOrCreateTransportIdentity(dir string) (*TransportIdentity, error) {
	keyPath := filepath.Join(dir, transportKeyFile)
	certPath := filepath.Join(dir, transportCertFile)

	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	if keyErr == nil && certErr == nil {
		id, err := identityFrom(certPEM, keyPEM)
		if err == nil {
			return id, nil
		}
		// Unreadable rather than absent. Replacing it would silently change the
		// fingerprint every client has pinned, so it is refused and said out
		// loud instead.
		return nil, fmt.Errorf("this agent's transport key exists but cannot be read, and "+
			"replacing it would change the fingerprint every client has pinned: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate a transport key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "identity-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		// Long-lived on purpose. Expiry exists so a name can be re-vouched for;
		// nothing here vouches for a name, and a certificate that expired would
		// break every pinned client for no gain.
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("could not create a transport certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// The key first and only then the certificate, so a crash between them
	// leaves a state the next start treats as absent rather than as a pair that
	// does not match.
	if err := writePrivate(keyPath, keyPEM); err != nil {
		return nil, err
	}
	if err := writePrivate(certPath, certPEM); err != nil {
		return nil, err
	}
	return identityFrom(certPEM, keyPEM)
}

func identityFrom(certPEM, keyPEM []byte) (*TransportIdentity, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("the stored certificate is not PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("the stored certificate cannot be parsed: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return &TransportIdentity{
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		FingerprintB64: base64.StdEncoding.EncodeToString(sum[:]),
	}, nil
}

// writePrivate writes a secret so that a crash cannot leave half of one.
func writePrivate(path string, body []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("could not write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("could not put %s in place: %w", path, err)
	}
	return nil
}
