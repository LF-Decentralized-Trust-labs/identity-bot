package secureenclave

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// PlatformSigner signs attestation payloads with a platform-backed key.
// Hardware implementations keep private key material inside the enclave/TPM/StrongBox.
type PlatformSigner interface {
	Available() bool
	Platform() string
	Label() string
	PublicKey() ([]byte, error)
	Sign(data []byte) ([]byte, error)
}

// NewPlatformSigner selects the best available signer for this host.
func NewPlatformSigner(dataDir string) PlatformSigner {
	if s := newDarwinSecureEnclaveSigner(); s != nil && s.Available() {
		return s
	}
	if s := newTPMSigner(); s != nil && s.Available() {
		return s
	}
	if s := newStrongBoxSigner(); s != nil && s.Available() {
		return s
	}
	return newSoftwareSigner(dataDir)
}

// softwareSigner persists an Ed25519 key for development and non-hardware hosts.
type softwareSigner struct {
	mu       sync.Mutex
	dataDir  string
	priv     ed25519.PrivateKey
	platform string
	label    string
}

func newSoftwareSigner(dataDir string) *softwareSigner {
	s := &softwareSigner{
		dataDir:  dataDir,
		platform: "software",
		label:    "Software signer (development fallback)",
	}
	_ = s.ensureKey()
	return s
}

func (s *softwareSigner) Available() bool { return true }
func (s *softwareSigner) Platform() string { return s.platform }
func (s *softwareSigner) Label() string  { return s.label }

func (s *softwareSigner) keyPath() string {
	return filepath.Join(s.dataDir, "secureenclave", "software_signer.key")
}

func (s *softwareSigner) ensureKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.priv) == ed25519.PrivateKeySize {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.keyPath()), 0700); err != nil {
		return err
	}
	if raw, err := os.ReadFile(s.keyPath()); err == nil && len(raw) == ed25519.SeedSize {
		s.priv = ed25519.NewKeyFromSeed(raw)
		return nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := priv.Seed()
	if err := os.WriteFile(s.keyPath(), seed, 0600); err != nil {
		return err
	}
	s.priv = priv
	return nil
}

func (s *softwareSigner) PublicKey() ([]byte, error) {
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	return s.priv.Public().(ed25519.PublicKey), nil
}

func (s *softwareSigner) Sign(data []byte) ([]byte, error) {
	if err := s.ensureKey(); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.priv, data), nil
}

// EncodeSignature returns unpadded base64url for wire formats.
func EncodeSignature(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}

// CanonicalPayload returns deterministic JSON bytes for signing.
func CanonicalPayload(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// VerifySoftwareSignature checks an Ed25519 signature over canonical payload bytes.
func VerifySoftwareSignature(pub, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}

// ErrSignerUnavailable is returned when no platform signer can sign.
var ErrSignerUnavailable = fmt.Errorf("platform signer unavailable")

// --- Relationship private seed storage (security fix) ---
// Private Ed25519 seeds for per-contact / per-login relationship AIDs
// are stored ONLY in the secureenclave/relationships/ subdirectory with 0600 perms,
// mirroring the software fallback for root/platform keys.
// SQLite / login_relationships.json contain only the public AID (the handle/reference).
// Never persist raw seeds in main data stores.

const relSeedsSubdir = "secureenclave/relationships"

func relationshipSeedPath(dataDir, aid string) string {
	// AID chars (E + base64url) are filesystem-safe; no sanitization needed beyond dir.
	return filepath.Join(dataDir, relSeedsSubdir, aid+".seed")
}

// StoreRelationshipSeed writes the seed to the protected location. Caller must ensure
// the seed corresponds to the AID minted via the local KERI engine.
func StoreRelationshipSeed(dataDir, aid string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	p := relationshipSeedPath(dataDir, aid)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, seed, 0600)
}

// LoadRelationshipSeed reads a previously stored seed for the given relationship AID.
// Returns error if not found or invalid (no plaintext seeds in main stores).
func LoadRelationshipSeed(dataDir, aid string) ([]byte, error) {
	p := relationshipSeedPath(dataDir, aid)
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("relationship seed not available for %s (must be loaded from secure storage): %w", aid, err)
	}
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid relationship seed size for %s", aid)
	}
	return raw, nil
}

// Root seed storage (the keystore root seed for HD pairwise derivation).
// Stored in secure location alongside relationship seeds. 64-byte BIP39 seed.

func rootSeedPath(dataDir string) string {
	return filepath.Join(dataDir, "secureenclave", "root_seed.key")
}

func StoreRootSeed(dataDir string, seed []byte) error {
	if len(seed) < 32 {
		return fmt.Errorf("root seed must be at least 32 bytes")
	}
	p := rootSeedPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	// store up to 64 bytes
	toStore := seed
	if len(toStore) > 64 {
		toStore = toStore[:64]
	}
	return os.WriteFile(p, toStore, 0600)
}

func LoadRootSeed(dataDir string) ([]byte, error) {
	p := rootSeedPath(dataDir)
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("root keystore seed not available in secure storage: %w", err)
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("invalid root seed size")
	}
	return raw, nil
}