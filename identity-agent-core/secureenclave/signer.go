package secureenclave

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/atomicfile"
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
//
// A hardware controller key that exists and will not open is a refusal, never a
// reason to use the software signer: that is a different key in a plain file, and
// a machine that quietly signs with it has become another machine (ADR-074
// section 3). Whatever made the key unusable (a locked identity, a key made by
// another chip, a damaged file, a key the core did not make) the answer is a
// signer that says what holds the key and signs nothing.
func NewPlatformSigner(dataDir string) PlatformSigner {
	platform, label := controllerKeyIsHardwareHere()
	if _, _, err := theGateForThisSeed(dataDir); errors.Is(err, ErrIdentityLocked) && platform != "" {
		return lockedControllerKey{platform: platform, label: label}
	}
	var failed error
	if s := newDarwinSecureEnclaveSigner(dataDir); s != nil {
		if s.Available() {
			return s
		}
		failed = whyUnavailable(s)
	}
	if s := newTPMSigner(); s != nil {
		if p, ok := s.(interface {
			forProfileAt(dataDir string) PlatformSigner
		}); ok {
			s = p.forProfileAt(dataDir)
		}
		if s.Available() {
			return s
		}
		failed = errors.Join(failed, whyUnavailable(s))
	}
	if platform != "" && (aHardwareControllerKeyExistsAt(dataDir) ||
		errors.Is(failed, errAHardwareKeyExistsAndWillNotOpen) || errors.Is(failed, ErrControllerKeyNotOurs)) {
		return refusingControllerKey{platform: platform, label: label, why: failed}
	}
	if s := newStrongBoxSigner(); s != nil && s.Available() {
		return s
	}
	return newSoftwareSigner(dataDir)
}

// errAHardwareKeyExistsAndWillNotOpen marks an error from a hardware signer that
// found its key and could not use it, as against finding none to use.
var errAHardwareKeyExistsAndWillNotOpen = errors.New("a hardware controller key exists and will not open")

// whyUnavailable is the reason a signer that is not available gave, when it
// kept one.
func whyUnavailable(s PlatformSigner) error {
	if w, ok := s.(interface{ whyUnavailable() error }); ok {
		return w.whyUnavailable()
	}
	return nil
}

// HardwareRootStatus reports what this machine can protect a key with, and why.
//
// Separate from NewPlatformSigner because the two answer different questions and
// merging them is what caused the problem this package is being fixed for.
// Choosing a signer needs one bit: use hardware or fall back. Telling somebody
// their identity is capped, or refusing to hold their root key, needs the
// reason — and `Available() bool` throws the reason away at exactly the moment
// it becomes load-bearing.
//
// The falling-back is fine. Silently reporting the fallback as "this machine has
// no security hardware" is not, and that is what a bare bool leaves callers no
// choice but to do.
func HardwareRootStatus() Capability {
	return DetectCapability()
}

// UsingHardware reports whether a signer is hardware-backed.
//
// The software signer names itself "software", so anything else came from an
// enclave, a TPM or StrongBox. Kept as a helper rather than a field so there is
// one definition of the distinction instead of a string comparison repeated at
// every call site — the shape of bug where one of them eventually disagrees.
func UsingHardware(s PlatformSigner) bool {
	return s != nil && s.Platform() != "software"
}

// softwareSigner persists an Ed25519 key for development and non-hardware hosts.
type softwareSigner struct {
	mu       sync.Mutex
	dataDir  string
	priv     ed25519.PrivateKey
	platform string
	label    string
}

// NewSoftwareSigner is a key file in dataDir, for a program that must not use
// this machine's one hardware key — on Windows the TPM key has a single fixed
// name, so a second program using it would share the Identity Agent's own key.
func NewSoftwareSigner(dataDir string) PlatformSigner { return newSoftwareSigner(dataDir) }

func newSoftwareSigner(dataDir string) *softwareSigner {
	s := &softwareSigner{
		dataDir:  dataDir,
		platform: "software",
		label:    "Software signer (development fallback)",
	}
	_ = s.ensureKey()
	return s
}

func (s *softwareSigner) Available() bool  { return true }
func (s *softwareSigner) Platform() string { return s.platform }
func (s *softwareSigner) Label() string    { return s.label }

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
	if err := atomicfile.Write(s.keyPath(), seed, 0600); err != nil {
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

// (per-relationship seed storage removed; only root seed persists in secure enclave.
// Pairwise seeds are re-derived from root + persisted RelationshipIndex.)

// Root seed storage lives in seedwrap.go: the keystore root seed (64-byte BIP39
// class, the HD derivation root) is stored in a self-describing envelope, wrapped
// under a platform hardware key where one is usable.
