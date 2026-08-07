package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/zeebo/blake3"
)

// Verification errors.
var (
	ErrUnknownManifestVersion = errors.New("unknown_manifest_version")
	ErrSignatureInvalid       = errors.New("signature_invalid")
	ErrUntrustedSigningKey    = errors.New("untrusted_signing_key")
	ErrChecksumMismatch       = errors.New("checksum_mismatch")
	ErrBelowMinimumVersion    = errors.New("below_minimum_version")
)

// TrustAnchor maps signing_key_id to compiled-in Ed25519 public keys.
type TrustAnchor struct {
	keys map[string]ed25519.PublicKey
}

func NewTrustAnchor(anchors map[string][]byte) (*TrustAnchor, error) {
	ta := &TrustAnchor{keys: make(map[string]ed25519.PublicKey)}
	for id, raw := range anchors {
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust anchor %q: invalid public key length %d", id, len(raw))
		}
		ta.keys[id] = ed25519.PublicKey(raw)
	}
	return ta, nil
}

func (ta *TrustAnchor) AddTrustedKey(id string, pub ed25519.PublicKey) {
	ta.keys[id] = pub
}

func (ta *TrustAnchor) PublicKey(id string) (ed25519.PublicKey, bool) {
	pub, ok := ta.keys[id]
	return pub, ok
}

// DecodeBase64URL decodes unpadded base64url.
func DecodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// EncodeBase64URL encodes bytes as unpadded base64url.
func EncodeBase64URL(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// VerifyManifest checks UM-1, UM-2, UM-3, UM-10.
func VerifyManifest(raw []byte, ta *TrustAnchor) (*Manifest, error) {
	if ta == nil {
		return nil, ErrUntrustedSigningKey
	}

	var probe struct {
		ManifestVersion int    `json:"manifest_version"`
		SigningKeyID    string `json:"signing_key_id"`
		Signature       string `json:"signature"`
	}
	if err := jsonUnmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	if probe.ManifestVersion != SupportedManifestVersion {
		return nil, ErrUnknownManifestVersion
	}
	if probe.Signature == "" {
		return nil, ErrSignatureInvalid
	}

	pub, ok := ta.PublicKey(probe.SigningKeyID)
	if !ok {
		return nil, ErrUntrustedSigningKey
	}

	canonical, err := CanonicalizeWithoutField(raw, "signature")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	sig, err := DecodeBase64URL(probe.Signature)
	if err != nil {
		return nil, ErrSignatureInvalid
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, ErrSignatureInvalid
	}

	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}

	if m.NextSigningKey != nil {
		if err := ta.learnNextSigningKey(m); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (ta *TrustAnchor) learnNextSigningKey(m *Manifest) error {
	if m.NextSigningKey == nil {
		return nil
	}
	raw, err := DecodeBase64URL(m.NextSigningKey.PublicKey)
	if err != nil {
		return fmt.Errorf("next_signing_key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("next_signing_key: invalid public key length")
	}
	ta.AddTrustedKey(m.NextSigningKey.KeyID, ed25519.PublicKey(raw))
	return nil
}

// VerifyKeyTransition validates a signed key-transition endorsement.
func VerifyKeyTransition(raw []byte, ta *TrustAnchor) (*KeyTransition, error) {
	var kt KeyTransition
	if err := jsonUnmarshal(raw, &kt); err != nil {
		return nil, err
	}
	pub, ok := ta.PublicKey(kt.OldKeyID)
	if !ok {
		return nil, ErrUntrustedSigningKey
	}
	canonical, err := CanonicalizeWithoutField(raw, "signature")
	if err != nil {
		return nil, ErrSignatureInvalid
	}
	sig, err := DecodeBase64URL(kt.Signature)
	if err != nil {
		return nil, ErrSignatureInvalid
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, ErrSignatureInvalid
	}
	newRaw, err := DecodeBase64URL(kt.NewPublicKey)
	if err != nil || len(newRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid new_public_key")
	}
	ta.AddTrustedKey(kt.NewKeyID, ed25519.PublicKey(newRaw))
	return &kt, nil
}

// VerifyArtifactBytes gates apply on blake3_256 and size_bytes (UM-4).
// sha256 is checked for interop only when requested; it never gates apply.
func VerifyArtifactBytes(data []byte, art Artifact, checkSHA256Interop bool) error {
	if int64(len(data)) != art.SizeBytes {
		return fmt.Errorf("%w: size mismatch got %d want %d", ErrChecksumMismatch, len(data), art.SizeBytes)
	}
	wantBlake, err := hex.DecodeString(art.Blake3_256)
	if err != nil {
		return fmt.Errorf("%w: invalid blake3_256 hex", ErrChecksumMismatch)
	}
	gotBlake := blake3.Sum256(data)
	if !bytesEqual(gotBlake[:], wantBlake) {
		return ErrChecksumMismatch
	}
	if checkSHA256Interop && art.SHA256 != "" {
		wantSHA, err := hex.DecodeString(art.SHA256)
		if err != nil {
			return fmt.Errorf("invalid sha256 hex")
		}
		gotSHA := sha256.Sum256(data)
		if !bytesEqual(gotSHA[:], wantSHA) {
			return fmt.Errorf("sha256 interop mismatch")
		}
	}
	return nil
}

// CompareVersion returns -1 if a<b, 0 if equal, 1 if a>b (semver-lite).
func CompareVersion(a, b string) int {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av == bv {
			continue
		}
		if av < bv {
			return -1
		}
		return 1
	}
	return 0
}

// CanDirectUpgrade reports whether installed can jump directly to target (UM-5).
func CanDirectUpgrade(installed, minimum, target string) bool {
	if CompareVersion(installed, minimum) < 0 {
		return false
	}
	return CompareVersion(installed, target) < 0
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SignManifestForTest signs a manifest with a test private key (publisher-side helper).
func SignManifestForTest(raw []byte, priv ed25519.PrivateKey) ([]byte, error) {
	canonical, err := CanonicalizeWithoutField(raw, "signature")
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canonical)
	var obj map[string]interface{}
	if err := jsonUnmarshal(raw, &obj); err != nil {
		return nil, err
	}
	obj["signature"] = EncodeBase64URL(sig)
	return jsonMarshal(obj)
}