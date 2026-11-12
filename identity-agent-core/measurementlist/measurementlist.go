// Package measurementlist verifies the signed, published list of launch
// measurements an owner will accept a sealed box for.
//
// A launch measurement says what a machine booted. Whether that is software
// the owner accepts cannot be answered by the machine, nor by the QR code or
// link that led to it, because both arrive through the same channel as the
// image and would vouch for themselves. It comes from a list that one
// publisher signs and everyone receives identically, checked against a public
// key the app already holds. Serving one person a different list then needs
// the publisher's key, and is visible to everyone who compares lists.
//
// The list names more than one measurement per image kind, so a rollout with
// two live versions rejects nobody.
//
// # Format (list_version 1)
//
// A JSON object, strict (no unknown fields, no repeated keys):
//
//	{
//	  "list_version": 1,
//	  "sequence": 7,                         // rises with every publication
//	  "published_at": "2026-11-12T00:00:00Z",
//	  "expires_at":   "2026-12-12T00:00:00Z",
//	  "signing_key_id": "measurements-prod-1",
//	  "images": { "<image kind>": ["<96 lowercase hex>", ...], ... },
//	  "signature": "<86 chars unpadded base64url>"
//	}
//
// The signature is Ed25519 over the ASCII line "measurement-list-v1\n"
// followed by the RFC 8785 canonical form of the object with "signature"
// removed. The prefix means a signature made for any other signed document
// signed by the same key is not a signature on a list.
//
// # What a verifier refuses
//
// Anything but a list signed by the pinned key under the pinned key id; an
// unknown version; a sequence below the highest one this verifier has already
// accepted (an old list, which may still name an image since found
// vulnerable); a list past its expiry, or one that expires before it was
// published; a malformed measurement; a repeated measurement or image kind.
// There is no partial acceptance: any fault refuses the whole list.
package measurementlist

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
	"identity-agent-core/update"
)

const (
	// Version is the only list_version this package reads.
	Version = 1

	// MeasurementSize is the length of a SEV-SNP launch measurement.
	MeasurementSize = 48

	// MaxListBytes bounds what is parsed; a real list is a few kilobytes.
	MaxListBytes = 1 << 20

	signingPrefix = "measurement-list-v1\n"
)

// Refusals. Each is a different thing for an operator to do something about,
// so they are distinct and wrapped rather than collapsed into "invalid".
var (
	ErrNoKey            = errors.New("no publisher key is pinned, so no list can be verified")
	ErrMalformed        = errors.New("the list is not well formed")
	ErrUnknownVersion   = errors.New("the list is a version this verifier does not read")
	ErrWrongKeyID       = errors.New("the list names a signing key other than the pinned one")
	ErrBadSignature     = errors.New("the list's signature is not valid for the pinned key")
	ErrOldList          = errors.New("the list is older than one already accepted")
	ErrExpired          = errors.New("the list has expired")
	ErrNotYetPublished  = errors.New("the list is dated in the future")
	ErrBadMeasurement   = errors.New("the list holds a malformed measurement")
	ErrDuplicateEntries = errors.New("the list repeats a measurement or an image kind")
)

// PinnedKey is the publisher's key as an app holds it.
type PinnedKey struct {
	ID     string
	Public ed25519.PublicKey
}

// Policy is what a verifier brings: the key it trusts, the highest sequence
// it has already accepted, and the time.
type Policy struct {
	Key PinnedKey
	// MinSequence is the highest sequence already accepted. A list below it
	// is refused; a list equal to it is the same list again and is fine.
	MinSequence int64
	Now         time.Time
}

// List is a verified list. It exists only as the result of Verify.
type List struct {
	Sequence    int64
	PublishedAt time.Time
	ExpiresAt   time.Time
	// Images maps an image kind to the measurements accepted for it.
	Images map[string][][]byte
}

// Measurements returns the accepted measurements for one image kind. A kind
// the list does not name has none, which a caller must treat as "accept
// nothing", never as "no restriction".
func (l *List) Measurements(kind string) [][]byte {
	if l == nil {
		return nil
	}
	return l.Images[kind]
}

type wireList struct {
	ListVersion  int                 `json:"list_version"`
	Sequence     int64               `json:"sequence"`
	PublishedAt  string              `json:"published_at"`
	ExpiresAt    string              `json:"expires_at"`
	SigningKeyID string              `json:"signing_key_id"`
	Images       map[string][]string `json:"images"`
	Signature    string              `json:"signature"`
}

// SignedBytes returns the exact bytes the signature covers for a list in raw
// form. Exported so the publisher signs what the verifier checks.
func SignedBytes(raw []byte) ([]byte, error) {
	canonical, err := update.CanonicalizeWithoutField(raw, "signature")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return append([]byte(signingPrefix), canonical...), nil
}

// Verify checks a list and returns it only if every check passes.
//
// The signature is checked before the content is trusted for anything, and
// the content is checked in full before anything is returned.
func Verify(raw []byte, p Policy) (*List, error) {
	if len(p.Key.Public) != ed25519.PublicKeySize || p.Key.ID == "" {
		return nil, ErrNoKey
	}
	if len(raw) == 0 || len(raw) > MaxListBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var w wireList
	if err := strictjson.Decode(raw, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if w.ListVersion != Version {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, w.ListVersion)
	}
	if w.SigningKeyID != p.Key.ID {
		return nil, fmt.Errorf("%w: %q", ErrWrongKeyID, w.SigningKeyID)
	}
	sig, err := iacrypto.DecodeBase64URLSized(w.Signature, ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	msg, err := SignedBytes(raw)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(p.Key.Public, msg, sig) {
		return nil, ErrBadSignature
	}

	// Signed, so now the content is the publisher's. Still held to the rules.
	if w.Sequence < 1 {
		return nil, fmt.Errorf("%w: sequence %d", ErrMalformed, w.Sequence)
	}
	if w.Sequence < p.MinSequence {
		return nil, fmt.Errorf("%w: sequence %d, already accepted %d", ErrOldList, w.Sequence, p.MinSequence)
	}
	published, err := time.Parse(time.RFC3339, w.PublishedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: published_at: %v", ErrMalformed, err)
	}
	expires, err := time.Parse(time.RFC3339, w.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at: %v", ErrMalformed, err)
	}
	if !expires.After(published) {
		return nil, fmt.Errorf("%w: expires_at is not after published_at", ErrMalformed)
	}
	if !p.Now.Before(expires) {
		return nil, ErrExpired
	}
	if published.After(p.Now) {
		return nil, ErrNotYetPublished
	}
	if len(w.Images) == 0 {
		return nil, fmt.Errorf("%w: no image kinds", ErrMalformed)
	}

	out := &List{Sequence: w.Sequence, PublishedAt: published, ExpiresAt: expires,
		Images: make(map[string][][]byte, len(w.Images))}
	seen := map[string]bool{}
	for kind, values := range w.Images {
		if kind == "" {
			return nil, fmt.Errorf("%w: an empty image kind", ErrMalformed)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("%w: image kind %q has no measurements", ErrMalformed, kind)
		}
		for _, v := range values {
			raw, err := iacrypto.DecodeHex(v)
			if err != nil || len(raw) != MeasurementSize {
				return nil, fmt.Errorf("%w: in %q", ErrBadMeasurement, kind)
			}
			// A measurement listed twice, or under two kinds, is a publishing
			// mistake that would let one image stand as another.
			if seen[v] {
				return nil, fmt.Errorf("%w: in %q", ErrDuplicateEntries, kind)
			}
			seen[v] = true
			out.Images[kind] = append(out.Images[kind], raw)
		}
	}
	return out, nil
}

// ParseKeyHex reads a pinned public key written as lowercase hex.
func ParseKeyHex(id, h string) (PinnedKey, error) {
	if h == "" {
		return PinnedKey{}, ErrNoKey
	}
	raw, err := iacrypto.DecodeHex(h)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return PinnedKey{}, fmt.Errorf("the pinned publisher key is not %d bytes of lowercase hex", ed25519.PublicKeySize)
	}
	if which, bad := publishedTestKeys[h]; bad {
		return PinnedKey{}, fmt.Errorf("the pinned publisher key is %s, whose private key is public", which)
	}
	return PinnedKey{ID: id, Public: ed25519.PublicKey(raw)}, nil
}

// publishedTestKeys are keys whose private halves are printed in a standard.
var publishedTestKeys = map[string]string{
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a": "RFC 8032 §7.1 Test 1",
}
