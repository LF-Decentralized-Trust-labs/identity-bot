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
// two live versions rejects nobody. A measurement is not a bare number: one
// image measures differently for each firmware, vCPU count and CPU model, so
// each entry says which image it is, what the number was computed from (so
// anyone can rebuild the image and recompute it offline with sev-snp-measure)
// and the window in which it is accepted.
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
//	  "images": { "<image kind>": [ <entry>, ... ], ... },
//	  "signature": "<86 chars unpadded base64url>"
//	}
//
// An entry:
//
//	{
//	  "image": "individual-v19",
//	  "measurement": "<96 lowercase hex>",
//	  "computed_from": {
//	    "ovmf_sha256": "<64 lowercase hex>",    // the pinned firmware
//	    "vcpus": 1,
//	    "cpu_model": "EPYC-v4",
//	    "guest_features": "0x1",              // optional
//	    "cmdline_sha256": "<64 lowercase hex>", // the measured kernel command line
//	    "kernel_sha256": "<64 hex, optional>",
//	    "initrd_sha256": "<64 hex, optional>",
//	    "root_hash": "<hex, optional>"          // the verity root hash
//	  },
//	  "valid_from":  "2026-11-01T00:00:00Z",
//	  "valid_until": "2026-12-01T00:00:00Z"     // or null: until a newer list drops it
//	}
//
// During an update the old and the new image both have entries valid at once.
// An entry stops being accepted at its valid_until, or when a newer list (a
// higher sequence) leaves it out; an entry outside its window is carried in a
// list for the record and is not accepted.
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
// vulnerable), or a different list at that same sequence; a list past its expiry, or one that expires before it was
// published; a malformed measurement; a repeated measurement or image kind.
// There is no partial acceptance: any fault refuses the whole list.
//
// # What guards what, and what is left
//
// The floor file (LoadFile) holds the highest sequence accepted and that
// list's hash. It is what stops an older list being put back, and a different
// list being served at the same sequence. Once it is above zero the agent
// never falls back to its bootstrap policy: every list failure then means no
// box is accepted (see measurementPolicy in package server).
//
// A clock set back is not guarded by the floor: it can make an expired list
// look current. What limits it is that an old list cannot be used below the
// floor whatever the time, and that entries carry their own windows, so only
// a list at or above the floor can be extended by a wrong clock.
//
// The floor and the list sit together on the same machine. Deleting both
// returns the agent to "nothing ever accepted", which is the one remaining
// attack; it needs write access to the agent's data directory. The floor is
// written 0600 there, apart from wherever the list file is delivered to, so
// whoever only delivers lists cannot delete it. Where a platform offers a
// store the list's writer cannot reach (a keychain item, a sealed counter),
// the floor belongs there; that is not done yet.
package measurementlist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	ErrConflictingList  = errors.New("a different list than the one already accepted carries the same sequence")
	ErrExpired          = errors.New("the list has expired")
	ErrNotYetPublished  = errors.New("the list is dated in the future")
	ErrBadMeasurement   = errors.New("the list holds a malformed measurement")
	ErrDuplicateEntries = errors.New("the list repeats a measurement or an image kind")
	ErrBadEntry         = errors.New("a list entry does not say what its measurement was computed from, or when it is valid")
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
	// SeenDigest is the hash (hex) of the list accepted at MinSequence, or ""
	// if unknown. A list at exactly MinSequence must hash to it: the same
	// sequence is the same list, never a different one.
	SeenDigest string
	Now        time.Time
}

// ComputedFrom is what a measurement was computed from. Everything here is
// public, and with the published image anyone can recompute the measurement.
type ComputedFrom struct {
	OVMFSHA256 string `json:"ovmf_sha256"`
	VCPUs      int    `json:"vcpus"`
	CPUModel   string `json:"cpu_model"`
	// GuestFeatures is the SNP guest feature word, e.g. "0x1" (optional).
	GuestFeatures string `json:"guest_features,omitempty"`
	CmdlineSHA256 string `json:"cmdline_sha256"`
	KernelSHA256  string `json:"kernel_sha256,omitempty"`
	InitrdSHA256  string `json:"initrd_sha256,omitempty"`
	RootHash      string `json:"root_hash,omitempty"`
}

// Entry is one accepted measurement of one image.
type Entry struct {
	Image        string
	Measurement  []byte
	ComputedFrom ComputedFrom
	ValidFrom    time.Time
	// ValidUntil is the zero time for an entry with no end of its own.
	ValidUntil time.Time
}

// ValidAt reports whether the entry is in its window at t.
func (e Entry) ValidAt(t time.Time) bool {
	return !t.Before(e.ValidFrom) && (e.ValidUntil.IsZero() || t.Before(e.ValidUntil))
}

// List is a verified list. It exists only as the result of Verify.
type List struct {
	Sequence    int64
	PublishedAt time.Time
	ExpiresAt   time.Time
	// Images maps an image kind to its entries, valid or not.
	Images map[string][]Entry
	// At is the time the list was verified at.
	At time.Time
	// Digest is the hex SHA-256 of the signed bytes (canonical form), so
	// re-serialising the same list does not change it.
	Digest string
}

// Measurements returns the measurements accepted for one image kind at the
// time the list was verified. A kind the list does not name, or whose entries
// are all outside their window, has none, which a caller must treat as "accept
// nothing", never as "no restriction".
func (l *List) Measurements(kind string) [][]byte {
	if l == nil {
		return nil
	}
	return l.MeasurementsAt(kind, l.At)
}

// MeasurementsAt is Measurements for another time, for a long-running process.
func (l *List) MeasurementsAt(kind string, t time.Time) [][]byte {
	if l == nil {
		return nil
	}
	var out [][]byte
	for _, e := range l.Images[kind] {
		if e.ValidAt(t) {
			out = append(out, e.Measurement)
		}
	}
	return out
}

type wireEntry struct {
	Image        string       `json:"image"`
	Measurement  string       `json:"measurement"`
	ComputedFrom ComputedFrom `json:"computed_from"`
	ValidFrom    string       `json:"valid_from"`
	ValidUntil   *string      `json:"valid_until"`
}

type wireList struct {
	ListVersion  int                    `json:"list_version"`
	Sequence     int64                  `json:"sequence"`
	PublishedAt  string                 `json:"published_at"`
	ExpiresAt    string                 `json:"expires_at"`
	SigningKeyID string                 `json:"signing_key_id"`
	Images       map[string][]wireEntry `json:"images"`
	Signature    string                 `json:"signature"`
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
	digest := sha256.Sum256(msg)
	if w.Sequence == p.MinSequence && p.SeenDigest != "" && hex.EncodeToString(digest[:]) != p.SeenDigest {
		return nil, fmt.Errorf("%w: sequence %d", ErrConflictingList, w.Sequence)
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

	out := &List{Sequence: w.Sequence, PublishedAt: published, ExpiresAt: expires, At: p.Now,
		Digest: hex.EncodeToString(digest[:]),
		Images: make(map[string][]Entry, len(w.Images))}
	seen := map[string]bool{}
	for kind, entries := range w.Images {
		if kind == "" {
			return nil, fmt.Errorf("%w: an empty image kind", ErrMalformed)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("%w: image kind %q has no measurements", ErrMalformed, kind)
		}
		for _, we := range entries {
			e, err := parseEntry(we)
			if err != nil {
				return nil, fmt.Errorf("%w: in %q", err, kind)
			}
			// A measurement listed twice, or under two kinds, is a publishing
			// mistake that would let one image stand as another.
			if seen[we.Measurement] {
				return nil, fmt.Errorf("%w: in %q", ErrDuplicateEntries, kind)
			}
			seen[we.Measurement] = true
			out.Images[kind] = append(out.Images[kind], e)
		}
	}
	return out, nil
}

func isHex(s string, n int) bool {
	b, err := iacrypto.DecodeHex(s)
	return err == nil && len(b) == n
}

func parseEntry(we wireEntry) (Entry, error) {
	raw, err := iacrypto.DecodeHex(we.Measurement)
	if err != nil || len(raw) != MeasurementSize {
		return Entry{}, ErrBadMeasurement
	}
	c := we.ComputedFrom
	switch {
	case we.Image == "":
		return Entry{}, fmt.Errorf("%w: no image name", ErrBadEntry)
	case !isHex(c.OVMFSHA256, 32):
		return Entry{}, fmt.Errorf("%w: ovmf_sha256", ErrBadEntry)
	case c.VCPUs < 1:
		return Entry{}, fmt.Errorf("%w: vcpus", ErrBadEntry)
	case c.CPUModel == "":
		return Entry{}, fmt.Errorf("%w: cpu_model", ErrBadEntry)
	case !isHex(c.CmdlineSHA256, 32):
		return Entry{}, fmt.Errorf("%w: cmdline_sha256", ErrBadEntry)
	case c.KernelSHA256 != "" && !isHex(c.KernelSHA256, 32):
		return Entry{}, fmt.Errorf("%w: kernel_sha256", ErrBadEntry)
	case c.InitrdSHA256 != "" && !isHex(c.InitrdSHA256, 32):
		return Entry{}, fmt.Errorf("%w: initrd_sha256", ErrBadEntry)
	}
	from, err := time.Parse(time.RFC3339, we.ValidFrom)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: valid_from", ErrBadEntry)
	}
	e := Entry{Image: we.Image, Measurement: raw, ComputedFrom: c, ValidFrom: from}
	if we.ValidUntil != nil {
		until, err := time.Parse(time.RFC3339, *we.ValidUntil)
		if err != nil || !until.After(from) {
			return Entry{}, fmt.Errorf("%w: valid_until", ErrBadEntry)
		}
		e.ValidUntil = until
	}
	return e, nil
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
