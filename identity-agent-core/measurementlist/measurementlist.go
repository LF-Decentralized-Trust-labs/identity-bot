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
// # What reads a list now
//
// The core accepts a list only as a credential issued under a pinned publisher
// identity and anchored in its witnessed key history (package anchored, ADR
// 078), and holds its content to the rules here through FromContent. The signed
// document above (Verify, with a pinned key) is the form the apps' own
// verifier, in Dart, still reads; no core code pins a key or calls Verify, and
// it goes when that verifier does. The floors (highest sequence and the list
// accepted at it, newest place of the publisher's history) are kept by
// anchored.FileFloors, and once a list has been accepted here the bootstrap is
// never used again (see measurementLists.policy in package server).
package measurementlist

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
	"identity-agent-core/update"
)

const (
	// Version is the list_version of a list that says only which measurements
	// are accepted. Every verifier reads it.
	Version = 1

	// VersionHandover is the list_version of a list whose entries also carry
	// what a sealed handover needs of the image behind a measurement: the
	// environment, the security version, whether SMT is allowed, and whether the
	// entry is retired. A verifier that does not read it refuses the list
	// (ErrUnknownVersion), so a publisher moves to it only once the apps that
	// check the list read it too.
	VersionHandover = 2

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

	// The rest is read from a VersionHandover list and is zero in a Version 1
	// list, which a handover therefore refuses (HasSVN is false).
	//
	// Environment is "production" or "development".
	Environment string
	// SVN is the image's security version; HasSVN says the list gave one.
	SVN    uint32
	HasSVN bool
	// SMT is whether the measurement is computed with SMT allowed.
	SMT bool
	// Retired is nil for an entry that is not retired.
	Retired *Retirement
}

// Retirement is an entry's "retired" field. An entry with none is not retired.
type Retirement struct {
	Kind        string    `json:"kind"`
	At          time.Time `json:"at"`
	SourceUntil time.Time `json:"source_until,omitempty"`
}

const (
	// RetiredForUpdate is an image that is no longer accepted as a new box but
	// may still be handed over FROM until SourceUntil, so an organisation on it
	// can update.
	RetiredForUpdate = "update"
	// Revoked is an image withdrawn as compromised: not a source either.
	Revoked = "revoked"
)

// ParseRetirement reads the field and fails closed: null or absent is not
// retired, and anything a verifier cannot read, or a kind it does not know, is
// revoked. A retirement "for update" with no source_until is unreadable too:
// the design requires it.
func ParseRetirement(raw json.RawMessage) *Retirement {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	revoked := &Retirement{Kind: Revoked}
	// Read as strictly as the list itself: an object another reader would read
	// differently (a key in another case, a repeated key, a field it does not
	// know) is unreadable, so it revokes. "at" must be given.
	var r Retirement
	if err := strictjson.Decode(raw, &r); err != nil || r.At.IsZero() {
		return revoked
	}
	switch r.Kind {
	case RetiredForUpdate:
		if r.SourceUntil.IsZero() {
			return revoked
		}
		return &r
	case Revoked:
		return &r
	default:
		return revoked
	}
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

// wireEntryV2 is wireEntry with what VersionHandover adds. Its own type, so a
// Version 1 list that carries any of these is refused as an unknown field
// rather than read as something it never said.
type wireEntryV2 struct {
	Image        string          `json:"image"`
	Measurement  string          `json:"measurement"`
	ComputedFrom ComputedFrom    `json:"computed_from"`
	ValidFrom    string          `json:"valid_from"`
	ValidUntil   *string         `json:"valid_until"`
	Environment  string          `json:"environment"`
	SVN          *uint32         `json:"svn"`
	SMT          *bool           `json:"smt"`
	Retired      json.RawMessage `json:"retired"`
}

type wireListV2 struct {
	ListVersion  int                      `json:"list_version"`
	Sequence     int64                    `json:"sequence"`
	PublishedAt  string                   `json:"published_at"`
	ExpiresAt    string                   `json:"expires_at"`
	SigningKeyID string                   `json:"signing_key_id"`
	Images       map[string][]wireEntryV2 `json:"images"`
	Signature    string                   `json:"signature"`
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
	var v2 map[string][]wireEntryV2
	var peek struct {
		ListVersion int `json:"list_version"`
	}
	_ = json.Unmarshal(raw, &peek) // only to choose the shape to read strictly
	if peek.ListVersion == VersionHandover {
		var x wireListV2
		if err := strictjson.Decode(raw, &x); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		v2 = x.Images
		w = wireList{ListVersion: x.ListVersion, Sequence: x.Sequence, PublishedAt: x.PublishedAt, ExpiresAt: x.ExpiresAt,
			SigningKeyID: x.SigningKeyID, Signature: x.Signature, Images: map[string][]wireEntry{}}
		for kind, es := range x.Images {
			for _, e := range es {
				w.Images[kind] = append(w.Images[kind], wireEntry{Image: e.Image, Measurement: e.Measurement,
					ComputedFrom: e.ComputedFrom, ValidFrom: e.ValidFrom, ValidUntil: e.ValidUntil})
			}
		}
	} else if err := strictjson.Decode(raw, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if w.ListVersion != Version && w.ListVersion != VersionHandover {
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
	digest := sha256.Sum256(msg)
	return FromContent(Content{Sequence: w.Sequence, PublishedAt: w.PublishedAt, ExpiresAt: w.ExpiresAt, Images: w.Images, v2: v2},
		hex.EncodeToString(digest[:]), Rules{MinSequence: p.MinSequence, SeenDigest: p.SeenDigest, Now: p.Now})
}

// Content is what a list says, apart from who vouched for it: the same in a
// list signed by a pinned key and in a credential anchored in a publisher's key
// history, so the rules below are written once.
type Content struct {
	Sequence    int64                  `json:"sequence"`
	PublishedAt string                 `json:"published_at"`
	ExpiresAt   string                 `json:"expires_at"`
	Images      map[string][]wireEntry `json:"images"`
	// v2 holds what VersionHandover entries add, by image kind and in the order
	// of Images; nil for a Version 1 list.
	v2 map[string][]wireEntryV2
}

// Rules are the rules a list's content is held to whoever vouched for it: the
// highest sequence already accepted, the hash of the list accepted at it, and
// the time.
type Rules struct {
	MinSequence int64
	SeenDigest  string
	Now         time.Time
}

// FromContent holds a list's content to the rules and returns the list only if
// all of them pass. digest names this exact list for the same-sequence rule.
func FromContent(c Content, digest string, r Rules) (*List, error) {
	if c.Sequence < 1 {
		return nil, fmt.Errorf("%w: sequence %d", ErrMalformed, c.Sequence)
	}
	if c.Sequence < r.MinSequence {
		return nil, fmt.Errorf("%w: sequence %d, already accepted %d", ErrOldList, c.Sequence, r.MinSequence)
	}
	if c.Sequence == r.MinSequence && r.SeenDigest != "" && digest != r.SeenDigest {
		return nil, fmt.Errorf("%w: sequence %d", ErrConflictingList, c.Sequence)
	}
	published, err := time.Parse(time.RFC3339, c.PublishedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: published_at: %v", ErrMalformed, err)
	}
	expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at: %v", ErrMalformed, err)
	}
	if !expires.After(published) {
		return nil, fmt.Errorf("%w: expires_at is not after published_at", ErrMalformed)
	}
	if !r.Now.Before(expires) {
		return nil, ErrExpired
	}
	if published.After(r.Now) {
		return nil, ErrNotYetPublished
	}
	if len(c.Images) == 0 {
		return nil, fmt.Errorf("%w: no image kinds", ErrMalformed)
	}

	out := &List{Sequence: c.Sequence, PublishedAt: published, ExpiresAt: expires, At: r.Now,
		Digest: digest,
		Images: make(map[string][]Entry, len(c.Images))}
	seen := map[string]bool{}
	for kind, entries := range c.Images {
		if kind == "" {
			return nil, fmt.Errorf("%w: an empty image kind", ErrMalformed)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("%w: image kind %q has no measurements", ErrMalformed, kind)
		}
		for i, we := range entries {
			e, err := parseEntry(we)
			if err != nil {
				return nil, fmt.Errorf("%w: in %q", err, kind)
			}
			if c.v2 != nil {
				if err := addHandoverFields(&e, c.v2[kind][i]); err != nil {
					return nil, fmt.Errorf("%w: in %q", err, kind)
				}
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

// addHandoverFields reads what a VersionHandover entry adds. The environment,
// the security version and SMT must all be stated: an entry that leaves one out
// is a publishing mistake, and a list is not read on a guess. An unreadable
// "retired" is not a refusal of the list but a revoked entry, so one bad entry
// withdraws itself and nothing else.
func addHandoverFields(e *Entry, w wireEntryV2) error {
	if w.Environment != "production" && w.Environment != "development" {
		return fmt.Errorf("%w: environment %q", ErrBadEntry, w.Environment)
	}
	if w.SVN == nil {
		return fmt.Errorf("%w: svn", ErrBadEntry)
	}
	if w.SMT == nil {
		return fmt.Errorf("%w: smt", ErrBadEntry)
	}
	e.Environment, e.SVN, e.HasSVN, e.SMT = w.Environment, *w.SVN, true, *w.SMT
	e.Retired = ParseRetirement(w.Retired)
	return nil
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

// attributes is a list credential's attribute block: the date the issuer gave
// it and the content, and nothing else. There is no holder, because a list is a
// public statement and not something issued to anybody.
type attributes struct {
	D           string                 `json:"d"`
	DT          string                 `json:"dt"`
	Sequence    int64                  `json:"sequence"`
	PublishedAt string                 `json:"published_at"`
	ExpiresAt   string                 `json:"expires_at"`
	Images      map[string][]wireEntry `json:"images"`
}

// attributesV2 is the block of a list whose entries also carry what a handover
// needs (environment, security version, SMT, retirement). It says so with
// "list_version": 2, which a plain block does not have: a block that carries
// those fields without saying so is refused as an unknown field, as in a signed
// list.
type attributesV2 struct {
	D           string                   `json:"d"`
	DT          string                   `json:"dt"`
	ListVersion int                      `json:"list_version"`
	Sequence    int64                    `json:"sequence"`
	PublishedAt string                   `json:"published_at"`
	ExpiresAt   string                   `json:"expires_at"`
	Images      map[string][]wireEntryV2 `json:"images"`
}

// ContentOfAttributes reads the attribute block of a list credential, by the
// same strict rules as a list: no unknown field, no repeated key.
func ContentOfAttributes(raw []byte) (Content, error) {
	if len(raw) == 0 || len(raw) > MaxListBytes {
		return Content{}, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var peek struct {
		ListVersion int `json:"list_version"`
	}
	_ = json.Unmarshal(raw, &peek) // only to choose the shape to read strictly
	if peek.ListVersion != 0 {
		if peek.ListVersion != VersionHandover {
			return Content{}, fmt.Errorf("%w: %d", ErrUnknownVersion, peek.ListVersion)
		}
		var x attributesV2
		if err := strictjson.Decode(raw, &x); err != nil {
			return Content{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if x.DT == "" {
			return Content{}, fmt.Errorf("%w: the credential gives no date", ErrMalformed)
		}
		if err := secondsInUTC(x.PublishedAt, x.ExpiresAt); err != nil {
			return Content{}, err
		}
		for _, es := range x.Images {
			for _, e := range es {
				if err := secondsInUTC(e.ValidFrom, deref(e.ValidUntil)); err != nil {
					return Content{}, err
				}
			}
		}
		c := Content{Sequence: x.Sequence, PublishedAt: x.PublishedAt, ExpiresAt: x.ExpiresAt,
			Images: map[string][]wireEntry{}, v2: x.Images}
		for kind, es := range x.Images {
			for _, e := range es {
				c.Images[kind] = append(c.Images[kind], wireEntry{Image: e.Image, Measurement: e.Measurement,
					ComputedFrom: e.ComputedFrom, ValidFrom: e.ValidFrom, ValidUntil: e.ValidUntil})
			}
		}
		return c, nil
	}
	var a attributes
	if err := strictjson.Decode(raw, &a); err != nil {
		return Content{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if a.DT == "" {
		return Content{}, fmt.Errorf("%w: the credential gives no date", ErrMalformed)
	}
	if err := secondsInUTC(a.PublishedAt, a.ExpiresAt); err != nil {
		return Content{}, err
	}
	for _, es := range a.Images {
		for _, e := range es {
			if err := secondsInUTC(e.ValidFrom, deref(e.ValidUntil)); err != nil {
				return Content{}, err
			}
		}
	}
	return Content{Sequence: a.Sequence, PublishedAt: a.PublishedAt, ExpiresAt: a.ExpiresAt, Images: a.Images}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// secondsInUTC holds the times of a list credential to the one form its schema
// allows: RFC 3339, UTC, whole seconds ("2026-11-12T00:00:00Z"). An empty
// value is not checked here (an absent end is null; a missing start is refused
// where it is parsed).
func secondsInUTC(values ...string) error {
	for _, v := range values {
		if v == "" {
			continue
		}
		if len(v) != len("2006-01-02T15:04:05Z") || v[len(v)-1] != 'Z' {
			return fmt.Errorf("%w: %q is not a time in UTC to the second", ErrMalformed, v)
		}
	}
	return nil
}
