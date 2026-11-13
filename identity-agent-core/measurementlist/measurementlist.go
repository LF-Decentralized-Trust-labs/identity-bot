// Package measurementlist holds the rules the published list of launch
// measurements is read by: what an entry says and when it is accepted.
//
// A launch measurement says what a machine booted. Whether that is software
// the owner accepts cannot be answered by the machine, nor by the QR code or
// link that led to it, because both arrive through the same channel as the
// image and would vouch for themselves. It comes from a list that one
// publisher issues and everyone receives identically.
//
// Who vouches for a list is not decided here. The core accepts a list only as
// a credential issued under a pinned publisher identity and anchored in its
// witnessed key history (package anchored, ADR-078), and holds its content to
// the rules below through ContentOfAttributes and FromContent. The floors
// (highest sequence and the list accepted at it, newest place of the
// publisher's history) are kept by anchored.FileFloors, and once a list has
// been accepted the bootstrap is never used again (see measurementLists.policy
// in package server). There is no signed-document form and no pinned key: the
// earlier one, a document signed by one Ed25519 key, is gone.
//
// The list names more than one measurement per image kind, so a rollout with
// two live versions rejects nobody. A measurement is not a bare number: one
// image measures differently for each firmware, vCPU count and CPU model, so
// each entry says which image it is, what the number was computed from (so
// anyone can rebuild the image and recompute it offline with sev-snp-measure)
// and the window in which it is accepted. During an update the old and the new
// image both have entries valid at once. An entry stops being accepted at its
// valid_until, or when a newer list (a higher sequence) leaves it out; an
// entry outside its window is carried for the record and is not accepted.
//
// # What is refused
//
// A sequence below the highest one already accepted (an old list, which may
// still name an image since found vulnerable), or a different list at that
// same sequence; a list past its expiry, dated in the future, or one that
// expires before it was published; a malformed measurement; a repeated
// measurement or image kind; an unknown field or version. There is no partial
// acceptance: any fault refuses the whole list.
package measurementlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
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
)

// Refusals. Each is a different thing for an operator to do something about,
// so they are distinct and wrapped rather than collapsed into "invalid".
var (
	ErrMalformed        = errors.New("the list is not well formed")
	ErrUnknownVersion   = errors.New("the list is a version this verifier does not read")
	ErrOldList          = errors.New("the list is older than one already accepted")
	ErrConflictingList  = errors.New("a different list than the one already accepted carries the same sequence")
	ErrExpired          = errors.New("the list has expired")
	ErrNotYetPublished  = errors.New("the list is dated in the future")
	ErrBadMeasurement   = errors.New("the list holds a malformed measurement")
	ErrDuplicateEntries = errors.New("the list repeats a measurement or an image kind")
	ErrBadEntry         = errors.New("a list entry does not say what its measurement was computed from, or when it is valid")
)

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

// Content is what a list says, apart from who vouched for it: what the
// credential anchored in a publisher's key history carries, apart from the
// anchoring that vouches for it.
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
