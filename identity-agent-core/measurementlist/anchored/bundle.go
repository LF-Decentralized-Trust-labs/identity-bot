package anchored

import (
	"encoding/base64"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/internal/strictjson"
)

const (
	// BundleVersion is the only bundle_version this package reads.
	BundleVersion = 1
	// MaxBundleBytes bounds what is parsed.
	MaxBundleBytes = 4 << 20
	// maxBundleParts bounds each list in a bundle.
	maxBundleParts = 4096
)

// Bundle is what travels: the publisher's key history, the registry's events and
// the list credentials, as raw bytes.
type Bundle struct {
	Version     int      `json:"bundle_version"`
	Publisher   string   `json:"publisher"`
	Registry    string   `json:"registry"`
	KEL         [][]byte `json:"-"`
	TEL         [][]byte `json:"-"`
	Credentials [][]byte `json:"-"`
}

type wireBundle struct {
	Version     int      `json:"bundle_version"`
	Publisher   string   `json:"publisher"`
	Registry    string   `json:"registry"`
	KEL         []string `json:"kel"`
	TEL         []string `json:"tel"`
	Credentials []string `json:"credentials"`
}

// ParseBundle reads a bundle strictly: no unknown field, no repeated key, every
// part unpadded base64url.
func ParseBundle(raw []byte) (*Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var w wireBundle
	if err := strictjson.Decode(raw, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if w.Version != BundleVersion {
		return nil, fmt.Errorf("%w: bundle_version %d", ErrMalformed, w.Version)
	}
	b := &Bundle{Version: w.Version, Publisher: w.Publisher, Registry: w.Registry}
	var err error
	if b.KEL, err = decodeParts("kel", w.KEL); err != nil {
		return nil, err
	}
	if b.TEL, err = decodeParts("tel", w.TEL); err != nil {
		return nil, err
	}
	if b.Credentials, err = decodeParts("credentials", w.Credentials); err != nil {
		return nil, err
	}
	return b, nil
}

func decodeParts(what string, in []string) ([][]byte, error) {
	if len(in) > maxBundleParts {
		return nil, fmt.Errorf("%w: %s holds %d parts", ErrMalformed, what, len(in))
	}
	out := make([][]byte, 0, len(in))
	for i, s := range in {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("%w: %s %d is not unpadded base64url", ErrMalformed, what, i)
		}
		out = append(out, b)
	}
	return out, nil
}

// Encode writes a bundle in the form ParseBundle reads, for the publisher.
func (b *Bundle) Encode() ([]byte, error) {
	enc := func(in [][]byte) []string {
		out := make([]string, 0, len(in))
		for _, p := range in {
			out = append(out, base64.RawURLEncoding.EncodeToString(p))
		}
		return out
	}
	return jsonMarshal(wireBundle{Version: BundleVersion, Publisher: b.Publisher, Registry: b.Registry,
		KEL: enc(b.KEL), TEL: enc(b.TEL), Credentials: enc(b.Credentials)})
}

// Pin is what a build holds of the publisher: never a key.
type Pin struct {
	// Publisher is the publisher's identifier.
	Publisher string
	// InceptionEvent is the publisher's inception event, as raw bytes.
	InceptionEvent []byte
	// Registry is the identifier of the registry lists are issued into.
	Registry string
	// SchemaSAID is the SAID of the schema of "accepted launch measurements".
	SchemaSAID string
}

// ParsePin reads a pin given as text (as a build is given it) and checks that
// the inception event is an inception and derives the identifier.
func ParsePin(publisher, inceptionB64, registry, schema string) (Pin, error) {
	if publisher == "" || inceptionB64 == "" || registry == "" || schema == "" {
		return Pin{}, ErrNoPin
	}
	icp, err := base64.RawURLEncoding.Strict().DecodeString(inceptionB64)
	if err != nil {
		return Pin{}, fmt.Errorf("the pinned inception event is not unpadded base64url: %w", err)
	}
	p := Pin{Publisher: publisher, InceptionEvent: icp, Registry: registry, SchemaSAID: schema}
	return p, p.check()
}

func (p Pin) check() error {
	if p.Publisher == "" || len(p.InceptionEvent) == 0 || p.Registry == "" || p.SchemaSAID == "" {
		return ErrNoPin
	}
	if err := keri.ValidateEvent(p.InceptionEvent); err != nil {
		return fmt.Errorf("the pinned inception event is not a valid event: %w", err)
	}
	ev, err := keri.ParseEvent(p.InceptionEvent)
	if err != nil {
		return fmt.Errorf("the pinned inception event is unreadable: %w", err)
	}
	if ev.Ilk != "icp" || ev.Identifier != p.Publisher {
		return errors.New("the pinned inception event is not the inception of the pinned publisher")
	}
	return nil
}

// NewBundle assembles a bundle from what a publisher's box holds: the key
// history as the witnesses serve it (one CESR stream, every event with its
// signatures and receipts), and the registry's events and the credentials as raw
// bytes. It checks nothing; Verify does.
func NewBundle(publisher, registry string, kelStream []byte, tel, credentials [][]byte) (*Bundle, error) {
	msgs, err := keri.ParseKELStream(kelStream)
	if err != nil {
		return nil, fmt.Errorf("%w: the key history: %v", ErrMalformed, err)
	}
	return &Bundle{Version: BundleVersion, Publisher: publisher, Registry: registry, KEL: msgs, TEL: tel, Credentials: credentials}, nil
}
