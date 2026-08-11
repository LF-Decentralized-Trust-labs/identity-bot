// Package keriengine performs KERI operations in-process, using a Go KERI
// library, for every platform the agent runs on.
//
// It exists because the only previous implementation was a Python subprocess.
// That had two costs. On desktop it made a Python runtime a hard requirement
// for creating an identity. On mobile it made KERI impossible: a phone cannot
// spawn a subprocess, so the driver is not started there, and every call site in
// the Go core takes its "not available" branch. Those operations were done in a
// Rust library reached through the UI instead — a second implementation of the
// same protocol, on the platform where it was hardest to check.
//
// This holds no private keys, and that is deliberate rather than incidental.
// Signing happens where the keys are, on the controller device; an engine that
// could sign would be an engine that had to be trusted with the key material.
// The Python driver takes the same position and answers its own signing
// endpoint with a refusal, which is the behaviour reproduced here.
package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	keri "github.com/grapeid/keri-go"
)

// identity is what the engine remembers about one named identity.
//
// It is the state needed to build the NEXT event: an event names its
// predecessor by digest and by sequence number, so an engine that has forgotten
// them cannot continue a log — only start a new one, which would fork the
// identity.
type identity struct {
	Name string `json:"name"`
	AID  string `json:"aid"`

	// PublicKey and NextKeyDigest are the current signing key and the
	// commitment to its successor, both qb64.
	PublicKey     string `json:"public_key"`
	NextKeyDigest string `json:"next_key_digest"`

	// Witnesses and Toad are held so a rotation can amend the set rather than
	// being handed it. A caller that supplied the current witnesses would be a
	// caller able to get them wrong.
	Witnesses []string `json:"witnesses"`
	Toad      int      `json:"toad"`

	SN       int    `json:"sequence_number"`
	LastSAID string `json:"last_said"`

	// KEL holds every event, in order.
	KEL []kelEntry `json:"kel"`

	// HistoryVerified records whether the log this identity was restored with
	// could be checked. False means the events were handed over in parsed form
	// only, so the engine can continue the log but has not confirmed the
	// history it is continuing. Reported rather than assumed either way.
	HistoryVerified bool `json:"history_verified"`

	// Registries maps a registry identifier to its transaction event log.
	Registries map[string]*registry `json:"registries"`
}

// kelEntry is one event in a key log.
//
// Raw is the canonical serialisation and is the authoritative form: the
// identifier is a digest over an exact byte sequence in an exact field order,
// so an event re-encoded from Parsed verifies as nothing. Parsed is for reading
// fields.
//
// Raw is nil only for an event restored from storage that predates the
// canonical bytes being kept. Such an event can be read and cannot be verified,
// and the two cases are kept distinguishable here so that nothing downstream
// has to guess which it is holding.
type kelEntry struct {
	Raw    []byte                 `json:"raw"`
	Parsed map[string]interface{} `json:"parsed"`
}

func entry(raw []byte) (kelEntry, error) {
	m, err := eventMap(raw)
	if err != nil {
		return kelEntry{}, err
	}
	return kelEntry{Raw: raw, Parsed: m}, nil
}

// verifiable returns the raw events, and whether every event had one.
func verifiable(entries []kelEntry) ([][]byte, bool) {
	out := make([][]byte, 0, len(entries))
	complete := true
	for _, e := range entries {
		if e.Raw == nil {
			complete = false
			continue
		}
		out = append(out, e.Raw)
	}
	return out, complete
}

// registry is one credential registry and the TEL events issued into it.
type registry struct {
	SAID string `json:"said"`
	// TEL holds issuance and revocation events by credential SAID, in order.
	TEL map[string][][]byte `json:"tel"`
	// IssuanceSAID records the issuance event for each credential, because a
	// revocation names it as its predecessor.
	IssuanceSAID map[string]string `json:"issuance_said"`
}

// state is every identity the engine knows about.
//
// Empty on a cold start, exactly as the Python driver's is. Event state is not
// persisted here because the agent already persists it and rehydrates the
// engine through ReloadIdentity at startup; a second copy would be a second
// thing to keep in step, and the copy that fell behind would be the one that
// silently forked a log.
type state struct {
	mu         sync.RWMutex
	identities map[string]*identity
	// receipts maps an event SAID to the witness receipts seen for it.
	receipts map[string][]receipt
}

type receipt struct {
	WitnessAID string
	PublicKey  string
	CesrSig    string
}

func newState() *state {
	return &state{
		identities: map[string]*identity{},
		receipts:   map[string][]receipt{},
	}
}

// get returns a named identity, or an error naming what is actually held.
//
// The error lists the known names because the failure this catches in practice
// is a caller using a different naming convention from the one that created the
// identity, and "not found" alone sends the reader looking in the wrong place.
func (s *state) get(name string) (*identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.identities[name]
	if !ok {
		known := make([]string, 0, len(s.identities))
		for n := range s.identities {
			known = append(known, n)
		}
		if len(known) == 0 {
			return nil, fmt.Errorf("no identity named %q; the engine holds none at all, "+
				"which is its state before an identity is created or reloaded", name)
		}
		return nil, fmt.Errorf("no identity named %q; the engine holds %s",
			name, strings.Join(known, ", "))
	}
	return id, nil
}

func (s *state) put(id *identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[id.Name] = id
}

// normaliseKey accepts a public key in either form the wire uses and returns
// qb64.
//
// Callers send both: a qb64 key that arrived from a previous response, or raw
// bytes in base64url from a key that was just generated. Guessing wrong is not
// a decoding error — a raw key read as qb64 yields 32 plausible bytes of the
// wrong value, and produces an event that encodes cleanly and verifies against
// nothing.
//
// transferable selects the derivation code: a transferable key belongs to an
// identity that can rotate, a non-transferable one to an identity that is its
// own key forever.
func normaliseKey(key string, transferable bool) (string, error) {
	if key == "" {
		return "", fmt.Errorf("no public key was supplied")
	}
	// Already qb64: a one-character derivation code and 43 characters of
	// payload. Both Ed25519 codes are accepted, and neither is rewritten —
	// changing a non-transferable key into a transferable one would change the
	// identifier of anything derived from it.
	if len(key) == 44 && (key[0] == 'D' || key[0] == 'B') {
		if _, err := keri.MatterRaw(string(key[0]), key, 32); err != nil {
			return "", fmt.Errorf("%q looks like a qb64 key and does not decode as one: %w", key, err)
		}
		return key, nil
	}
	raw, err := decodeB64(key)
	if err != nil {
		return "", fmt.Errorf("the public key is neither qb64 nor base64 raw bytes: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("a public key decodes to %d bytes; Ed25519 keys are 32", len(raw))
	}
	code := keri.CodeEd25519
	if !transferable {
		code = keri.CodeEd25519N
	}
	return keri.MatterQB64(code, raw)
}

// decodeB64 accepts base64 in any of the four spellings in use.
//
// The wire carries standard and URL-safe alphabets, padded and not, depending
// on which language produced the value. Accepting one and rejecting the rest
// would fail on input that is entirely well-formed.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%q is not base64 in any of the standard alphabets", s)
}

// eventMap parses canonical event bytes into the map form the wire uses.
//
// The bytes remain the truth; this is for callers that read fields. Field order
// is lost, which is why the raw form travels alongside it everywhere.
func eventMap(raw []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("an event this engine produced does not parse as JSON: %w", err)
	}
	return m, nil
}

// said reads the self-addressing identifier out of an event.
func said(raw []byte) (string, error) {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return "", err
	}
	return ev.SAID, nil
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// rawData converts the loosely-typed anchor data the wire carries into the
// JSON messages the event builder takes.
func rawData(data []interface{}) ([]json.RawMessage, error) {
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]json.RawMessage, 0, len(data))
	for i, d := range data {
		b, err := normaliseAnchor(d)
		if err != nil {
			return nil, fmt.Errorf("anchor entry %d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}
