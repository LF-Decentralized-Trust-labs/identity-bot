package keri

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"identity-agent-core/iacrypto"
)

// An interaction event: the simplest thing a key history can contain after its
// first event, and the one that anchors a credential, a delegation or a key
// commitment into that history.
//
// Implemented first because it exercises everything the harder events need —
// ordered serialisation, a version string that states its own length, and a
// self-addressing digest taken over the event with its own identifier blanked —
// with the least else going on. If this does not agree with the reference,
// nothing more elaborate will.

// ixnWire is an interaction event in the order KERI serialises it.
//
// Field ORDER is not a style choice. The version string states the length of
// what follows, and the identifier is a digest of the whole thing, so
// reordering these produces a different identity. This is a struct rather than
// a map because Go marshals a struct in declaration order and a map
// alphabetically — and the alphabetical form is precisely what made our stored
// events unreadable to the reference implementation for months.
type ixnWire struct {
	V string `json:"v"`
	T string `json:"t"`
	D string `json:"d"`
	I string `json:"i"`
	S string `json:"s"`
	P string `json:"p"`
	// Seals are carried as the bytes they arrived as, never through a map.
	//
	// A seal's field order is part of the event, and Go marshals a map
	// alphabetically — so putting a seal through one silently reorders it and
	// changes the identifier. That is not hypothetical: it is what this case
	// caught the first time it ran.
	A []json.RawMessage `json:"a"`
}

// saidPlaceholderLen is the width of a CESR Blake3-256 identifier.
//
// The placeholder written before hashing must be exactly this wide, so that
// substituting the real value cannot change the event's length after the
// version string has already declared it.
const saidPlaceholderLen = 44

var versionPattern = regexp.MustCompile(`KERI[0-9a-f]{2}JSON[0-9a-f]{6}_`)

// versionString declares the serialisation and the event's total size.
func versionString(size int) string {
	return fmt.Sprintf("KERI10JSON%06x_", size)
}

// BuildInteraction returns the canonical bytes of an interaction event.
func BuildInteraction(in InteractionInput) ([]byte, error) {
	if in.Prefix == "" {
		return nil, fmt.Errorf("an interaction must name the identity it belongs to")
	}
	if in.PriorSAID == "" {
		return nil, fmt.Errorf("an interaction must chain to the event before it")
	}
	seals := in.Data
	if seals == nil {
		seals = []json.RawMessage{}
	}

	w := ixnWire{
		T: "ixn",
		D: strings.Repeat("#", saidPlaceholderLen),
		I: in.Prefix,
		S: sequenceNumber(in.SN),
		P: in.PriorSAID,
		A: seals,
	}

	// First pass: the event with its identifier blanked. The digest is taken
	// over exactly these bytes — not over the event without the field, and not
	// with a placeholder of a different width, either of which produces an
	// answer nothing else in the world agrees with.
	dummy, err := serialize(w)
	if err != nil {
		return nil, err
	}
	said, err := iacrypto.Blake3QB64(dummy)
	if err != nil {
		return nil, fmt.Errorf("could not compute the event's identifier: %w", err)
	}
	if len(said) != saidPlaceholderLen {
		return nil, fmt.Errorf("identifier is %d characters and the placeholder was %d, "+
			"so the event's declared size is now wrong", len(said), saidPlaceholderLen)
	}

	w.D = said
	return serialize(w)
}

// sequenceNumber renders a sequence number the way KERI writes it: lowercase
// hexadecimal, no padding, no prefix.
//
// Stated rather than assumed, because "1", "01" and "0x1" are three different
// events with three different identifiers.
func sequenceNumber(sn int) string {
	return strconv.FormatInt(int64(sn), 16)
}

// serialize renders an event and fills in the size its version string declares.
//
// Two passes are unavoidable: the version string states the length of the
// serialised event and is itself part of it, so the size is not known until
// after serialising. The placeholder is written at the exact final width, so
// filling it in cannot change the length it is declaring.
func serialize(event interface{}) ([]byte, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if !versionPattern.Match(raw) {
		return nil, fmt.Errorf("the event carries no version string to fill in")
	}
	patched := versionPattern.ReplaceAll(raw, []byte(versionString(len(raw))))
	if len(patched) != len(raw) {
		return nil, fmt.Errorf("declaring the size changed the length, from %d to %d",
			len(raw), len(patched))
	}
	return patched, nil
}

// init writes the version placeholder at its final width, so that the two
// serialisation passes agree on length.
func (w ixnWire) MarshalJSON() ([]byte, error) {
	type wire ixnWire // avoid recursing into this method
	if w.V == "" {
		w.V = versionString(0)
	}
	return json.Marshal(wire(w))
}
