package keriengine

import (
	"encoding/json"
	"fmt"
)

// Seals, and why they cannot be built from a Go map.
//
// A seal is what an event anchors: a reference to something the identity is
// committing to. It is not free-form JSON. There is a closed set of shapes, and
// the fields appear in a fixed order.
//
// Both halves of that matter, and the second one is the trap. Marshalling a Go
// map emits its keys in sorted order, so a seal assembled as
// map[string]string{"i":…, "s":…, "d":…} is written as {"d","i","s"} — the
// right fields, the wrong order. It looks correct in a debugger and in a log.
// It was measured against an independent implementation: the same seal is
// accepted in the specified order and refused in sorted order.
//
// A refused anchor does not fail loudly at the point it was built. The event is
// well-formed, it digests, it signs, and it is published. What fails is another
// implementation reading the log afterwards, which is far away from the cause
// and may be another organisation's software.
//
// So seals are built here, in order, and never from a map.

// eventSeal refers to one event in an identity's log: which identity, where in
// the log, and which event exactly.
//
// All three are needed. A seal naming only the identity would approve anything
// that identity ever published, and one naming only the position would be
// satisfied by whatever event later occupied it.
func eventSeal(identifier, sn, digest string) (json.RawMessage, error) {
	if identifier == "" || sn == "" || digest == "" {
		return nil, fmt.Errorf("an event seal needs an identifier, a sequence number and a "+
			"digest; got %q, %q, %q", identifier, sn, digest)
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%s,"s":%s,"d":%s}`,
		quote(identifier), quote(sn), quote(digest))), nil
}

// digestSeal refers to something by content alone — a credential, a document,
// anything whose identifier is its digest.
func digestSeal(digest string) (json.RawMessage, error) {
	if digest == "" {
		return nil, fmt.Errorf("a digest seal needs a digest")
	}
	return json.RawMessage(fmt.Sprintf(`{"d":%s}`, quote(digest))), nil
}

// quote renders a string as a JSON string, so a value containing a quote or a
// backslash cannot break out of the seal being assembled.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string does not fail; this keeps the helper total.
		return `""`
	}
	return string(b)
}

// normaliseAnchor puts a caller's anchor into the form an event can carry.
//
// A caller that has already produced ordered JSON is passed through untouched —
// it has said exactly what it means. A caller passing a map has not, because
// the map has no order, so any seal-shaped map is rebuilt in the specified
// order rather than marshalled as it stands.
//
// An anchor that is not seal-shaped is passed through as the caller wrote it.
// It is not this function's place to refuse it: anchoring arbitrary data is
// legal, and callers do it. What is NOT legal is a seal with the right fields
// in the wrong order, and that is the case this exists to prevent.
func normaliseAnchor(v interface{}) (json.RawMessage, error) {
	if raw, ok := v.(json.RawMessage); ok {
		return raw, nil
	}
	if raw, ok := v.([]byte); ok {
		return json.RawMessage(raw), nil
	}

	// Re-read through a generic map so the same logic covers a map, a struct
	// and anything else that encodes as a JSON object.
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("the anchor cannot be encoded: %w", err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		// Not an object — a string, a number, a list. Anchored as written.
		return encoded, nil
	}

	str := func(k string) (string, bool) {
		s, ok := fields[k].(string)
		return s, ok && s != ""
	}

	switch len(fields) {
	case 3:
		i, hasI := str("i")
		s, hasS := str("s")
		d, hasD := str("d")
		if hasI && hasS && hasD {
			return eventSeal(i, s, d)
		}
	case 1:
		if d, ok := str("d"); ok {
			return digestSeal(d)
		}
	}
	return encoded, nil
}
