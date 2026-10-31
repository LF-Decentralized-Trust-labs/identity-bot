package witnessproto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	keri "github.com/grapeid/keri-go"
)

// SequenceNumber reads a key event's sequence number.
//
// KERI writes it in hexadecimal: the eleventh event is "a" and the seventeenth
// "10". Read as decimal, "a" fails to parse and "10" reads as ten, so a reader
// that gets this wrong places events at the wrong position in the log from the
// eleventh event on.
//
// It is read in its one canonical spelling, as KERI writes it: a string of
// lowercase hexadecimal with no leading zeros ("0" itself included), no
// larger than an int32. A JSON number is not how KERI writes one and is
// refused, as are uppercase digits and leading zeros, which would give one
// position several strings. A missing or unreadable sequence number is an
// error, never a guess. (The core reads counts by the same rule in
// iacrypto.ParseHexCount; this module stands alone, so it states the rule
// itself.)
func SequenceNumber(ev map[string]interface{}) (int, error) {
	switch v := ev["s"].(type) {
	case string:
		n, err := strconv.ParseUint(v, 16, 31)
		if err != nil || strconv.FormatUint(n, 16) != v {
			return -1, fmt.Errorf("invalid sequence number %q", v)
		}
		return int(n), nil
	case nil:
		return -1, fmt.Errorf("the event carries no sequence number")
	default:
		return -1, fmt.Errorf("a sequence number of type %T", v)
	}
}

// CurrentSeq returns the highest sequence number in a key log, or -1 for an
// empty one.
func CurrentSeq(events []map[string]interface{}) (int, error) {
	max := -1
	for i, ev := range events {
		s, err := SequenceNumber(ev)
		if err != nil {
			return -1, fmt.Errorf("event %d: %w", i, err)
		}
		if s > max {
			max = s
		}
	}
	return max, nil
}

// KelDigestAtSeq is the digest of a key log through sequence number seq,
// inclusive: Blake3-256, CESR qb64 (code E), over the events ordered by
// sequence number and serialised as a compact JSON array, each event with its
// fields in sorted order.
//
// This is the value a watcher publishes for an identity at a position and a
// verifier compares with its own. Both must compute it here.
func KelDigestAtSeq(events []map[string]interface{}, seq int) (string, error) {
	type numbered struct {
		sn int
		ev map[string]interface{}
	}
	upTo := make([]numbered, 0, len(events))
	for i, ev := range events {
		sn, err := SequenceNumber(ev)
		if err != nil {
			return "", fmt.Errorf("event %d: %w", i, err)
		}
		if sn <= seq {
			upTo = append(upTo, numbered{sn, ev})
		}
	}
	if len(upTo) == 0 {
		return "", fmt.Errorf("no key events at or before sequence number %d", seq)
	}
	sort.SliceStable(upTo, func(i, j int) bool { return upTo[i].sn < upTo[j].sn })

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, n := range upTo {
		if i > 0 {
			buf.WriteByte(',')
		}
		b, err := json.Marshal(n.ev)
		if err != nil {
			return "", fmt.Errorf("serialise event %d: %w", i, err)
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return keri.Blake3SAID(buf.Bytes())
}
