package witnessproto

import (
	"fmt"
	"strconv"
	"strings"
)

// DigestStatementTag opens every signed digest statement. It keeps a signature
// over a digest answer from being a valid signature over anything else a
// watcher key signs (a receipt over an event SAID, for one).
const DigestStatementTag = "kel-digest-response/v1"

// DigestStatement is the exact text a watcher signs when it answers
// GET /public/kel-digest, and the exact text a verifier checks the signature
// against. Both sides build it from the fields of the answer, so neither has to
// reproduce the other's JSON encoding:
//
//	kel-digest-response/v1
//	aid=<aid>
//	seq=<decimal>
//	digest=<digest, or - when the watcher has not seen that event>
//	first_seen_at=<RFC 3339 UTC, or ->
//	observed_since=<RFC 3339 UTC, or ->
//	rival_at_or_below=true      (this line only when it is true)
//
// The last line says the watcher holds a validly signed event that conflicts
// with the one it holds at that place or below it, which a digest of its own
// branch cannot show; a client that sees it asks for the watcher's log. It is
// written only when true, so an answer without a rival is the same text it has
// always been, and an answer that has one cannot be altered into one that does
// not, or the other way, without breaking the signature.
//
// Each line ends with a line feed, the last included. A field that is absent is
// written as "-" and is never empty; a field holding a line break, a control
// character or a lone "-" is refused, because any of them would let two
// different answers share one statement.
func DigestStatement(aid string, seq int, digest, firstSeenAt, observedSince *string) (string, error) {
	return DigestStatementWithRival(aid, seq, digest, firstSeenAt, observedSince, false)
}

// DigestStatementWithRival is DigestStatement for an answer that also says
// whether the watcher holds a rival event at or below the place asked about.
func DigestStatementWithRival(aid string, seq int, digest, firstSeenAt, observedSince *string, rival bool) (string, error) {
	if seq < 0 {
		return "", fmt.Errorf("a sequence number is not negative")
	}
	var b strings.Builder
	b.WriteString(DigestStatementTag + "\n")
	fields := []struct {
		name string
		v    string
		opt  bool
		set  bool
	}{
		{"aid", aid, false, true},
		{"seq", strconv.Itoa(seq), false, true},
		{"digest", deref(digest), true, digest != nil},
		{"first_seen_at", deref(firstSeenAt), true, firstSeenAt != nil},
		{"observed_since", deref(observedSince), true, observedSince != nil},
	}
	for _, f := range fields {
		v := f.v
		if f.opt && !f.set {
			v = "-"
		} else if v == "" || v == "-" {
			return "", fmt.Errorf("%s is %q, which cannot be signed", f.name, v)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("%s holds a control character, which cannot be signed", f.name)
			}
		}
		b.WriteString(f.name + "=" + v + "\n")
	}
	if rival {
		b.WriteString("rival_at_or_below=true\n")
	}
	return b.String(), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
