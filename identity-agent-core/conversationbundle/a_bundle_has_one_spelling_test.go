package conversationbundle

import (
	"strings"
	"testing"
)

// Respelling something a bundle carries, without changing a byte it decodes
// to, still changes the bundle, and is refused. The standard base64 decoder
// skips line breaks even in strict mode, and a log row's record can be
// respaced and still read as the same event; either left the bundle's text
// open to change with nothing it proves changing.
func TestARespelledBundleFails(t *testing.T) {
	_, b := theVector(t)
	for _, c := range []struct {
		name   string
		change func(b *Bundle)
	}{
		{"a line break inside a message's words", func(b *Bundle) {
			b.Entries[0].Body = b.Entries[0].Body[:8] + "\n" + b.Entries[0].Body[8:]
		}},
		// A guard, not a fix: canonicalURL already refused this before the
		// change, and this keeps it so.
		{"a line break inside a countersignature (guard)", func(b *Bundle) {
			b.Entries[1].Envelope.EdSig = b.Entries[1].Envelope.EdSig[:8] + "\r\n" + b.Entries[1].Envelope.EdSig[8:]
		}},
		{"a log row respaced", func(b *Bundle) {
			last := len(b.Log.Rows) - 1
			b.Log.Rows[last].Record = strings.Replace(b.Log.Rows[last].Record, `":`, `": `, 1)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := copyOf(t, b)
			c.change(changed)
			if r := Verify(changed); r.Verified {
				t.Fatalf("%s, and the bundle still verifies", c.name)
			}
		})
	}
}
