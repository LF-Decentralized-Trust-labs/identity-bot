package conversationbundle

import (
	"os"
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

// A file that two parsers read as two bundles is refused. Go keeps the last of a
// key written twice and folds a key's case, where another language's parser
// keeps the first or sees an unknown key, so a checker written there could be
// shown one "head" and this one another. Nothing the entries prove changes, so
// nothing else would notice.
func TestAFileTwoParsersWouldReadDifferentlyIsRefused(t *testing.T) {
	raw, err := os.ReadFile(headVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(raw); err != nil {
		t.Fatalf("the published head-bearing vector is refused: %v", err)
	}
	text := string(raw)
	for _, c := range []struct {
		name, from, to, says string
	}{
		{"the head written twice", "\n  \"head\": {", "\n  \"head\": {\"mode\": \"signed\"},\n  \"head\": {", "more than once"},
		{"the format written twice", "\n  \"format\":", "\n  \"format\": \"x\",\n  \"format\":", "more than once"},
		{"the head in another case", "\n  \"head\": {", "\n  \"Head\": {", "spelled"},
		{"the root in capitals", "\n  \"root\":", "\n  \"ROOT\":", "spelled"},
		{"the head spelled two ways", "\n  \"head\": {", "\n  \"Head\": {},\n  \"head\": {", "one field spelled twice"},
		{"a signature written twice in an entry's envelope", "\"ed_sig\":", "\"ed_sig\": \"x\", \"ed_sig\":", "more than once"},
		{"an envelope key in another case inside an entry", "\"plaintext\":", "\"Plaintext\":", "spelled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(text, c.from) {
				t.Fatalf("the vector has no %q to change", c.from)
			}
			_, err := Read([]byte(strings.Replace(text, c.from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("read as %v, want a refusal saying %q", err, c.says)
			}
		})
	}
}

// A file of nested brackets is refused quickly, before anything is checked: the
// token reader that finds a repeated key has no depth limit of its own.
func TestADeeplyNestedFileIsRefused(t *testing.T) {
	for _, depth := range []int{maxNesting + 2, 3_000_000} {
		deep := `{"format": ` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`
		if _, err := Read([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nests deeper") {
			t.Fatalf("a file nested %d deep was read as %v", depth, err)
		}
	}
}

// The published head-bearing vector: a genuine export of a conversation whose
// export carries the Identity Agent's signed head statement.
const headVectorFile = "../contracts/conversation-bundle/genuine-bundle-with-head.json"
