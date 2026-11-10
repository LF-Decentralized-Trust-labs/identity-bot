package boundedread

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// A stream of exactly the limit is read whole; one byte more is refused, and
// refused again on every read after, never read as though it had ended there.
func TestAStreamOverTheLimitIsRefusedNotCut(t *testing.T) {
	if b, err := io.ReadAll(Reader(strings.NewReader("12345678"), 8)); err != nil || string(b) != "12345678" {
		t.Fatalf("a stream of exactly the limit: %q, %v", b, err)
	}
	r := Reader(strings.NewReader("123456789"), 8)
	if _, err := io.ReadAll(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a stream over the limit: %v", err)
	}
	if _, err := r.Read(make([]byte, 4)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a read after the refusal: %v", err)
	}
}

// A document cut at the limit that still parses is the case io.LimitReader
// gets wrong: 12345678 cut at four bytes is the number 1234.
func TestADocumentThatParsesWhenCutIsStillRefused(t *testing.T) {
	var n int
	err := json.NewDecoder(Reader(strings.NewReader("12345678"), 4)).Decode(&n)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a number cut by the limit decoded as %d, error %v", n, err)
	}
	if err := json.NewDecoder(io.LimitReader(strings.NewReader("12345678"), 4)).Decode(&n); err != nil || n != 1234 {
		t.Fatalf("the premise: io.LimitReader reads it as %d, %v", n, err)
	}
}
