package boundedread

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllRefusesABodyOverTheLimitAndNeverTruncates(t *testing.T) {
	if b, err := All(strings.NewReader("12345"), 5); err != nil || string(b) != "12345" {
		t.Fatalf("a body exactly at the limit: %q, %v", b, err)
	}
	b, err := All(strings.NewReader("123456"), 5)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one byte over was not refused: %v", err)
	}
	if b != nil {
		t.Fatalf("an oversized body returned %d bytes as if they were the document", len(b))
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestAllReportsAReadError(t *testing.T) {
	if _, err := All(failing{}, 10); err == nil || errors.Is(err, ErrTooLarge) {
		t.Fatalf("a read error was lost or misreported: %v", err)
	}
}

func TestReaderStopsADecoderPastTheLimit(t *testing.T) {
	big := `{"alias":"` + strings.Repeat("a", 100) + `"}`
	var v map[string]string
	if err := json.NewDecoder(Reader(strings.NewReader(big), 50)).Decode(&v); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decoder read past the limit: %v", err)
	}
	if err := json.NewDecoder(Reader(strings.NewReader(big), int64(len(big)))).Decode(&v); err != nil {
		t.Fatalf("a body at the limit was refused: %v", err)
	}
}

func TestSnippetIsBounded(t *testing.T) {
	if got := Snippet(strings.NewReader(strings.Repeat("x", 10000))); int64(len(got)) != Diagnostic {
		t.Fatalf("snippet length %d", len(got))
	}
}

func TestRequestBodyOverTheLimitIsAnswered413(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
	LimitRequest(rec, r, 10)
	_, err := io.ReadAll(r.Body)
	if err == nil || Status(err) != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d for %v", Status(err), err)
	}
	if Status(errors.New("bad json")) != http.StatusBadRequest {
		t.Fatal("an ordinary error was not a 400")
	}
}
