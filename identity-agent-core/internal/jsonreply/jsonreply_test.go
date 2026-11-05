package jsonreply

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The bytes every JSON route answers with are pinned here: status, header,
// HTML escaping on, and one trailing newline.
func TestWritePinsStatusHeaderAndEncoding(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusCreated, map[string]string{"k": "<a&b>"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want exactly application/json", got)
	}
	want := "{\"k\":\"" + `\` + "u003ca" + `\` + "u0026b" + `\` + "u003e\"}\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestWriteNilIsNullWithNewline(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusOK, nil)
	if rec.Body.String() != "null\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
