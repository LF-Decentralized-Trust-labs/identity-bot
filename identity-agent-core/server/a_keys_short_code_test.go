package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func askForAShortCode(s *CoreServer, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleAKeysShortCode(rec, httptest.NewRequest(http.MethodPost, "/api/machines/key-short-code", strings.NewReader(body)))
	return rec
}

// The vectors are ADR-045 Amendment 2's, the same two the authorisation package
// pins, so the route and the function cannot part.
func TestAKeysShortCodeIsTheCoresOwn(t *testing.T) {
	s := &CoreServer{}
	for key, want := range map[string]string{
		"DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB":     "M8PN-ME83-7RPK-D6FF",
		"DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx":     "CAJR-NJXE-0370-4RZR",
		"  DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB\n": "M8PN-ME83-7RPK-D6FF",
	} {
		b, _ := json.Marshal(map[string]string{"public_key": key})
		rec := askForAShortCode(s, string(b))
		var got aKeysShortCodeResponse
		json.NewDecoder(rec.Body).Decode(&got)
		if rec.Code != http.StatusOK || got.ShortCode != want {
			t.Errorf("%q: %d %q, want %q", key, rec.Code, got.ShortCode, want)
		}
	}
}

func TestNoKeyHasNoShortCode(t *testing.T) {
	s := &CoreServer{}
	for _, body := range []string{`{}`, `{"public_key":"  "}`, `not json`} {
		if rec := askForAShortCode(s, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s was answered %d", body, rec.Code)
		}
	}
}
