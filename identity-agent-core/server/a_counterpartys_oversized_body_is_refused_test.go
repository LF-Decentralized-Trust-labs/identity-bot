package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

// oversized is a JSON document larger than any limit the core reads under, whose
// first part is valid, so a reader that cut it at the limit would still parse it.
func oversized() []byte {
	return []byte(`{"v":"ASK1","t":1,"aid":"E1","alias":"` + strings.Repeat("a", int(boundedread.Document)+10) + `"}`)
}

func servesOversized(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(oversized()) }))
	t.Cleanup(srv.Close)
	return srv
}

// A scanned Ask larger than the limit is refused, not truncated and parsed.
func TestAnOversizedAskIsRefused(t *testing.T) {
	srv := servesOversized(t)
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	if _, err := s.buildAskContext(srv.URL + "/i/tok"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("an oversized Ask was accepted: %v", err)
	}
	rec := scanDecode(t, oversized())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("decode of an oversized Ask: %d", rec.Code)
	}
}

// The scan decode and execute request bodies are bounded.
func TestAnOversizedScanRequestIsRefused(t *testing.T) {
	body := `{"url":"http://x/i/t","pad":"` + strings.Repeat("a", int(boundedread.Request)+10) + `"}`
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	for name, h := range map[string]http.HandlerFunc{"decode": s.handleScanDecode, "execute": s.handleScanExecute} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/scan/"+name, strings.NewReader(body)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", name, rec.Code)
		}
	}
}

// An OOBI answer larger than the limit is refused on every route that fetches one.
func TestAnOversizedOOBIAnswerIsRefused(t *testing.T) {
	srv := servesOversized(t)
	s := serverWithIdentity(t, "EUS")
	if _, _, err := s.EnsureKeriContact(srv.URL + "/oobi/E1"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("EnsureKeriContact accepted an oversized answer: %v", err)
	}
	post := func(h http.HandlerFunc, payload any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(b))))
		return rec
	}
	for name, h := range map[string]http.HandlerFunc{"contacts/resolve": s.handleResolveOobiContact, "contacts/add": s.handleAddContact} {
		rec := post(h, map[string]string{"oobi_url": srv.URL + "/oobi/E1"})
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "size limit") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// A credential schema larger than the limit is refused.
func TestAnOversizedSchemaIsRefused(t *testing.T) {
	srv := servesOversized(t)
	s := serverWithIdentity(t, "EUS")
	b, _ := json.Marshal(map[string]string{"url": srv.URL + "/schema"})
	rec := httptest.NewRecorder()
	s.handleFetchCredentialSchema(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(b))))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "size limit") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
