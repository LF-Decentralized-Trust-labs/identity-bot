package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/linkverifier"
)

func TestHandleVerificationBadgeLocalhostOnly(t *testing.T) {
	s := &CoreServer{
		LinkVerifier: linkverifier.New(nil, linkverifier.Config{}),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/verification/badge?url=https://example.com", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	s.handleVerificationBadge(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
}

func TestHandleVerificationBadgeLoopback(t *testing.T) {
	s := &CoreServer{
		LinkVerifier: linkverifier.New(nil, linkverifier.Config{}),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/verification/badge?url=https://example.invalid&flow=badge", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.handleVerificationBadge(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var result linkverifier.VerificationResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != linkverifier.OutcomeUnverified {
		t.Fatalf("outcome=%s", result.Outcome)
	}
}