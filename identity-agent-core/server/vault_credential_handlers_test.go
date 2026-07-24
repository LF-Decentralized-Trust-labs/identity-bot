package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/sandbox"
)

func vaultTestServer(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: dir})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	mgr.SetVaultKeyProvider(func() ([]byte, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	})
	return &CoreServer{DataDir: dir, SandboxManager: mgr}
}

func postCredential(s *CoreServer, body map[string]any, remote bool) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/vault/credentials", bytes.NewReader(b))
	req.RemoteAddr = "127.0.0.1:9999"
	if remote {
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
	}
	w := httptest.NewRecorder()
	s.handleSetVaultCredential(w, req)
	return w
}

// A credential stored with explicit match domains lands in the ENCRYPTED vault
// and injects for its domains — the Cloudflare shape the LLM endpoint can't do.
func TestSetVaultCredentialWithDomains(t *testing.T) {
	s := vaultTestServer(t)
	w := postCredential(s, map[string]any{
		"service":       "cloudflare",
		"api_key":       "cf-token-xyz",
		"match_domains": []string{"api.cloudflare.com"},
	}, false)
	if w.Code != http.StatusOK {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}

	if got := s.SandboxManager.GetLLMAPIKey("cloudflare"); got != "cf-token-xyz" {
		t.Fatalf("stored key mismatch: %q", got)
	}
	// Encrypted at rest: the token must not appear on disk, and no plaintext
	// credentials file may exist.
	enc, err := os.ReadFile(filepath.Join(s.DataDir, "service_credentials.enc"))
	if err != nil {
		t.Fatalf("encrypted vault missing: %v", err)
	}
	if bytes.Contains(enc, []byte("cf-token-xyz")) {
		t.Fatal("token stored in plaintext")
	}

	// List names only, never keys.
	req := httptest.NewRequest(http.MethodGet, "/api/vault/credentials", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	lw := httptest.NewRecorder()
	s.handleListVaultCredentials(lw, req)
	if !strings.Contains(lw.Body.String(), "cloudflare") || strings.Contains(lw.Body.String(), "cf-token") {
		t.Fatalf("list must name services without keys: %s", lw.Body)
	}
}

func TestSetVaultCredentialValidation(t *testing.T) {
	s := vaultTestServer(t)
	if w := postCredential(s, map[string]any{"service": "x", "api_key": "k"}, false); w.Code != http.StatusBadRequest {
		t.Fatalf("missing match_domains must be rejected: %d", w.Code)
	}
	if w := postCredential(s, map[string]any{"service": "x", "match_domains": []string{"a.b"}}, false); w.Code != http.StatusBadRequest {
		t.Fatalf("missing key/headers must be rejected: %d", w.Code)
	}
	if w := postCredential(s, map[string]any{
		"service": "x", "match_domains": []string{"a.b"},
		"headers": map[string]string{"X-Auth-Email": "e", "X-Auth-Key": "k"},
	}, false); w.Code != http.StatusOK {
		t.Fatalf("full headers form must be accepted: %d %s", w.Code, w.Body)
	}
}

func TestVaultCredentialRemoteDenied(t *testing.T) {
	s := vaultTestServer(t)
	if w := postCredential(s, map[string]any{
		"service": "cloudflare", "api_key": "k", "match_domains": []string{"api.cloudflare.com"},
	}, true); w.Code != http.StatusForbidden {
		t.Fatalf("forwarded request must be denied: %d", w.Code)
	}
}
