package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/store"
)

// The Identity Agent's own handlers answer a relayed request without a page,
// even from a relay that applies none of its own rules. These reach the
// router directly with a relay's preamble, so no relay answers first.

func relayedRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(relayproto.ContextWithPreamble(r.Context(),
		relayproto.Preamble{Allocation: "acme", Mode: relayproto.ModePublic, Host: "acme.relay.test"}))
}

func TestTheWebAppIsNotServedThroughARelay(t *testing.T) {
	s := agentWithNoIdentity(t)
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "index.html"),
		[]byte(`<!doctype html><html><head><base href="/"></head><body>app</body></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := s.buildRouter(web)

	direct := httptest.NewRecorder()
	r.ServeHTTP(direct, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(direct.Body.String(), "<html") {
		t.Fatalf("the page this test guards is not served directly any more: %d %.100q", direct.Code, direct.Body.String())
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, relayedRequest("GET", "/"))
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("the web app answered a relayed request: %d %.100q", w.Code, w.Body.String())
	}
}

func TestACredentialIsNotShownAsAPageThroughARelay(t *testing.T) {
	s := agentWithNoIdentity(t)
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID: "ECredentialShown", Status: "issued", Format: "acdc", CredentialType: "Membership",
		HolderAID: "EHolder", IssuerAID: "EIssuer",
	}); err != nil {
		t.Fatal(err)
	}
	r := s.buildRouter("")
	ask := func(req *http.Request) *httptest.ResponseRecorder {
		req.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if direct := ask(httptest.NewRequest("GET", "/public/credential/ECredentialShown", nil)); !strings.Contains(direct.Header().Get("Content-Type"), "html") {
		t.Fatalf("the page this test guards is not served directly any more: %d %q", direct.Code, direct.Header().Get("Content-Type"))
	}
	w := ask(relayedRequest("GET", "/public/credential/ECredentialShown"))
	if strings.Contains(w.Header().Get("Content-Type"), "html") || strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("a credential was shown as a page through a relay: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}
