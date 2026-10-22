package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// These reach the Identity Agent's own rules for relayed requests directly,
// as a relay that applies none of its own would deliver them: ADR-048 does
// not trust a relay to.

func servingManager(handler http.Handler) *Manager {
	m := NewManager(Config{Mode: relayproto.ModePublic, Handler: handler})
	m.markActive([]Allocation{{Label: "acme", URL: "https://acme.relay.test", Mode: relayproto.ModePublic, Kind: KindName}})
	return m
}

func relayed(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(relayproto.ContextWithPreamble(r.Context(),
		relayproto.Preamble{Allocation: "acme", Mode: relayproto.ModePublic, Host: "acme.relay.test"}))
}

func TestAPageLoadIsRefusedByTheIdentityAgentItself(t *testing.T) {
	var reached bool
	m := servingManager(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	r := relayed("GET", "/oobi/x")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	m.serve(w, r)
	if reached || w.Code == http.StatusOK {
		t.Fatalf("a page load reached the handler (status %d)", w.Code)
	}
}

func TestTheIdentityAgentNeverAnswersARelayWithAPage(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"html": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<form>password</form>")
		},
		"untyped page": func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "<!doctype html><form>password</form>")
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.test/", http.StatusFound)
		},
	} {
		w := httptest.NewRecorder()
		servingManager(handler).serve(w, relayed("GET", "/oobi/x"))
		if w.Code < 500 || strings.Contains(w.Body.String(), "<") || w.Header().Get("Location") != "" {
			t.Errorf("%s: status %d, location %q, body %q", name, w.Code, w.Header().Get("Location"), w.Body.String())
		}
	}
}

func TestTheIdentityAgentSendsARelayOnlyTheProtocolsHeaders(t *testing.T) {
	m := servingManager(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "public, max-age=31536000")
		h.Set("WWW-Authenticate", `Basic realm="sign in"`)
		h.Set("X-Keri-Keystate-Seq", "2")
		io.WriteString(w, `{"ok":true}`)
	}))
	w := httptest.NewRecorder()
	m.serve(w, relayed("GET", "/x/did.json"))
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":true}` {
		t.Fatalf("a protocol answer was not passed: %d %q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	if v := w.Header().Get("WWW-Authenticate"); v != "" {
		t.Errorf("WWW-Authenticate passed: %q", v)
	}
	if w.Header().Get("X-Keri-Keystate-Seq") != "2" {
		t.Error("the protocol's key-state header was dropped")
	}
}
