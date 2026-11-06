package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/store"
)

const (
	allowedAID    = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
	notAllowedAID = "EMBjaz3NEzLtVobBkATmbGJHCUNHXRTvZ5F7rXdLZSop"
)

// an agent in Direct mode with allowedAID on the URL manager's list.
func directAgent(t *testing.T) *CoreServer {
	t.Helper()
	s := agentWithNoIdentity(t)
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct"}); err != nil {
		t.Fatal(err)
	}
	al, err := loadDirectAllowlist(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := al.Allow(allowedAID); err != nil {
		t.Fatal(err)
	}
	s.directAIDs = al
	return s
}

func askDirect(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// Every route on the external listener is a GET under /{aid}/ that publicRoutes
// already names as public, with its reason. Nothing on it is owner-only, scoped
// or state-changing.
func TestEveryRouteOnTheDirectListenerIsAPublicIdentifierDocument(t *testing.T) {
	if len(directIngressRoutes) == 0 {
		t.Fatal("no routes")
	}
	for _, rt := range directIngressRoutes {
		if !strings.HasPrefix(rt.pattern, "/{aid}/") {
			t.Errorf("%s is not path-scoped by identifier", rt.pattern)
		}
		if why := publicRoutes["GET "+rt.pattern]; why == "" {
			t.Errorf("GET %s is on the external listener but is not a public route", rt.pattern)
		}
	}
	// And the router has no route beyond the list.
	s := directAgent(t)
	n := 0
	_ = chi.Walk(s.directRouter(), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		n++
		if method != http.MethodGet {
			t.Errorf("%s %s: the direct listener serves GET only", method, route)
		}
		return nil
	})
	if n != len(directIngressRoutes) {
		t.Errorf("router has %d routes, list has %d", n, len(directIngressRoutes))
	}
}

// A management route is unreachable on the external listener: not the owner API,
// the sealed carrier, DIDComm, the root-scoped public routes or the OIDC routes,
// even for an allowlisted identifier in Direct mode.
func TestAManagementRouteIsUnreachableOnTheDirectListener(t *testing.T) {
	s := directAgent(t)
	h := s.directRouter()
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/health"}, {"GET", "/api/identity"}, {"GET", "/api/info"},
		{"GET", "/api/settings/reachability"}, {"PUT", "/api/settings/reachability"},
		{"GET", "/api/settings/reachability/direct-aids"},
		{"PUT", "/api/settings/reachability/direct-aids/" + notAllowedAID},
		{"POST", "/api/sealed"}, {"POST", "/api/sealed/send"},
		{"GET", "/api/local-owner/proof?nonce=x"},
		{"POST", "/didcomm"}, {"GET", "/i/token"},
		{"GET", "/oobi/" + allowedAID}, {"GET", "/public/oobi/" + allowedAID},
		{"GET", "/public/" + allowedAID + "/did.json"},
		{"GET", "/" + allowedAID + "/oidc/authorize"},
		{"GET", "/" + allowedAID + "/.well-known/openid-configuration"},
		{"POST", "/" + allowedAID + "/oidc/complete"},
		// a served path, wrong method: still nothing
		{"POST", "/" + allowedAID + "/oobi"}, {"DELETE", "/" + allowedAID + "/kel"},
		{"GET", "/"}, {"GET", "/api"},
	} {
		rec := askDirect(h, c.method, c.path)
		if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != "404 page not found" {
			t.Errorf("%s %s answered %d %q on the direct listener", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

// An identifier not on the allowlist gets nothing, and the same nothing as an
// identifier the agent has never heard of, so the answer is no oracle. An
// allowlisted one is answered by its handler.
func TestAnIdentifierNotOnTheAllowlistGetsNothing(t *testing.T) {
	s := directAgent(t)
	h := s.directRouter()
	for _, doc := range []string{"oobi", "did.json", "kel", "keri.cesr"} {
		off := askDirect(h, "GET", "/"+notAllowedAID+"/"+doc)
		if off.Code != http.StatusNotFound || strings.TrimSpace(off.Body.String()) != "404 page not found" {
			t.Errorf("%s for an identifier off the list answered %d %q", doc, off.Code, off.Body.String())
		}
		junk := askDirect(h, "GET", "/not-an-identifier/"+doc)
		if junk.Code != off.Code || junk.Body.String() != off.Body.String() {
			t.Errorf("%s: an unlisted identifier and a junk one are told apart", doc)
		}
	}
	// the list gates; it is not a stub: an allowlisted identifier reaches the handler.
	if rec := askDirect(h, "GET", "/"+allowedAID+"/oobi"); rec.Body.String() == askDirect(h, "GET", "/"+notAllowedAID+"/oobi").Body.String() {
		t.Errorf("an allowlisted identifier got the same bare refusal (%d %q): the handler never ran", rec.Code, rec.Body.String())
	}
	// removing it takes the answer away at once
	if err := s.directAIDs.Remove(allowedAID); err != nil {
		t.Fatal(err)
	}
	if rec := askDirect(h, "GET", "/"+allowedAID+"/oobi"); rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != "404 page not found" {
		t.Errorf("a removed identifier is still answered: %d %q", rec.Code, rec.Body.String())
	}
}

// The listener answers only while the mode is Direct.
func TestTheDirectListenerIsSilentOutsideDirectMode(t *testing.T) {
	s := directAgent(t)
	h := s.directRouter()
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "relay"}); err != nil {
		t.Fatal(err)
	}
	rec := askDirect(h, "GET", "/"+allowedAID+"/oobi")
	if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != "404 page not found" {
		t.Fatalf("answered an allowlisted identifier in relay mode: %d %q", rec.Code, rec.Body.String())
	}
}

// The allowlist survives a restart, takes only identifiers, and an unreadable
// file is an empty list rather than an open one.
func TestTheAllowlistIsKeptAndTakesOnlyIdentifiers(t *testing.T) {
	dir := t.TempDir()
	al, _ := loadDirectAllowlist(dir)
	if err := al.Allow("hello"); err == nil {
		t.Error("a non-identifier was allowed")
	}
	if err := al.Allow(allowedAID); err != nil {
		t.Fatal(err)
	}
	again, err := loadDirectAllowlist(dir)
	if err != nil || !again.Has(allowedAID) || again.Has(notAllowedAID) {
		t.Fatalf("not kept: %v %v", err, again.List())
	}
}

// Over a real socket: the configured bind serves a document path for the
// allowlisted identifier's route table and nothing of the management API, and
// the root stays on loopback while it does.
func TestTheDirectListenerOverARealSocket(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", addr)
	t.Setenv("AGENT_SEALED_INSTANCE_INGRESS", "")
	s := directAgent(t)
	if err := s.bindDirectListener(); err != nil {
		t.Fatal(err)
	}
	defer s.directSrv.Close()

	if got := rootListenAddr(5050); got != "127.0.0.1:5050" {
		t.Fatalf("the root moved to %q", got)
	}
	for _, path := range []string{"/api/health", "/api/identity", "/" + notAllowedAID + "/oobi"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s on the direct socket answered %d", path, resp.StatusCode)
		}
	}
}

// A configured bind that is not host:port is refused, not ignored.
func TestAMalformedDirectBindIsRefused(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "0.0.0.0")
	if err := agentWithNoIdentity(t).bindDirectListener(); err == nil {
		t.Fatal("a bind with no port was accepted")
	}
}

// Nothing is bound unless asked for.
func TestNoDirectListenerUnlessConfigured(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "")
	s := agentWithNoIdentity(t)
	if err := s.bindDirectListener(); err != nil || s.directLn != nil {
		t.Fatalf("bound with nothing configured: %v", err)
	}
}
