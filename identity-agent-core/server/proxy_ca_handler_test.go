package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCACertIsServedWithoutAuthentication(t *testing.T) {
	// Deliberately unauthenticated, and the reason is a chicken-and-egg: a
	// workspace needs this certificate before its first outbound request, holds
	// no credential yet, and the credential it will use is injected by the very
	// proxy it cannot reach until it trusts this. Requiring auth here would mean
	// nothing could ever bootstrap.
	//
	// Safe because it is a CA certificate — public by construction. The private
	// key is never served.
	s := &CoreServer{DataDir: t.TempDir()} // no sandbox wired
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/proxy/ca.crt", nil)
	r.RemoteAddr = "203.0.113.9:1234" // remote, unauthenticated

	s.handleProxyCACert(w, r)

	// Without a sandbox it cannot serve one — but it must fail on availability,
	// never on authorisation. A 403 here would be a bootstrap deadlock.
	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("the CA must not require authentication, got %d", w.Code)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when the sandbox is absent, got %d", w.Code)
	}
}

func TestCACertRouteEndsInCrt(t *testing.T) {
	// The usual install is to drop the file into a trust directory and run
	// update-ca-certificates, which SKIPS anything not named *.crt. A path or
	// filename without that suffix produces a guest that looks configured and
	// still rejects every TLS connection — a failure that presents as a broken
	// remote rather than a missing trust anchor.
	//
	// So the route registration itself is the thing under test.
	var got []string
	s := &CoreServer{DataDir: t.TempDir()}
	s.proxyCARoutes(routeRecorder{&got})

	if len(got) != 1 {
		t.Fatalf("expected one route, got %v", got)
	}
	if !strings.HasSuffix(got[0], ".crt") {
		t.Fatalf("route %q must end in .crt or trust stores will skip the file", got[0])
	}
}

// routeRecorder captures what proxyCARoutes registers.
type routeRecorder struct{ paths *[]string }

func (rr routeRecorder) Get(p string, _ http.HandlerFunc) { *rr.paths = append(*rr.paths, p) }
