package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const shellHTML = `<!DOCTYPE html><html><head><base href="/">` +
	`<script src="flutter_bootstrap.js" async></script></head><body></body></html>`

func writeShell(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A base href without a trailing slash is the classic version of this bug: the
// browser treats the last segment as a file and resolves siblings against its
// parent, so the page is blank again for a reason that looks nothing like the
// cause.
func TestAPrefixAlwaysEndsInASlash(t *testing.T) {
	for in, want := range map[string]string{
		"/grape-workforce":  "/grape-workforce/",
		"grape-workforce":   "/grape-workforce/",
		"/grape-workforce/": "/grape-workforce/",
		"":                  "/",
		"/":                 "/",
		"  /app  ":          "/app/",
	} {
		if got := normalisePrefix(in); got != want {
			t.Errorf("normalisePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// Whether a relay forwards the prefix or strips it is somebody else's
// configuration. An agent that only worked one way would fail with the same
// blank page and no clue which half was wrong.
func TestPathsResolveWhetherOrNotTheProxyStripped(t *testing.T) {
	const prefix = "/grape-workforce/"
	for in, want := range map[string]string{
		// Arrived still carrying the prefix.
		"/grape-workforce/main.dart.js": "/main.dart.js",
		"/grape-workforce/":             "/",
		"/grape-workforce":              "/",
		// Already stripped by the proxy.
		"/main.dart.js": "/main.dart.js",
		"/":             "/",
	} {
		if got := stripPrefix(in, prefix); got != want {
			t.Errorf("stripPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// At the root nothing should be touched.
func TestNothingIsStrippedAtTheRoot(t *testing.T) {
	for _, p := range []string{"/", "/main.dart.js", "/assets/thing.png"} {
		if got := stripPrefix(p, "/"); got != p {
			t.Errorf("stripPrefix(%q, \"/\") = %q, want it unchanged", p, got)
		}
	}
}

// The whole point: the shell must tell the browser where the app actually
// lives, or it loads and then fetches its code from the wrong place.
func TestTheShellIsRewrittenToTheServingPrefix(t *testing.T) {
	path := writeShell(t, shellHTML)
	w := httptest.NewRecorder()
	serveShell(w, path, "/grape-workforce/")

	body := w.Body.String()
	if !strings.Contains(body, `<base href="/grape-workforce/">`) {
		t.Fatalf("the base href was not rewritten:\n%s", body)
	}
	if strings.Contains(body, `<base href="/">`) {
		t.Error("the original root base href survived")
	}
}

// Serving at the root must not disturb a build that is already correct.
func TestTheShellIsUntouchedAtTheRoot(t *testing.T) {
	path := writeShell(t, shellHTML)
	w := httptest.NewRecorder()
	serveShell(w, path, "/")

	if w.Body.String() != shellHTML {
		t.Errorf("the shell was modified when serving at the root:\n%s", w.Body.String())
	}
}

// Only the <base> tag's href is rewritten. A stray href elsewhere in the
// document belongs to the page, not to us.
func TestOnlyTheBaseTagIsRewritten(t *testing.T) {
	html := `<html><head><base href="/"><link rel="icon" href="/favicon.png"></head></html>`
	path := writeShell(t, html)
	w := httptest.NewRecorder()
	serveShell(w, path, "/app/")

	body := w.Body.String()
	if !strings.Contains(body, `<base href="/app/">`) {
		t.Errorf("base not rewritten: %s", body)
	}
	if !strings.Contains(body, `href="/favicon.png"`) {
		t.Errorf("an unrelated href was rewritten: %s", body)
	}
}

// The proxy is the only party that reliably knows the prefix, so its header
// wins over a static setting somebody has to keep in step by hand.
func TestTheProxyHeaderWinsOverTheEnvironment(t *testing.T) {
	t.Setenv("WEB_BASE_HREF", "/from-env")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Prefix", "/from-proxy")
	if got := webPathPrefix(r); got != "/from-proxy/" {
		t.Errorf("expected the proxy's prefix, got %q", got)
	}

	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := webPathPrefix(plain); got != "/from-env/" {
		t.Errorf("expected the environment fallback, got %q", got)
	}
}

func TestNoPrefixAnywhereMeansTheRoot(t *testing.T) {
	t.Setenv("WEB_BASE_HREF", "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := webPathPrefix(r); got != "/" {
		t.Errorf("expected the root, got %q", got)
	}
}

// A shell with no base tag cannot be corrected, and serving it silently would
// produce a blank page with a clean log — the hardest version of this to
// diagnose.
func TestAShellWithNoBaseTagStillServes(t *testing.T) {
	path := writeShell(t, `<html><head></head><body></body></html>`)
	w := httptest.NewRecorder()
	serveShell(w, path, "/app/")

	if w.Code != http.StatusOK {
		t.Errorf("expected the page to still be served, got %d", w.Code)
	}
}

func TestAMissingShellIsNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	serveShell(w, filepath.Join(t.TempDir(), "absent.html"), "/")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for a missing shell, got %d", w.Code)
	}
}
