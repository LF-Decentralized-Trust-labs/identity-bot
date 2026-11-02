package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No Identity Agent app is reached through a browser: the apps are installed
// desktop and phone apps. The core serves no directory of files as a UI,
// whatever the environment says, and answers "/" with nothing.

func TestTheCoreServesNoUIDirectoryWhateverTheEnvironmentSays(t *testing.T) {
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "index.html"),
		[]byte(`<!doctype html><html><head><base href="/"></head><body>app</body></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLUTTER_WEB_DIR", web)
	t.Setenv("WEB_BASE_HREF", "/app")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "no_ui_directory_is_served_test.go")); err != nil {
		t.Fatalf("the file this test guards is not in the working directory: %v", err)
	}

	r := agentWithNoIdentity(t).buildRouter()

	for _, path := range []string{"/", "/index.html", "/some/client/route", "/no_ui_directory_is_served_test.go"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		body := w.Body.String()
		if w.Code != 404 || strings.Contains(body, "<html") || strings.Contains(body, "package server") {
			t.Errorf("GET %s answered %d %.100q; the core must serve no UI", path, w.Code, body)
		}
	}
}

// A request that arrives through a relay for "/" or any non-/api path gets no
// page either, with the UI directory configured in the environment.
func TestNoPageIsServedForARelayedRequestToTheRootOrAClientRoute(t *testing.T) {
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "index.html"),
		[]byte(`<!doctype html><html><head><base href="/"></head><body>app</body></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLUTTER_WEB_DIR", web)

	r := agentWithNoIdentity(t).buildRouter()

	for _, path := range []string{"/", "/index.html", "/some/client/route"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, relayedRequest("GET", path))
		body := w.Body.String()
		if w.Code == http.StatusOK || strings.Contains(body, "<html") || strings.Contains(w.Header().Get("Content-Type"), "html") {
			t.Errorf("a relayed GET %s answered %d %.100q; a relayed request must get no page", path, w.Code, body)
		}
	}
}
