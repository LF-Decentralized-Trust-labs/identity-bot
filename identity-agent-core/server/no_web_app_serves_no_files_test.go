package server

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The core ships no web app of its own. With none configured it answers "/"
// with a placeholder, and serves no file from wherever it happens to be run:
// the absolute form of an empty directory name is the working directory, which
// exists, so a check that only asks whether the directory exists would publish
// the files beside the binary.

func TestNoWebAppConfiguredServesNoFiles(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// This test's own source is in the working directory; it must not be served.
	if _, err := os.Stat(cwd + "/no_web_app_serves_no_files_test.go"); err != nil {
		t.Fatalf("the file this test guards is not in the working directory: %v", err)
	}

	r := agentWithNoIdentity(t).buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/no_web_app_serves_no_files_test.go", nil))
	if strings.Contains(w.Body.String(), "package server") {
		t.Fatalf("a file from the working directory was served with no web app configured")
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), "No web app is configured") {
		t.Fatalf("with no web app configured, / did not answer with the placeholder: %d %.120q", w.Code, w.Body.String())
	}
}
