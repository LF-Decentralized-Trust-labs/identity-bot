package server

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeFiles is every file the asset store keeps, as it is on disk now; a
// missing one is nil.
func storeFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range []string{"assets.json", "asset_invites.json", "asset_members.json",
		"asset_requests.json", "employee_invites.json", "employees.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out[n] = b
	}
	return out
}

// A server started over a store file it cannot read says so in its log, and
// every asset route answers with an error naming the file: not a 404, not an
// empty list. Nothing is deleted, revoked or written, so fixing the file
// brings everything back.
func TestAServerOverAnUnreadableAssetStoreSaysSoAndChangesNothing(t *testing.T) {
	for _, file := range []string{"assets.json", "employees.json"} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			// An asset, an invite and an enrolment exist on disk; one file is damaged.
			good := map[string]string{
				"assets.json":           `{"a1":{"id":"a1","name":"Door"}}`,
				"asset_invites.json":    `{"tok":{"token":"tok","asset_id":"a1"}}`,
				"employees.json":        `{}`,
				"employee_invites.json": `{}`,
			}
			good[file] = `{"a1": {"id": ` // cut off
			for n, c := range good {
				if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := storeFiles(t, dir)

			var logged bytes.Buffer
			log.SetOutput(io.MultiWriter(&logged, os.Stderr))
			defer log.SetOutput(os.Stderr)

			cfg := DefaultConfig()
			cfg.DataDir = dir
			cfg.LocalOwnerSecret = testOwnerSecret
			s, err := New(cfg)
			if err != nil {
				t.Fatalf("the server did not start: %v", err)
			}
			defer s.Stop()

			startup := logged.String()
			if !strings.Contains(startup, "ERROR") || !strings.Contains(startup, filepath.Join(dir, file)) ||
				!strings.Contains(startup, "assets are unavailable until this is fixed") {
				t.Fatalf("the startup log does not say, at error level, that %s could not be read and assets are unavailable:\n%s", file, startup)
			}

			srv := httptest.NewServer(s.buildRouter())
			defer srv.Close()
			for _, c := range []struct{ method, path string }{
				{"GET", "/api/assets"},
				{"GET", "/api/assets/a1"},
				{"POST", "/api/assets"},
				{"PUT", "/api/assets/a1/policy"},
				{"GET", "/api/assets/a1/members"},
				{"DELETE", "/api/assets/a1/members/EAID"},
				{"DELETE", "/api/assets/a1/invites/tok"},
				{"POST", "/api/assets/a1/requests/r1/approve"},
				{"GET", "/api/invites/tok"},
				{"POST", "/api/invites/tok/redeem"},
				{"GET", "/api/enrolments"},
				{"POST", "/api/enrolments"},
				{"DELETE", "/api/enrolments/tok"},
				{"POST", "/api/enrol"},
				{"POST", "/api/notify"},
			} {
				req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(`{}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusServiceUnavailable ||
					!strings.Contains(string(body), file) || !strings.Contains(string(body), "unavailable") {
					t.Errorf("%s %s: %d %s — want 503 naming %s", c.method, c.path, resp.StatusCode, body, file)
				}
			}

			after := storeFiles(t, dir)
			for n, b := range before {
				if !bytes.Equal(b, after[n]) || (b == nil) != (after[n] == nil) {
					t.Errorf("%s changed: was %q, now %q", n, b, after[n])
				}
			}
		})
	}
}
