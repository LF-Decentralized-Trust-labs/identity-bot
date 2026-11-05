package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/asset"
)

// storeFiles is every file the asset store keeps, as it is on disk now; a
// missing one is nil.
func storeFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range []string{"assets.json", "asset_invites.json", "asset_members.json",
		"asset_requests.json", "employee_invites.json", "employees.json", "asset_enrolments.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out[n] = b
	}
	return out
}

// damagedStore writes a store directory where file is cut off and the rest are
// fine, and returns it.
func damagedStore(t *testing.T, file string) string {
	t.Helper()
	dir := t.TempDir()
	good := map[string]string{
		"assets.json":           `{"a1":{"id":"a1","name":"Door"}}`,
		"asset_invites.json":    `{}`,
		"employees.json":        `{}`,
		"employee_invites.json": `{}`,
		"asset_members.json":    `[]`,
		"asset_requests.json":   `[]`,
		"asset_enrolments.json": `{}`,
	}
	good[file] = `{"a1": {"id": ` // cut off
	for n, c := range good {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newServerOver(dir string) (*CoreServer, error) {
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.LocalOwnerSecret = testOwnerSecret
	return New(cfg)
}

// A server over a file that can hold an invite or enrolment secret, which it
// cannot read, does not start: the file might hold codes in the clear, and
// migrating them to digests cannot be done (or ruled out) without reading it.
// The error names the file, and nothing is written.
func TestAServerOverAnUnreadableSecretFileDoesNotStartAndChangesNothing(t *testing.T) {
	for _, file := range []string{"asset_invites.json", "employee_invites.json", "asset_enrolments.json"} {
		t.Run(file, func(t *testing.T) {
			dir := damagedStore(t, file)
			before := storeFiles(t, dir)
			s, err := newServerOver(dir)
			if err == nil {
				s.Stop()
				t.Fatal("the server started over a secret file it could not read")
			}
			if !errors.Is(err, asset.ErrSecretsNotMigrated) || !strings.Contains(err.Error(), filepath.Join(dir, file)) {
				t.Fatalf("the error does not say the secrets were not migrated and name %s: %v", file, err)
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

// A file with no secrets in it does not stop the agent, the phone build
// included: the asset routes answer 503 naming the file, and nothing is written.
func TestAServerOverAnUnreadableFileWithNoSecretsStillStarts(t *testing.T) {
	for _, file := range []string{"assets.json", "employees.json", "asset_members.json", "asset_requests.json"} {
		t.Run(file, func(t *testing.T) {
			dir := damagedStore(t, file)
			before := storeFiles(t, dir)
			s, err := newServerOver(dir)
			if err != nil {
				t.Fatalf("the server refused to start over %s, which holds no secret: %v", file, err)
			}
			defer s.Stop()
			if s.assetHandler != nil || s.assetStoreErr == nil {
				t.Fatalf("an asset handler was made over an unreadable %s", file)
			}
			r := httptest.NewRecorder()
			s.assetsUnavailable()(r, httptest.NewRequest(http.MethodGet, "/assets", nil))
			if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body.String(), file) {
				t.Fatalf("assets answered %d %q, want 503 naming %s", r.Code, r.Body.String(), file)
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
