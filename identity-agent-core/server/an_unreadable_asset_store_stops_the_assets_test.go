package server

import (
	"bytes"
	"errors"
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
		"asset_requests.json", "employee_invites.json", "employees.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out[n] = b
	}
	return out
}

// A server over a store file it cannot read does not start: the unreadable
// file might hold invite codes in the clear, and migrating them to digests
// cannot be done (or ruled out) without reading it. The error names the file,
// and nothing is deleted, revoked or written, so fixing the file and starting
// again brings everything back.
func TestAServerOverAnUnreadableAssetStoreDoesNotStartAndChangesNothing(t *testing.T) {
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

			cfg := DefaultConfig()
			cfg.DataDir = dir
			cfg.LocalOwnerSecret = testOwnerSecret
			s, err := New(cfg)
			if err == nil {
				s.Stop()
				t.Fatal("the server started over an asset store it could not read")
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
