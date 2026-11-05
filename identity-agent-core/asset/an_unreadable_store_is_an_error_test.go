package asset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func listAssets(t *testing.T, h *Handler) []Asset {
	t.Helper()
	out, err := h.Store.ListAssets()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A store file that is not there is an agent that holds nothing yet.
func TestAMissingAssetFileIsAnEmptyStore(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("a missing file is empty, not an error: %v", err)
	}
	if got, err := s.ListAssets(); err != nil || len(got) != 0 {
		t.Fatalf("want empty and no error, got %v, %v", got, err)
	}
	if _, found, err := s.GetAsset("x"); found || err != nil {
		t.Fatalf("want not found and no error, got %v, %v", found, err)
	}
}

func TestACorruptAssetFileIsAnErrorNotAnEmptyStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assets.json")
	corrupt := []byte(`{"a1": {"id": "a1"`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(dir)
	if err == nil || !strings.Contains(err.Error(), "assets.json") {
		t.Fatalf("want an error naming assets.json, got %v", err)
	}
	if s == nil {
		t.Fatal("the store must still be returned so its reads can report the error")
	}
	// The case that failed before: not found would read as "gone".
	if _, found, gerr := s.GetAsset("a1"); gerr == nil || found {
		t.Fatalf("GetAsset on a corrupt store must return the error, got found=%v err=%v", found, gerr)
	}
	if _, lerr := s.ListAssets(); lerr == nil {
		t.Fatal("ListAssets on a corrupt store must return the error")
	}
	if _, herr := s.HasAssetOfType("app"); herr == nil {
		t.Fatal("HasAssetOfType on a corrupt store must return the error")
	}
	if uerr := s.UpsertAsset(Asset{ID: "a2"}); uerr == nil {
		t.Fatal("a write must not replace a file that could not be read")
	}
	if derr := s.DeleteAsset("a1"); derr == nil {
		t.Fatal("a delete must not replace a file that could not be read")
	}
	if got, _ := os.ReadFile(path); string(got) != string(corrupt) {
		t.Fatalf("the corrupt file was rewritten: %q", got)
	}
}

func TestAnUnreadableAssetFileIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "assets.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	s, err := NewStore(dir)
	if err == nil {
		t.Fatal("an unreadable file must be an error")
	}
	if _, found, gerr := s.GetAsset("a1"); gerr == nil || found {
		t.Fatalf("want the read error, got found=%v err=%v", found, gerr)
	}
}

// Every other store file is held to the same rule.
func TestACorruptSiblingFileIsAnError(t *testing.T) {
	for _, name := range []string{"asset_invites.json", "asset_members.json", "asset_requests.json", "employee_invites.json", "employees.json"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(dir); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: want an error naming it, got %v", name, err)
		}
	}
}

// A handler is not built over a store that could not be read.
func TestNoHandlerOverACorruptStore(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "assets.json"), []byte("{"), 0o600)
	if h, err := NewHandler(dir, nil); err == nil || h != nil {
		t.Fatalf("want no handler and an error, got %v, %v", h, err)
	}
}
