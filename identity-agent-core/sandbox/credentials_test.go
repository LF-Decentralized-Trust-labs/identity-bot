package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestVault(t *testing.T, dir string) *CredentialVault {
	t.Helper()
	cv := NewCredentialVault(dir)
	cv.SetKeyProvider(testVaultKeyProvider)
	return cv
}

// Stored credentials must never appear in plaintext on disk, and a fresh vault
// instance with the same key must read them back.
func TestVaultEncryptsAtRest(t *testing.T) {
	dir := t.TempDir()
	cv := newTestVault(t, dir)

	secret := "cf-token-abc123"
	if err := cv.SetCredential("cloudflare", []string{"api.cloudflare.com"}, map[string]string{"Authorization": "Bearer " + secret}); err != nil {
		t.Fatalf("set: %v", err)
	}

	vaultPath := filepath.Join(dir, vaultFileName)
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("vault file missing: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("cloudflare")) {
		t.Fatal("vault file contains plaintext")
	}
	var env vaultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Version != 1 || env.Ciphertext == "" {
		t.Fatalf("vault file is not a v1 envelope: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.json")); !os.IsNotExist(err) {
		t.Fatal("vault must not write credentials.json")
	}

	reopened := newTestVault(t, dir)
	if got := reopened.GetAPIKey("cloudflare"); got != secret {
		t.Fatalf("reopened vault returned %q", got)
	}
}

// Without a key the vault refuses writes with a clear error and injects nothing
// from an encrypted store it cannot open.
func TestVaultLockedWithoutKey(t *testing.T) {
	dir := t.TempDir()
	sealed := newTestVault(t, dir)
	if err := sealed.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatalf("set: %v", err)
	}

	locked := NewCredentialVault(dir) // no key provider
	if err := locked.SetCredential("svc2", []string{"example.org"}, map[string]string{"Authorization": "Bearer y"}); err == nil {
		t.Fatal("locked vault must refuse writes")
	}
	if got := locked.GetAPIKey("svc"); got != "" {
		t.Fatal("locked vault must not expose stored credentials")
	}
	// The sealed store must survive the failed attempts untouched.
	reopened := newTestVault(t, dir)
	if got := reopened.GetAPIKey("svc"); got != "x" {
		t.Fatalf("sealed store damaged, got %q", got)
	}
}

// A wrong key fails closed: reads return nothing, writes error, and the
// original ciphertext is not clobbered.
func TestVaultWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	sealed := newTestVault(t, dir)
	if err := sealed.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, vaultFileName))

	wrong := NewCredentialVault(dir)
	wrong.SetKeyProvider(func() ([]byte, error) {
		return []byte("ffffffffffffffffffffffffffffffff"), nil
	})
	if got := wrong.GetAPIKey("svc"); got != "" {
		t.Fatal("wrong key must not decrypt")
	}
	if err := wrong.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer evil"}); err == nil {
		t.Fatal("wrong key must refuse writes")
	}
	after, _ := os.ReadFile(filepath.Join(dir, vaultFileName))
	if !bytes.Equal(before, after) {
		t.Fatal("ciphertext was clobbered")
	}
}

// A legacy plaintext credentials.json (vault-array form) migrates into the
// encrypted vault on first access and the plaintext file is removed.
func TestVaultMigratesLegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	legacy := []CredentialEntry{{
		Service:      "openrouter",
		MatchDomains: []string{"openrouter.ai"},
		Headers:      map[string]string{"Authorization": "Bearer legacy-key"},
	}}
	data, _ := json.Marshal(legacy)
	legacyPath := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(legacyPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	cv := newTestVault(t, dir)
	if got := cv.GetAPIKey("openrouter"); got != "legacy-key" {
		t.Fatalf("migrated key = %q", got)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatal("plaintext file must be removed after migration")
	}
	if _, err := os.Stat(filepath.Join(dir, vaultFileName)); err != nil {
		t.Fatalf("encrypted vault missing after migration: %v", err)
	}
}

// credentials.json holding the verifiable-credential (ACDC) store — a JSON
// object, not a vault array — must be ignored and never deleted or rewritten.
func TestVaultLeavesACDCStoreAlone(t *testing.T) {
	dir := t.TempDir()
	acdc := []byte(`{"ESAID123":{"said":"ESAID123","issuer":"EAID"}}`)
	acdcPath := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(acdcPath, acdc, 0600); err != nil {
		t.Fatal(err)
	}

	cv := newTestVault(t, dir)
	if err := cv.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	after, err := os.ReadFile(acdcPath)
	if err != nil {
		t.Fatalf("ACDC store was deleted: %v", err)
	}
	if !bytes.Equal(acdc, after) {
		t.Fatal("ACDC store was rewritten")
	}
}

// settings.json-derived keys still work read-only, and a vault entry for the
// same service takes precedence.
func TestVaultSettingsFallback(t *testing.T) {
	dir := t.TempDir()
	settings := map[string]string{"openrouter_api_key": "from-settings"}
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	cv := newTestVault(t, dir)
	if got := cv.GetAPIKey("openrouter"); got != "from-settings" {
		t.Fatalf("fallback key = %q", got)
	}
	if err := cv.SetCredential("openrouter", []string{"openrouter.ai"}, map[string]string{"Authorization": "Bearer from-vault"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := cv.GetAPIKey("openrouter"); got != "from-vault" {
		t.Fatalf("vault must win over settings fallback, got %q", got)
	}
}

// Injection works end-to-end from an encrypted store.
func TestVaultInjectsFromEncryptedStore(t *testing.T) {
	dir := t.TempDir()
	sealed := newTestVault(t, dir)
	if err := sealed.SetCredential("svc", []string{"api.example.com"}, map[string]string{"Authorization": "Bearer tok"}); err != nil {
		t.Fatalf("set: %v", err)
	}

	cv := newTestVault(t, dir)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/x", nil)
	if !cv.InjectCredentials(req) {
		t.Fatal("expected injection")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("injected header = %q", got)
	}
}

// RemoveCredential persists the removal to the encrypted store.
func TestVaultRemovePersists(t *testing.T) {
	dir := t.TempDir()
	cv := newTestVault(t, dir)
	if err := cv.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := cv.RemoveCredential("svc"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	reopened := newTestVault(t, dir)
	if got := reopened.GetAPIKey("svc"); got != "" {
		t.Fatalf("removed credential still present: %q", got)
	}
}

// A key provider that fails at first (identity not set up yet) and succeeds
// later unlocks the vault without a restart.
func TestVaultUnlocksWhenKeyBecomesAvailable(t *testing.T) {
	dir := t.TempDir()
	ready := false
	cv := NewCredentialVault(dir)
	cv.SetKeyProvider(func() ([]byte, error) {
		if !ready {
			return nil, fmt.Errorf("root seed not available yet")
		}
		return testVaultKeyProvider()
	})

	if err := cv.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err == nil {
		t.Fatal("must refuse writes before the key exists")
	}
	ready = true
	cv.Reload()
	if err := cv.SetCredential("svc", []string{"example.com"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatalf("set after unlock: %v", err)
	}
	if got := cv.GetAPIKey("svc"); got != "x" {
		t.Fatalf("got %q", got)
	}
}
