package store

import "testing"

// TestSettingsPersistence covers the single-row settings store: a saved tunnel
// provider + token survives a read (previously it silently never persisted), and
// re-saving replaces the row rather than accumulating.
func TestSettingsPersistence(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// No settings yet -> nil, no error.
	got, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil settings initially, got %+v", got)
	}

	// Save cloudflare + token -> must persist (the bug: it didn't).
	if err := s.SaveSettings(SettingsData{TunnelProvider: "cloudflare", CloudflareTunnelToken: "tok123"}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	got, err = s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after save: %v", err)
	}
	if got == nil || got.TunnelProvider != "cloudflare" || got.CloudflareTunnelToken != "tok123" {
		t.Fatalf("cloudflare settings not persisted: %+v", got)
	}

	// Re-save a different provider -> replaces the single row (token cleared).
	if err := s.SaveSettings(SettingsData{TunnelProvider: "grapeid", TunnelExtension: "soft-lion"}); err != nil {
		t.Fatalf("SaveSettings overwrite: %v", err)
	}
	got, _ = s.GetSettings()
	if got.TunnelProvider != "grapeid" || got.TunnelExtension != "soft-lion" || got.CloudflareTunnelToken != "" {
		t.Fatalf("overwrite did not replace cleanly: %+v", got)
	}

	// Exactly one row.
	var n int
	if err := s.DB().QueryRow("SELECT count(*) FROM settings").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 settings row, got %d", n)
	}
}
