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

// TestReachabilitySettingsRoundTrip covers the ingress-mode + relay-operator
// fields: they persist across a read, they default to empty on a store that
// never wrote them (back-compat for the pre-migration single row), and re-saving
// replaces them cleanly alongside the tunnel fields.
func TestReachabilitySettingsRoundTrip(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// A row written with only tunnel fields reads back with empty reachability
	// fields — the migration's defaults, not an error.
	if err := s.SaveSettings(SettingsData{TunnelProvider: "none"}); err != nil {
		t.Fatalf("SaveSettings tunnel-only: %v", err)
	}
	got, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.IngressMode != "" || got.RelayOperator != "" {
		t.Fatalf("expected empty reachability fields by default, got mode=%q operator=%q", got.IngressMode, got.RelayOperator)
	}

	// Save both new fields alongside a tunnel provider -> all persist.
	if err := s.SaveSettings(SettingsData{
		TunnelProvider: "grapeid",
		IngressMode:    "relay",
		RelayOperator:  "https://relay.example.org",
	}); err != nil {
		t.Fatalf("SaveSettings with reachability: %v", err)
	}
	got, err = s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after reachability save: %v", err)
	}
	if got.IngressMode != "relay" || got.RelayOperator != "https://relay.example.org" || got.TunnelProvider != "grapeid" {
		t.Fatalf("reachability settings not persisted cleanly: %+v", got)
	}

	// Re-save clearing the mode -> the single row replaces cleanly.
	if err := s.SaveSettings(SettingsData{TunnelProvider: "grapeid", RelayOperator: "https://relay.example.org"}); err != nil {
		t.Fatalf("SaveSettings clear mode: %v", err)
	}
	got, _ = s.GetSettings()
	if got.IngressMode != "" {
		t.Fatalf("expected mode cleared, got %q", got.IngressMode)
	}
}
