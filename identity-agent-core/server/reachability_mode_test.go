package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/endpoint"
	"identity-agent-core/store"
	"identity-agent-core/tunnel"
)

// resolveIngressMode is the single control point for how an agent becomes
// reachable. Its defaults are per-product, and an explicit setting overrides
// them.

func TestResolveIngressModeDefaultsByEntityType(t *testing.T) {
	cases := []struct {
		entity string
		want   IngressMode
	}{
		{"individual", IngressModeRelay},    // privacy by default
		{"organization", IngressModeTunnel}, // one public address
		{"", IngressModeRelay},              // OSS core / undeclared -> relay, never Direct
		{"nonsense", IngressModeRelay},      // unrecognised normalises to relay, not a guess into Tunnel
	}
	for _, c := range cases {
		s := exportServer(t, t.TempDir())
		s.DeclaredEntityType = c.entity
		if got := s.resolveIngressMode(); got != c.want {
			t.Fatalf("entity %q: default mode = %q, want %q", c.entity, got, c.want)
		}
	}
}

func TestResolveIngressModeNeverDefaultsToDirect(t *testing.T) {
	// Direct is a developer/testing toggle; no entity type may resolve to it as
	// a default.
	for _, entity := range []string{"individual", "organization", ""} {
		s := exportServer(t, t.TempDir())
		s.DeclaredEntityType = entity
		if got := s.resolveIngressMode(); got == IngressModeDirect {
			t.Fatalf("entity %q defaulted to Direct, which is never a product default", entity)
		}
	}
}

func TestResolveIngressModeExplicitSettingOverridesDefault(t *testing.T) {
	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "organization" // default would be tunnel

	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct"}); err != nil {
		t.Fatal(err)
	}
	if got := s.resolveIngressMode(); got != IngressModeDirect {
		t.Fatalf("explicit mode not honored: got %q, want direct", got)
	}

	// An invalid stored mode falls back to the per-product default rather than
	// acting on garbage.
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "banana"}); err != nil {
		t.Fatal(err)
	}
	if got := s.resolveIngressMode(); got != IngressModeTunnel {
		t.Fatalf("invalid stored mode should fall back to default tunnel, got %q", got)
	}
}

// loadTunnelConfig must no longer publish a public tunnel just because nothing
// was configured — the retired default-public switch.

func TestNonTunnelModeOpensNoPublicTunnel(t *testing.T) {
	// A fresh OSS-core / individual instance with no tunnel env and no settings
	// resolves to relay mode and therefore opens NO public tunnel.
	t.Setenv("TUNNEL_PROVIDER", "")
	t.Setenv("NGROK_AUTHTOKEN", "")
	t.Setenv("CLOUDFLARE_TUNNEL_TOKEN", "")

	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "individual"

	cfg := s.loadTunnelConfig()
	if cfg.Provider != tunnel.ProviderNone {
		t.Fatalf("relay-mode instance opened a %q tunnel; it must open none (the retired default-public switch)", cfg.Provider)
	}
}

func TestTunnelEnvIsStillHonouredForBackCompat(t *testing.T) {
	// Even in a non-tunnel default mode, an explicit tunnel env var still selects
	// a tunnel, so deployments that configured one only through the environment
	// keep working.
	t.Setenv("NGROK_AUTHTOKEN", "")
	t.Setenv("CLOUDFLARE_TUNNEL_TOKEN", "")
	t.Setenv("TUNNEL_PROVIDER", "ngrok")

	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "individual" // default relay

	cfg := s.loadTunnelConfig()
	if cfg.Provider != tunnel.ProviderNgrok {
		t.Fatalf("explicit TUNNEL_PROVIDER env should still select a tunnel, got %q", cfg.Provider)
	}
}

func TestExplicitTunnelSettingHonoured(t *testing.T) {
	t.Setenv("TUNNEL_PROVIDER", "")
	t.Setenv("NGROK_AUTHTOKEN", "")
	t.Setenv("CLOUDFLARE_TUNNEL_TOKEN", "")

	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "individual"
	if err := s.DataStore.SaveSettings(store.SettingsData{TunnelProvider: "ngrok"}); err != nil {
		t.Fatal(err)
	}

	cfg := s.loadTunnelConfig()
	if cfg.Provider != tunnel.ProviderNgrok {
		t.Fatalf("an explicitly chosen tunnel provider must be used, got %q", cfg.Provider)
	}
}

// relayBaseURL resolves the operator from settings first, then the env var.

func TestRelayOperatorFromSettingsThenEnv(t *testing.T) {
	t.Setenv("RELAY_BASE_URL", "https://env-relay.example.org")

	s := exportServer(t, t.TempDir())
	// Nothing stored -> env is the fallback.
	if got := s.relayBaseURL(); got != "https://env-relay.example.org" {
		t.Fatalf("env fallback not used: got %q", got)
	}

	// A stored operator wins over the env, and a trailing slash is trimmed.
	if err := s.DataStore.SaveSettings(store.SettingsData{RelayOperator: "https://stored-relay.example.org/"}); err != nil {
		t.Fatal(err)
	}
	if got := s.relayBaseURL(); got != "https://stored-relay.example.org" {
		t.Fatalf("stored operator should win and be trimmed: got %q", got)
	}
}

// The reachability settings route reads and writes the mode + operator without
// disturbing the tunnel settings, and vice versa.

func TestReachabilitySettingsRouteRoundTrip(t *testing.T) {
	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "individual"

	// A tunnel setting exists already; changing reachability must not wipe it.
	if err := s.DataStore.SaveSettings(store.SettingsData{TunnelProvider: "ngrok", NgrokAuthToken: "tok"}); err != nil {
		t.Fatal(err)
	}

	// PUT the mode + operator.
	r := httptest.NewRequest(http.MethodPut, "/api/settings/reachability",
		bytes.NewReader([]byte(`{"mode":"direct","relay_operator":"https://r.example.org"}`)))
	w := httptest.NewRecorder()
	s.handlePutReachabilitySettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT reachability failed: %d %s", w.Code, w.Body)
	}

	saved, _ := s.DataStore.GetSettings()
	if saved.IngressMode != "direct" || saved.RelayOperator != "https://r.example.org" {
		t.Fatalf("reachability not saved: %+v", saved)
	}
	if saved.TunnelProvider != "ngrok" || saved.NgrokAuthToken != "tok" {
		t.Fatalf("saving reachability wiped the tunnel settings: %+v", saved)
	}

	// GET reflects the resolved mode and the explicit choice.
	rg := httptest.NewRequest(http.MethodGet, "/api/settings/reachability", nil)
	wg := httptest.NewRecorder()
	s.handleGetReachabilitySettings(wg, rg)
	if wg.Code != http.StatusOK {
		t.Fatalf("GET reachability failed: %d %s", wg.Code, wg.Body)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(wg.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["resolved_mode"] != "direct" || body["mode"] != "direct" {
		t.Fatalf("GET did not reflect the explicit mode: %+v", body)
	}
	if body["is_default"] != false {
		t.Fatalf("is_default should be false after an explicit choice: %+v", body)
	}
	if body["default_mode"] != "relay" {
		t.Fatalf("individual default should be relay: %+v", body)
	}
}

func TestReachabilityPutRejectsInvalidMode(t *testing.T) {
	s := exportServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPut, "/api/settings/reachability",
		bytes.NewReader([]byte(`{"mode":"sideways"}`)))
	w := httptest.NewRecorder()
	s.handlePutReachabilitySettings(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode should be rejected, got %d %s", w.Code, w.Body)
	}
}

func TestReachabilityPutOnlyMovesTheFieldsItCarries(t *testing.T) {
	s := exportServer(t, t.TempDir())
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "relay", RelayOperator: "https://keep.example.org"}); err != nil {
		t.Fatal(err)
	}
	// Send only the mode; the operator must survive.
	r := httptest.NewRequest(http.MethodPut, "/api/settings/reachability",
		bytes.NewReader([]byte(`{"mode":"tunnel"}`)))
	w := httptest.NewRecorder()
	s.handlePutReachabilitySettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT failed: %d %s", w.Code, w.Body)
	}
	saved, _ := s.DataStore.GetSettings()
	if saved.IngressMode != "tunnel" {
		t.Fatalf("mode not updated: %+v", saved)
	}
	if saved.RelayOperator != "https://keep.example.org" {
		t.Fatalf("operator was wiped when only the mode was sent: %+v", saved)
	}
}

// The tunnel settings route must likewise preserve the reachability fields it
// does not own.

func TestTunnelPutPreservesReachabilityFields(t *testing.T) {
	s := exportServer(t, t.TempDir())
	s.DeclaredEntityType = "individual"
	s.EndpointService = endpoint.New(nil, 5050) // the tunnel handler refreshes it
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct", RelayOperator: "https://keep.example.org"}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPut, "/api/settings/tunnel",
		strings.NewReader(`{"provider":"none"}`))
	w := httptest.NewRecorder()
	s.handlePutTunnelSettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT tunnel failed: %d %s", w.Code, w.Body)
	}

	saved, _ := s.DataStore.GetSettings()
	if saved.IngressMode != "direct" || saved.RelayOperator != "https://keep.example.org" {
		t.Fatalf("saving a tunnel setting wiped the reachability fields: %+v", saved)
	}
}
