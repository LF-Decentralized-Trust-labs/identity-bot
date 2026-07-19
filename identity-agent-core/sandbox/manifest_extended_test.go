package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// An extended plug-in manifest: kind/sub_type/provides/host_control +
// per-OS binaries via supported_platforms (covers every host so the test resolves).
const extendedManifestJSON = `{
  "id": "native-computer-use",
  "name": "Native Computer Use",
  "description": "Drives the real machine with OS input + screen vision.",
  "version": "0.1.0",
  "author": "Example Author",
  "execution_type": "compiled",
  "display_method": "webview",
  "network_mode": "local_only",
  "kind": "capability",
  "sub_type": "go-binary",
  "provides": [
    {
      "id": "native-computer-use",
      "name": "Native Computer Use",
      "description": "Operate any UI as if a human were at the keyboard.",
      "request_contract": "contracts/native-computer-use-request.md",
      "acdc_scope": "",
      "enabled_by_default": false,
      "host_control": true
    }
  ],
  "host_control": {
    "grants_required": { "darwin": ["accessibility", "screen_recording"] },
    "kill_switch": true
  },
  "supported_platforms": [
    { "os": "darwin",  "min_version": "13.0", "arch": ["arm64", "amd64"], "binary": "bin/native-computer-use-darwin" },
    { "os": "linux",   "min_version": "",     "arch": ["amd64", "arm64"], "binary": "bin/native-computer-use-linux" },
    { "os": "windows", "min_version": "10",   "arch": ["amd64"],          "binary": "bin/native-computer-use-windows.exe" }
  ],
  "resources": { "cpu_cores": 1.0, "memory_mb": 512, "disk_mb": 128, "egress_kbps": 1024, "ingress_kbps": 1024 },
  "network": { "tls_mode": "sni_only", "allowed_domains": [], "blocked_domains": [] },
  "capabilities": { "allowed": ["host_control"], "blocked": ["network", "filesystem"] },
  "log_level": "metadata",
  "signature": null,
  "publisher_key": null,
  "signature_algorithm": null
}`

func writeTempManifest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadExtendedManifest(t *testing.T) {
	m, err := LoadManifest(writeTempManifest(t, extendedManifestJSON))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.Kind != "capability" || m.SubType != "go-binary" {
		t.Errorf("kind/sub_type not parsed: %q/%q", m.Kind, m.SubType)
	}
	if len(m.Provides) != 1 || m.Provides[0].ID != "native-computer-use" {
		t.Fatalf("provides not parsed: %+v", m.Provides)
	}
	if !m.Provides[0].HostControl || !m.RequiresHostControl() {
		t.Errorf("host_control not detected")
	}
	if m.HostControl == nil || !m.HostControl.KillSwitch {
		t.Errorf("host_control spec not parsed: %+v", m.HostControl)
	}
	// The loader must have resolved the host-matching binary into Binary.
	if m.Binary == nil {
		t.Fatalf("host binary not resolved for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	want, ok := m.SelectPlatformBinary(runtime.GOOS, runtime.GOARCH)
	if !ok || m.Binary.Path != want {
		t.Errorf("resolved binary = %q, want %q", m.Binary.Path, want)
	}
	if ids := m.ProvidedCapabilityIDs(); len(ids) != 1 || ids[0] != "native-computer-use" {
		t.Errorf("ProvidedCapabilityIDs = %v", ids)
	}
}

// A legacy manifest (no profile fields, single binary.path) must still validate unchanged.
func TestLegacyManifestStillValidates(t *testing.T) {
	const legacy = `{
  "id": "go-demo", "name": "Go Demo", "description": "x", "version": "1.0.0", "author": "IA",
  "execution_type": "compiled", "display_method": "webview", "network_mode": "proxy_required",
  "binary": { "path": "bin/go-demo", "args": [], "environment": {} },
  "resources": { "cpu_cores": 0.5, "memory_mb": 256, "disk_mb": 128, "egress_kbps": 1024, "ingress_kbps": 1024 },
  "network": { "tls_mode": "sni_only", "allowed_domains": ["agent.internal"], "blocked_domains": [] },
  "capabilities": { "allowed": ["network"], "blocked": ["camera"] },
  "log_level": "full", "signature": null, "publisher_key": null, "signature_algorithm": null
}`
	m, err := LoadManifest(writeTempManifest(t, legacy))
	if err != nil {
		t.Fatalf("legacy manifest failed to load: %v", err)
	}
	if m.Kind != "" || len(m.Provides) != 0 || m.RequiresHostControl() {
		t.Errorf("legacy manifest gained profile fields unexpectedly")
	}
	if m.Binary == nil || m.Binary.Path != "bin/go-demo" {
		t.Errorf("legacy binary path altered: %+v", m.Binary)
	}
}

func TestInvalidKindRejected(t *testing.T) {
	bad := `{"id":"x","name":"x","execution_type":"compiled","display_method":"webview",
  "network_mode":"local_only","kind":"widget","binary":{"path":"bin/x"},
  "resources":{"memory_mb":64},"network":{"tls_mode":"sni_only"},"log_level":"metadata"}`
	if _, err := LoadManifest(writeTempManifest(t, bad)); err == nil {
		t.Fatalf("expected invalid kind to be rejected")
	}
}
