package appmanifest

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An entry ValidOutboundHost accepts is read the way it is written by the one
// matcher IsDomainAllowed uses: no port means any port of the host, a port
// means that port only.
func TestAnAllowedHostIsReadAsWritten(t *testing.T) {
	for _, c := range []struct {
		entry, dest string
		want        bool
	}{
		{"api.example.org", "api.example.org", true},
		{"api.example.org", "api.example.org:8443", true},
		{"api.example.org:8443", "api.example.org:8443", true},
		{"api.example.org:8443", "api.example.org:443", false},
		{"api.example.org:8443", "api.example.org", false},
		{"*.example.org", "a.example.org:1", true},
		{"*.example.org", "a.b.example.org", false},
		{"*.example.org:8080", "a.example.org:8080", true},
		{"*.example.org:8080", "a.example.org:80", false},
		{"**.cdn.example.net:443", "a.b.cdn.example.net:443", true},
		{"**.cdn.example.net:443", "a.b.cdn.example.net:80", false},
		{"**.cdn.example.net", "cdn.example.net", false},
	} {
		if !ValidOutboundHost(c.entry) {
			t.Errorf("%q is not a valid entry", c.entry)
		}
		m := &AppManifest{Network: NetworkPermissions{AllowedDomains: []string{c.entry}}}
		host, port, _ := net.SplitHostPort(c.dest)
		if host == "" {
			host = c.dest
		}
		allowed, explicit := m.IsDomainAllowed(host, port)
		if allowed != c.want || explicit != c.want {
			t.Errorf("entry %q, destination %q: allowed %v explicit %v, want %v", c.entry, c.dest, allowed, explicit, c.want)
		}
	}
	// A blocked entry with no port blocks every port.
	m := &AppManifest{Network: NetworkPermissions{AllowedDomains: []string{"**.example.org"}, BlockedDomains: []string{"bad.example.org"}}}
	if allowed, explicit := m.IsDomainAllowed("bad.example.org", "8443"); allowed || !explicit {
		t.Errorf("a blocked host on another port: allowed %v explicit %v", allowed, explicit)
	}
}

// A port-qualified BLOCK entry blocks that port and only it. With the host
// allowed by a wildcard, the blocked port is refused by an explicit rule and
// every other port of the same host stays allowed.
func TestAPortedBlockEntryBlocksThatPortOnly(t *testing.T) {
	m := &AppManifest{Network: NetworkPermissions{
		AllowedDomains: []string{"**.example.org"},
		BlockedDomains: []string{"bad.example.org:8443"},
	}}
	for _, c := range []struct {
		host, port string
		allowed    bool
		explicit   bool
	}{
		{"bad.example.org", "8443", false, true}, // the blocked port
		{"bad.example.org", "443", true, true},   // same host, another port
		{"bad.example.org", "80", true, true},
		{"BAD.example.org", "8443", false, true}, // case does not slip past it
		{"good.example.org", "8443", true, true}, // another host, same port
		{"bad.example.org", "", true, true},      // port unknown: the ported block cannot apply
	} {
		allowed, explicit := m.IsDomainAllowed(c.host, c.port)
		if allowed != c.allowed || explicit != c.explicit {
			t.Errorf("%s:%s: allowed %v explicit %v, want %v %v", c.host, c.port, allowed, explicit, c.allowed, c.explicit)
		}
	}
}

// A manifest is read as the schema reads it: a key it does not declare, a
// key spelt in another case, and null where the schema gives none are refused
// where the manifest is read, not dropped.
func TestDecodeManifestRefusesWhatTheSchemaRefuses(t *testing.T) {
	for _, c := range []struct{ name, json, row string }{
		{"null placement", `{"id":"a","placement":null}`, "placement"},
		{"null queue", `{"id":"a","when_down":{"person_sees":"notice","queue_requests":false,"queue_max_seconds":null}}`, "when_down.queue_max_seconds"},
		{"null list item", `{"id":"a","secrets":[null]}`, "secrets[0]"},
		{"empty placement", `{"id":"a","placement":""}`, "placement"},
		{"empty kind", `{"id":"a","kind":""}`, "kind"},
	} {
		if _, err := DecodeManifest([]byte(c.json)); err == nil || !strings.HasPrefix(err.Error(), c.row+":") {
			t.Errorf("%s: %v, want a refusal that begins %q", c.name, err, c.row+":")
		}
	}
	for _, c := range []struct{ name, json, mention string }{
		{"unknown top key", `{"id":"a","placment":"x"}`, `"placment"`},
		{"other case", `{"id":"a","Placement":"own_machine"}`, `"Placement"`},
		{"unknown nested key", `{"id":"a","resources":{"cpu":1}}`, `"cpu"`},
		{"a key twice", `{"id":"a","id":"b"}`, `"id"`},
	} {
		if _, err := DecodeManifest([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: %v, want a refusal that names %s", c.name, err, c.mention)
		}
	}
	// Null is still allowed where the schema allows it.
	if _, err := DecodeManifest([]byte(`{"id":"a","signature":null,"publisher_key":null,"signature_algorithm":null,"api_schema":null,"binary":{"path":"x","args":null,"environment":null}}`)); err != nil {
		t.Errorf("null on a key the schema allows it on: %v", err)
	}
}

// The manifests shipped in this repository are read by the strict reader.
func TestTheShippedManifestsAreRead(t *testing.T) {
	ms, skipped, err := LoadManifestsFromDir("../../manifests")
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("shipped manifests skipped: %v", skipped)
	}
	if len(ms) == 0 {
		t.Fatal("no manifests found")
	}
}

// {APP_DATA} is the host directory of a manifest that is not an app; for an
// app a volume is its own encrypted store, whatever {APP_DATA} says.
func TestVolumesMeanOneThingForAnAppAndAnotherForAnyOtherManifest(t *testing.T) {
	app := validCompiledApp(t)
	app.ExecutionType, app.Binary = "container", nil
	app.ReleaseDigest = "sha256:" + strings.Repeat("ab", 32)
	app.Store = &AppStore{Format: "sqlite", SizeMB: 10}
	app.Container = &ContainerConfig{Image: "example/x:1", Ports: map[string]string{}, Environment: map[string]string{}, Volumes: map[string]string{"store": "/data"}}
	if err := app.Validate(); err != nil {
		t.Fatalf("an app mounting its store: %v", err)
	}
	app.Container.Volumes = map[string]string{"{APP_DATA}/x": "/data"}
	if err := app.Validate(); err == nil || !strings.HasPrefix(err.Error(), "container.volumes:") {
		t.Errorf("an app naming {APP_DATA}: %v", err)
	}

	plug := &AppManifest{ID: "p", Name: "p", ExecutionType: "container", DisplayMethod: "webview", NetworkMode: "isolated",
		Container: &ContainerConfig{Image: "x", Volumes: map[string]string{"/etc": "/etc"}},
		Network:   NetworkPermissions{TLSMode: "sni_only"}, LogLevel: "none", Resources: ResourceLimits{MemoryMB: 1}}
	if err := plug.Validate(); err == nil || !strings.Contains(err.Error(), "{APP_DATA}") {
		t.Errorf("a plug-in mounting a host path: %v", err)
	}
	plug.Container.Volumes = map[string]string{"{APP_DATA}/x": "/data"}
	if err := plug.Validate(); err != nil {
		t.Errorf("a plug-in mounting {APP_DATA}: %v", err)
	}
}

// One bad file in a folder does not cost the others: it is skipped and named,
// and every good manifest still loads.
func TestOneBadManifestDoesNotCostTheFolder(t *testing.T) {
	dir := t.TempDir()
	shipped, err := os.ReadFile("../../manifests/go-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"a-good.json":    shipped,
		"b-garbage.json": []byte("{not json"),
		"c-invalid.json": []byte(`{"id":"x"}`),
		"d-good.json":    shipped,
		"notes.txt":      []byte("ignored"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ms, skipped, err := LoadManifestsFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Errorf("loaded %d manifests, want the 2 good ones", len(ms))
	}
	if len(skipped) != 2 || skipped[0].File != "b-garbage.json" || skipped[1].File != "c-invalid.json" {
		t.Errorf("skipped %v, want b-garbage.json and c-invalid.json", skipped)
	}
	for _, s := range skipped {
		if s.Err == nil {
			t.Errorf("%s skipped with no reason", s.File)
		}
	}
	if _, _, err := LoadManifestsFromDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("an unreadable folder must still be an error")
	}
}
