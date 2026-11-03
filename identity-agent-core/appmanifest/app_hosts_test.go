package appmanifest

import (
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
		allowed, explicit := m.IsDomainAllowed(c.dest)
		if allowed != c.want || explicit != c.want {
			t.Errorf("entry %q, destination %q: allowed %v explicit %v, want %v", c.entry, c.dest, allowed, explicit, c.want)
		}
	}
	// A blocked entry with no port blocks every port.
	m := &AppManifest{Network: NetworkPermissions{AllowedDomains: []string{"**.example.org"}, BlockedDomains: []string{"bad.example.org"}}}
	if allowed, explicit := m.IsDomainAllowed("bad.example.org:8443"); allowed || !explicit {
		t.Errorf("a blocked host on another port: allowed %v explicit %v", allowed, explicit)
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
	ms, err := LoadManifestsFromDir("../../manifests")
	if err != nil {
		t.Fatal(err)
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
