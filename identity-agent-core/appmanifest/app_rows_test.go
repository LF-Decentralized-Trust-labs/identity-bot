package appmanifest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"identity-agent-core/internal/contractcheck"
)

type appVector struct {
	Name     string          `json:"name"`
	Outcome  string          `json:"outcome"`
	Row      string          `json:"row"`
	Why      string          `json:"why"`
	Manifest json.RawMessage `json:"manifest"`
}

func readAppVectors(t *testing.T) []appVector {
	t.Helper()
	raw, err := os.ReadFile("app-manifest-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []appVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Vectors
}

// Every published manifest is accepted or refused as the file says, and a
// refusal names the row the file says. The file holds accepted manifests and,
// for each row an app declares, one missing that row; and for every rule of a
// row, one manifest that breaks only that rule.
func TestThePublishedAppManifestVectorsHold(t *testing.T) {
	vs := readAppVectors(t)
	accepted, refusedRows := 0, map[string]bool{}
	for _, v := range vs {
		// DecodeManifest, not json.Unmarshal: the keys the schema refuses (an
		// unknown one, a null) are refused where the manifest is read.
		var err error
		if m, decodeErr := DecodeManifest(v.Manifest); decodeErr != nil {
			err = decodeErr
		} else {
			err = m.Validate()
		}
		switch v.Outcome {
		case "accepted":
			accepted++
			if err != nil {
				t.Errorf("%s: refused: %v", v.Name, err)
			}
		case "refused":
			if err == nil {
				t.Errorf("%s: accepted, want refused for %s", v.Name, v.Row)
				continue
			}
			if !strings.Contains(err.Error(), v.Row) {
				t.Errorf("%s: refused for %q, want the row %q named", v.Name, err, v.Row)
			}
			if strings.HasPrefix(v.Name, "an app with no ") {
				refusedRows[v.Row] = true
			}
		default:
			t.Errorf("%s: outcome %q", v.Name, v.Outcome)
		}
	}
	if accepted < 10 {
		t.Errorf("%d accepted vectors; want at least 10", accepted)
	}
	for _, row := range []string{"name", "release_digest", "encrypted_machine", "resources.cpu_cores", "network.allowed_domains",
		"store", "front_and_back_end", "secrets", "when_down", "backup"} {
		if !refusedRows[row] {
			t.Errorf("no vector shows a manifest missing %s refused", row)
		}
	}
}

// The checks that vectors cannot show: an explicit empty list of outbound
// hosts is an answer, a manifest that predates the rows still validates, and a
// manifest read from disk is refused by the loader as by Validate.
func TestAnAppDeclaresItsRows(t *testing.T) {
	var good AppManifest
	for _, v := range readAppVectors(t) {
		if v.Name == "a valid compiled app that needs an encrypted machine and reaches no host" {
			if err := json.Unmarshal(v.Manifest, &good); err != nil {
				t.Fatal(err)
			}
		}
	}
	if good.ID == "" || good.Network.AllowedDomains == nil || len(good.Network.AllowedDomains) != 0 {
		t.Fatalf("vector for an empty host list not found or not empty: %+v", good.Network)
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("empty allowed_domains refused: %v", err)
	}
	good.Network.AllowedDomains = nil
	if err := good.Validate(); err == nil {
		t.Fatal("a nil allowed_domains was accepted")
	}
	good.Network.AllowedDomains = []string{}
	if err := good.Validate(); err != nil {
		t.Fatalf("an empty list is refused again: %v", err)
	}
	empty := []string{}
	good.Secrets = &empty
	if err := good.Validate(); err != nil {
		t.Fatalf("an empty secrets list (none needed) refused: %v", err)
	}
	good.Secrets = nil
	if err := good.Validate(); err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("an absent secrets row: %v", err)
	}

	for _, v := range readAppVectors(t) {
		if v.Name == "an app with no release_digest" {
			if _, err := LoadManifest(writeTempManifest(t, string(v.Manifest))); err == nil || !strings.Contains(err.Error(), "release_digest") {
				t.Fatalf("LoadManifest on an app with no release_digest: %v", err)
			}
		}
	}
}

func TestTheAppManifestSchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/app-manifest/app-manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]any{
		"manifest":            AppManifest{},
		"container":           ContainerConfig{},
		"binary":              BinaryConfig{},
		"resources":           ResourceLimits{},
		"network":             NetworkPermissions{},
		"capabilities":        Capabilities{},
		"provided_capability": ProvidedCapability{},
		"host_control":        HostControlSpec{},
		"platform_binary":     PlatformBinary{},
		"store":               AppStore{},
		"front_and_back_end":  FrontAndBackEnd{},
		"when_down":           WhenDown{},
		"backup":              Backup{},
	}
	var faults []string
	for def, v := range held {
		faults = append(faults, s.Matches(def, v)...)
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}

// A name that is only white space is no name, and an app's name is checked by
// one rule whether it is empty or not.
func TestAnAppNameIsCheckedByOneRule(t *testing.T) {
	for _, name := range []string{"", " ", "\t\n", "\u00a0\u2003"} {
		m := validCompiledApp(t)
		m.Name = name
		if err := m.Validate(); err == nil || !strings.HasPrefix(err.Error(), "name:") {
			t.Errorf("name %q: %v", name, err)
		}
	}
	m := validCompiledApp(t)
	m.Kind, m.Name = "capability", ""
	m.ReleaseDigest, m.EncryptedMachine, m.Store, m.Placement = "", "", nil, ""
	m.FrontAndBackEnd, m.Secrets, m.WhenDown, m.Backup = nil, nil, nil, nil
	if err := m.Validate(); err == nil || err.Error() != "name is required" {
		t.Errorf("a capability with no name: %v", err)
	}
}

func validCompiledApp(t *testing.T) *AppManifest {
	t.Helper()
	for _, v := range readAppVectors(t) {
		if v.Name == "a valid compiled app that needs an encrypted machine and reaches no host" {
			var m AppManifest
			if err := json.Unmarshal(v.Manifest, &m); err != nil {
				t.Fatal(err)
			}
			return &m
		}
	}
	t.Fatal("vector for a valid compiled app not found")
	return nil
}

// ValidOutboundHost accepts the five written forms and nothing else.
func TestOutboundHostForms(t *testing.T) {
	for _, h := range []string{"a", "a.example.org", "a-b.example.org", "a.example.org:1", "a.example.org:65535", "*.example.org",
		"**.example.org", "*.example.org:8080", "**.a.b.example.org:443", "localhost:8080"} {
		if !ValidOutboundHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"", "*", "*.com", "**.com", "a.*.example.org", "***.example.org", "*example.org", "A.example.org", "10.0.0.1",
		"1.2", "a.example.org:0", "a.example.org:65536", "a.example.org:080", "a.example.org:", "a:1:2", "a..b", "a.b.", "-a.b", "a_b.c",
		"https://a.example.org", "a.example.org/x", "a b.example.org", "*.1.2"} {
		if ValidOutboundHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

// An independent implementation, written from the schema's prose in Python,
// agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheAppManifestVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_app_manifest_vectors.py", "app-manifest-vectors.json")
}
