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
// refusal names the row the file says. The file holds an accepted manifest
// and, for each of the five rows an app declares, one missing that row.
func TestThePublishedAppManifestVectorsHold(t *testing.T) {
	vs := readAppVectors(t)
	accepted, refusedRows := 0, map[string]bool{}
	for _, v := range vs {
		var m AppManifest
		if err := json.Unmarshal(v.Manifest, &m); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		err := m.Validate()
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
	if accepted < 2 {
		t.Errorf("%d accepted vectors; want at least 2", accepted)
	}
	for _, row := range []string{"name", "release_digest", "encrypted_machine", "resources", "network.allowed_domains"} {
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
		if v.Name == "a valid app that needs an encrypted machine and reaches no host" {
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
