package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPackJSON = `{
  "pack": "testpack",
  "version": "1.0.0",
  "publisher": "test",
  "capabilities": [
    {
      "id": "testsvc.widget.list",
      "name": "List widgets",
      "description": "List widgets.",
      "domain": "dev",
      "executor_type": "external_api",
      "impact": "read",
      "egress": {"base_url": "https://api.example.com", "method": "GET", "path_template": "/widgets", "credential_service": "testsvc"},
      "enabled": true
    }
  ]
}`

// Pack validation rejects malformed documents with actionable errors.
func TestParseCapabilityPackValidation(t *testing.T) {
	if _, err := ParseCapabilityPack([]byte(`not json`)); err == nil {
		t.Fatal("non-JSON must error")
	}
	if _, err := ParseCapabilityPack([]byte(`{"capabilities":[{"id":"x","executor_type":"external_api","egress":{"base_url":"https://x"}}]}`)); err == nil || !strings.Contains(err.Error(), "pack") {
		t.Fatalf("missing pack name must error, got %v", err)
	}
	if _, err := ParseCapabilityPack([]byte(`{"pack":"p","capabilities":[]}`)); err == nil {
		t.Fatal("empty capability list must error")
	}
	if _, err := ParseCapabilityPack([]byte(`{"pack":"p","capabilities":[{"id":"x","executor_type":"teleport"}]}`)); err == nil || !strings.Contains(err.Error(), "executor_type") {
		t.Fatalf("unknown executor_type must error, got %v", err)
	}
	if _, err := ParseCapabilityPack([]byte(`{"pack":"p","capabilities":[{"id":"x","executor_type":"external_api"}]}`)); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("external_api without egress must error, got %v", err)
	}
}

// Importing a pack registers its records (SAID computed, provider defaulted to the
// pack) and re-importing an edited pack rolls records forward.
func TestImportCapabilityPackRollsForward(t *testing.T) {
	m := registryTestManager(t)
	p, n, err := m.ImportCapabilityPackJSON([]byte(testPackJSON))
	if err != nil || n != 1 || p.Pack != "testpack" {
		t.Fatalf("import: %v (n=%d)", err, n)
	}
	rec, err := m.store.GetCapabilityRecord("testsvc.widget.list")
	if err != nil || rec == nil {
		t.Fatalf("record missing after import: %v", err)
	}
	if !strings.HasPrefix(rec.SAID, "blake3:") {
		t.Fatalf("imported record missing SAID: %q", rec.SAID)
	}
	if rec.Provider != "pack:testpack" {
		t.Fatalf("provider not defaulted to pack, got %q", rec.Provider)
	}

	updated := strings.Replace(testPackJSON, "List widgets.", "List all widgets.", 1)
	if _, _, err := m.ImportCapabilityPackJSON([]byte(updated)); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	rec2, _ := m.store.GetCapabilityRecord("testsvc.widget.list")
	if rec2.Description != "List all widgets." {
		t.Fatalf("re-import must roll forward, got %q", rec2.Description)
	}
	if rec2.SAID == rec.SAID {
		t.Fatal("edited record must get a new SAID")
	}
}

// Packs dropped into <dataDir>/capability-packs/ load at startup alongside the
// embedded reference pack; a broken file is skipped, not fatal.
func TestLoadCapabilityPacksFromDataDir(t *testing.T) {
	m := registryTestManager(t)
	dir := filepath.Join(m.dataDir, packsDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpack.json"), []byte(testPackJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"pack":`), 0644); err != nil {
		t.Fatal(err)
	}

	m.loadCapabilityPacks()

	recs, err := m.store.ListCapabilityRecords()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if !ids["testsvc.widget.list"] {
		t.Fatalf("operator pack not loaded: %v", ids)
	}
	if !ids["cloudflare.dns.list"] {
		t.Fatalf("embedded reference pack not loaded: %v", ids)
	}
}

// Enable/disable and delete manage records without touching content; a disabled
// record leaves discovery and the invoke path.
func TestCapabilityEnableDisableDelete(t *testing.T) {
	m := registryTestManager(t)
	if _, _, err := m.ImportCapabilityPackJSON([]byte(testPackJSON)); err != nil {
		t.Fatal(err)
	}

	ok, err := m.store.SetCapabilityEnabled("testsvc.widget.list", false)
	if err != nil || !ok {
		t.Fatalf("disable: %v", err)
	}
	if rec := m.registryRecord("testsvc.widget.list"); rec != nil {
		t.Fatal("disabled record must not resolve for invocation")
	}
	enabled, _ := m.store.ListCapabilityRecords()
	if len(enabled) != 0 {
		t.Fatalf("disabled record must leave discovery, got %d", len(enabled))
	}
	all, _ := m.store.ListAllCapabilityRecords()
	if len(all) != 1 || all[0].Enabled {
		t.Fatalf("management view must still show it disabled, got %+v", all)
	}

	ok, err = m.store.SetCapabilityEnabled("testsvc.widget.list", true)
	if err != nil || !ok {
		t.Fatalf("re-enable: %v", err)
	}
	if rec := m.registryRecord("testsvc.widget.list"); rec == nil {
		t.Fatal("re-enabled record must resolve again")
	}

	ok, err = m.store.DeleteCapabilityRecord("testsvc.widget.list")
	if err != nil || !ok {
		t.Fatalf("delete: %v", err)
	}
	if ok, _ := m.store.DeleteCapabilityRecord("testsvc.widget.list"); ok {
		t.Fatal("second delete must report not found")
	}
}
