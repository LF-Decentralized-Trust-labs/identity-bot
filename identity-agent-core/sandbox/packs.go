package sandbox

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Capability packs are how capabilities reach the registry: capabilities are DATA,
// never code. A pack is a JSON document bundling CapabilityRecords under a named,
// versioned publisher. The engine ships with a small reference pack (embedded below);
// operators add their own by dropping pack files into <dataDir>/capability-packs/ or
// importing them over the local management API. Adding, updating, or retiring a
// capability is an edit to a pack — no code change, no release.

//go:embed packs/*.json
var embeddedPacks embed.FS

// packsDirName under the agent data dir; *.json files here load at startup.
const packsDirName = "capability-packs"

// CapabilityPack is the interchange format for capability records.
type CapabilityPack struct {
	Pack      string `json:"pack"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	// Signature is reserved for the publisher's signature over the pack's canonical
	// JSON, verified at import once publisher identities are wired end-to-end.
	Signature    string             `json:"signature,omitempty"`
	Capabilities []CapabilityRecord `json:"capabilities"`
}

var validExecutorTypes = map[string]bool{
	"internal_api": true,
	"external_api": true,
	"ai_agent":     true,
	"host_control": true,
}

// ParseCapabilityPack decodes and validates a pack document.
func ParseCapabilityPack(data []byte) (*CapabilityPack, error) {
	var p CapabilityPack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid pack JSON: %w", err)
	}
	if strings.TrimSpace(p.Pack) == "" {
		return nil, fmt.Errorf("pack is missing its \"pack\" name")
	}
	if len(p.Capabilities) == 0 {
		return nil, fmt.Errorf("pack %q declares no capabilities", p.Pack)
	}
	for i, r := range p.Capabilities {
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("pack %q: capability %d has no id", p.Pack, i)
		}
		if !validExecutorTypes[r.ExecutorType] {
			return nil, fmt.Errorf("pack %q: capability %q has unknown executor_type %q", p.Pack, r.ID, r.ExecutorType)
		}
		if r.ExecutorType == "external_api" && (r.Egress == nil || r.Egress.BaseURL == "") {
			return nil, fmt.Errorf("pack %q: external_api capability %q has no egress base_url", p.Pack, r.ID)
		}
	}
	return &p, nil
}

// ImportCapabilityPack upserts a pack's records (idempotent — re-importing an
// updated pack rolls its capabilities forward). Records with no provider are
// attributed to the pack.
func (s *SandboxStore) ImportCapabilityPack(p *CapabilityPack) (int, error) {
	for _, r := range p.Capabilities {
		if r.Provider == "" {
			r.Provider = "pack:" + p.Pack
		}
		if err := s.UpsertCapabilityRecord(r); err != nil {
			return 0, fmt.Errorf("pack %q: import capability %q: %w", p.Pack, r.ID, err)
		}
	}
	return len(p.Capabilities), nil
}

// ImportCapabilityPackJSON parses, validates, and imports one pack document.
func (m *Manager) ImportCapabilityPackJSON(data []byte) (*CapabilityPack, int, error) {
	p, err := ParseCapabilityPack(data)
	if err != nil {
		return nil, 0, err
	}
	n, err := m.store.ImportCapabilityPack(p)
	if err != nil {
		return nil, 0, err
	}
	return p, n, nil
}

// loadCapabilityPacks loads the embedded reference pack(s) and every pack file in
// <dataDir>/capability-packs/. Errors are logged, never fatal — one bad pack must
// not take the agent down.
func (m *Manager) loadCapabilityPacks() {
	entries, err := embeddedPacks.ReadDir("packs")
	if err == nil {
		for _, e := range entries {
			data, rerr := embeddedPacks.ReadFile("packs/" + e.Name())
			if rerr != nil {
				log.Printf("[registry] read embedded pack %s: %v", e.Name(), rerr)
				continue
			}
			m.importPackFile("embedded:"+e.Name(), data)
		}
	}

	dir := filepath.Join(m.dataDir, packsDirName)
	files, err := os.ReadDir(dir)
	if err != nil {
		return // no operator packs directory — nothing to load
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, f.Name()))
		if rerr != nil {
			log.Printf("[registry] read pack %s: %v", f.Name(), rerr)
			continue
		}
		m.importPackFile(f.Name(), data)
	}
}

func (m *Manager) importPackFile(name string, data []byte) {
	p, n, err := m.ImportCapabilityPackJSON(data)
	if err != nil {
		log.Printf("[registry] pack %s not loaded: %v", name, err)
		return
	}
	log.Printf("[registry] loaded pack %q (%d capabilities) from %s", p.Pack, n, name)
}
