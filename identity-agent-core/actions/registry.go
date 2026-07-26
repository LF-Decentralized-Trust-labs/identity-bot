// Package actions exposes the canonical action registry (registry.json) to Go.
//
// registry.json is the single source of truth for action codes + their schemas
// (see docs/action-code-registry.md). It is embedded here so the core can seed
// runtime state from it — e.g. the share_actions table (ADR-017) — rather than
// duplicating the list in hardcoded SQL. Adding a share action becomes a registry
// change, not a code change.
package actions

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed registry.json
var registryJSON []byte

// Action is one registered action-code entry. Code is the canonical wire
// identifier (t); Key is the stable string handle (URLs / share_actions.action_key).
// Code is a pointer so a reserved entry with no assigned wire code yet is allowed.
type Action struct {
	Code            *int            `json:"code"`
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Summary         string          `json:"summary"`
	WhoMints        string          `json:"who_mints"`
	Status          string          `json:"status"`
	Version         string          `json:"version"`
	RequestSchema   json.RawMessage `json:"request_schema"`
	PreviewContract json.RawMessage `json:"preview_contract"`
	// Discloses names the profile fields that leave the agent when this action
	// executes. It is the action's own declaration of what it sends about you:
	// the consent screen renders it and the outbound payload is built from it.
	// An empty list means the action sends nothing about you.
	Discloses []string `json:"discloses"`
	Outcome         string          `json:"outcome"`
	Tiers           []string        `json:"tiers"`
	UI              ActionUI        `json:"ui"`
}

// ActionUI is presentation/runtime metadata used to seed the share_actions table.
type ActionUI struct {
	ShareMenu bool   `json:"share_menu"`
	Icon      string `json:"icon"`
	Enabled   bool   `json:"enabled"`
	SortOrder int    `json:"sort_order"`
	Subtitle  string `json:"subtitle"`
}

// Registry is the parsed registry.json.
type Registry struct {
	RegistryVersion string   `json:"registry_version"`
	EnvelopeVersion string   `json:"envelope_version"`
	Actions         []Action `json:"actions"`
}

// Load parses the embedded canonical action registry.
func Load() (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(registryJSON, &r); err != nil {
		return nil, fmt.Errorf("parse embedded action registry: %w", err)
	}
	return &r, nil
}

// ShareMenuActions returns the actions flagged for the user-initiable share menu
// (ui.share_menu = true) — the subset seeded into share_actions.
func (r *Registry) ShareMenuActions() []Action {
	var out []Action
	for _, a := range r.Actions {
		if a.UI.ShareMenu {
			out = append(out, a)
		}
	}
	return out
}
