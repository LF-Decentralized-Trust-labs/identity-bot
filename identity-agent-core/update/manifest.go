package update

import (
	"encoding/json"
	"fmt"
	"time"
)

const SupportedManifestVersion = 1

// Manifest is the signed release manifest.
type Manifest struct {
	ManifestVersion int                       `json:"manifest_version"`
	PublishedAt     string                    `json:"published_at"`
	SigningKeyID    string                    `json:"signing_key_id"`
	Channels        map[string]ChannelPolicy  `json:"channels"`
	Components      map[string]ComponentEntry `json:"components"`
	Compatibility   map[string]CompatRule     `json:"compatibility"`
	Changelog       []ChangelogEntry          `json:"changelog"`
	NextSigningKey  *NextSigningKey           `json:"next_signing_key,omitempty"`
	Signature       string                    `json:"signature"`
}

type ChannelPolicy struct {
	MinSupportedManifestVersion int `json:"min_supported_manifest_version"`
}

type ComponentEntry struct {
	Version        string     `json:"version"`
	MinimumVersion string     `json:"minimum_version"`
	Critical       bool       `json:"critical"`
	Artifacts      []Artifact `json:"artifacts"`
}

type Artifact struct {
	Platform  string `json:"platform"`
	URL       string `json:"url"`
	Blake3_256 string `json:"blake3_256"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	DiffURL   string `json:"diff_url,omitempty"`
}

type CompatRule struct {
	MinGoBackend string `json:"min_go_backend"`
	MaxGoBackend string `json:"max_go_backend"`
}

type ChangelogEntry struct {
	Version  string   `json:"version"`
	Date     string   `json:"date"`
	Critical bool     `json:"critical"`
	Summary  string   `json:"summary"`
	Entries  []string `json:"entries"`
}

type NextSigningKey struct {
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	ActivatesAt string `json:"activates_at"`
}

// KeyTransition is the signed key-rotation endorsement object that lets a
// release-signing key be replaced without trusting the new key on its own.
type KeyTransition struct {
	OldKeyID     string `json:"old_key_id"`
	NewKeyID     string `json:"new_key_id"`
	NewPublicKey string `json:"new_public_key"`
	EndorsedAt   string `json:"endorsed_at"`
	Signature    string `json:"signature"`
}

// ParseManifest unmarshals raw JSON without verification.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("invalid manifest json: %w", err)
	}
	return &m, nil
}

// PublishedTime parses published_at as RFC3339 UTC.
func (m *Manifest) PublishedTime() (time.Time, error) {
	return time.Parse(time.RFC3339, m.PublishedAt)
}

// ComponentForPlatform returns the artifact for the given platform key.
func (c *ComponentEntry) ComponentForPlatform(platform string) (*Artifact, error) {
	for i := range c.Artifacts {
		if c.Artifacts[i].Platform == platform {
			return &c.Artifacts[i], nil
		}
	}
	return nil, fmt.Errorf("no artifact for platform %q", platform)
}

// AvailableUpdate describes an update surfaced to the UI.
type AvailableUpdate struct {
	Component       string `json:"component"`
	Installed       string `json:"installed"`
	Available       string `json:"available"`
	Critical        bool   `json:"critical"`
	BelowMinimum    bool   `json:"below_minimum"`
	RequiresConfirm bool   `json:"requires_confirm"`
}