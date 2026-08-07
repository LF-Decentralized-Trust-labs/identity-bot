package update

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// DefaultManifestURL is the OSS-neutral update manifest endpoint.
const DefaultManifestURL = "https://updates.identitybot.org/v1/manifest.json"

// ConfigFile is persisted under dataDir/updates/config.json.
type ConfigFile struct {
	ManifestURL string `json:"manifest_url,omitempty"`
	Channel     string `json:"channel,omitempty"`
}

// ResolveManifestURL returns the manifest URL from env, config file, or default.
func ResolveManifestURL(dataDir string) string {
	if url := os.Getenv("UPDATE_MANIFEST_URL"); url != "" {
		return url
	}
	if dataDir != "" {
		if cfg, err := LoadConfigFile(dataDir); err == nil && cfg.ManifestURL != "" {
			return cfg.ManifestURL
		}
	}
	return DefaultManifestURL
}

func configPath(dataDir string) string {
	return filepath.Join(dataDir, "updates", "config.json")
}

// LoadConfigFile reads updates/config.json when present.
func LoadConfigFile(dataDir string) (*ConfigFile, error) {
	raw, err := os.ReadFile(configPath(dataDir))
	if err != nil {
		return nil, err
	}
	var cfg ConfigFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfigFile writes updates/config.json.
func SaveConfigFile(dataDir string, cfg ConfigFile) error {
	dir := filepath.Join(dataDir, "updates")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(dataDir), raw, 0644)
}