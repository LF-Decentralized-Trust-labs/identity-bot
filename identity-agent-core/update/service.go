package update

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Settings holds updater preferences (code-plane only — never KERI config).
type Settings struct {
	Channel            string `json:"channel"`
	AutoApplyCritical  bool   `json:"auto_apply_critical"`
	OptOutWarningShown bool   `json:"opt_out_warning_shown"`
}

// StatusResponse is returned by GET /api/updates/status.
type StatusResponse struct {
	Installed       map[string]string `json:"installed"`
	LastChecked     string            `json:"last_checked,omitempty"`
	Available       []AvailableUpdate `json:"available"`
	Settings        Settings          `json:"settings"`
	Genuineness     GenuinenessAxis   `json:"genuineness"`
	ManifestPresent bool              `json:"manifest_present"`
}

// Service orchestrates polling, verification, apply, and attestation.
type Service struct {
	mu sync.RWMutex

	dataDir      string
	manifestURL  string
	trust        *TrustAnchor
	poller       *Poller
	applier      *Applier
	attestation  *Attestation
	settings     Settings
	installed    map[string]string
	cachedRaw    []byte
	cached       *Manifest
	lastChecked  time.Time
	lastError    string
	healthCheck  func() error
}

type Config struct {
	DataDir         string
	ManifestURL     string
	TrustAnchor     *TrustAnchor
	HealthCheckURL  string
	BinaryPath      string
	Installed       map[string]string
}

func DefaultConfig(dataDir string) Config {
	url := os.Getenv("UPDATE_MANIFEST_URL")
	if url == "" {
		url = "https://updates.grapeid.com/v1/manifest.json"
	}
	ta, err := DefaultTrustAnchor()
	if err != nil {
		log.Printf("[update] trust anchor init failed: %v", err)
	}
	bin, _ := os.Executable()
	return Config{
		DataDir:     dataDir,
		ManifestURL: url,
		TrustAnchor: ta,
		BinaryPath:  bin,
		Installed: map[string]string{
			"go_backend": "0.1.0",
		},
	}
}

func NewService(cfg Config) (*Service, error) {
	if cfg.TrustAnchor == nil {
		var err error
		cfg.TrustAnchor, err = DefaultTrustAnchor()
		if err != nil {
			return nil, err
		}
	}
	if cfg.Installed == nil {
		cfg.Installed = map[string]string{"go_backend": "0.1.0"}
	}

	staging := filepath.Join(cfg.DataDir, "updates", "staging")
	applier := NewApplier(staging, cfg.HealthCheckURL, CurrentPlatform())
	att := NewAttestation(cfg.BinaryPath, CurrentPlatform())
	att.SetInstalledVersions(cfg.Installed)

	s := &Service{
		dataDir:     cfg.DataDir,
		manifestURL: cfg.ManifestURL,
		trust:       cfg.TrustAnchor,
		applier:     applier,
		attestation: att,
		settings: Settings{
			Channel:           "stable",
			AutoApplyCritical: true, // OQ-1: ON by default
		},
		installed: copyStringMap(cfg.Installed),
	}
	s.loadState()
	s.attestation.SetInstalledVersions(s.installed)
	if s.cached != nil {
		s.attestation.SetManifest(s.cached)
	}

	p := NewPoller(cfg.ManifestURL)
	p.OnManifest(s.handlePolledManifest)
	p.OnError(func(err error) {
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
	})
	s.poller = p
	return s, nil
}

func (s *Service) SetHealthCheck(fn func() error) {
	s.applier.OnHealthCheck = fn
	s.healthCheck = fn
}

func (s *Service) Start(ctx context.Context) {
	s.poller.Start(ctx)
}

func (s *Service) Stop() {
	s.poller.Stop()
}

func (s *Service) CheckNow() {
	s.poller.CheckNow()
}

func (s *Service) Genuineness() GenuinenessAxis {
	return s.attestation.Genuineness()
}

func (s *Service) Status() StatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StatusResponse{
		Installed:       copyStringMap(s.installed),
		LastChecked:     formatTime(s.lastChecked),
		Available:       s.computeAvailableLocked(),
		Settings:        s.settings,
		Genuineness:     s.attestation.Genuineness(),
		ManifestPresent: s.cached != nil,
	}
}

func (s *Service) CachedManifestRaw() ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cachedRaw == nil {
		return nil, false
	}
	out := make([]byte, len(s.cachedRaw))
	copy(out, s.cachedRaw)
	return out, true
}

func (s *Service) GetSettings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

func (s *Service) UpdateSettings(st Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.Channel != "" {
		s.settings.Channel = st.Channel
	}
	s.settings.AutoApplyCritical = st.AutoApplyCritical
	if st.OptOutWarningShown {
		s.settings.OptOutWarningShown = true
	}
	s.persistLocked()
}

// IngestManifest verifies and caches a manifest (used by poller and tests).
func (s *Service) IngestManifest(raw []byte) error {
	m, err := VerifyManifest(raw, s.trust)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachedRaw = make([]byte, len(raw))
	copy(s.cachedRaw, raw)
	s.cached = m
	s.lastChecked = time.Now().UTC()
	s.lastError = ""
	s.attestation.SetManifest(m)
	s.persistLocked()
	s.maybeAutoApplyLocked()
	return nil
}

func (s *Service) Apply(component, version string, userConfirmed bool) (*ApplyResult, error) {
	s.mu.RLock()
	m := s.cached
	settings := s.settings
	installed := s.installed[component]
	s.mu.RUnlock()

	if m == nil {
		return nil, fmt.Errorf("no verified manifest cached")
	}
	entry, ok := m.Components[component]
	if !ok {
		return nil, fmt.Errorf("unknown component %q", component)
	}
	if version != "" && version != entry.Version {
		return nil, fmt.Errorf("requested version %q does not match manifest %q", version, entry.Version)
	}
	if !CanDirectUpgrade(installed, entry.MinimumVersion, entry.Version) {
		return nil, ErrBelowMinimumVersion
	}
	if entry.Critical && settings.AutoApplyCritical {
		// UM-11: auto-apply removes tap gate only; sig/checksum already verified.
	} else if !userConfirmed {
		return nil, fmt.Errorf("user confirmation required")
	}

	target := s.componentTargetPath(component)
	result, err := s.applier.ApplyComponent(component, entry, target)
	if err != nil {
		return nil, err
	}
	if result.Applied {
		s.mu.Lock()
		s.installed[component] = entry.Version
		s.attestation.SetInstalledVersions(s.installed)
		s.persistLocked()
		s.mu.Unlock()
	}
	return result, nil
}

func (s *Service) handlePolledManifest(raw []byte) {
	if err := s.IngestManifest(raw); err != nil {
		log.Printf("[update] manifest rejected: %v", err)
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
	}
}

func (s *Service) maybeAutoApplyLocked() {
	if !s.settings.AutoApplyCritical || s.cached == nil {
		return
	}
	for name, entry := range s.cached.Components {
		if !entry.Critical {
			continue
		}
		installed := s.installed[name]
		if !CanDirectUpgrade(installed, entry.MinimumVersion, entry.Version) {
			continue
		}
		if CompareVersion(installed, entry.Version) >= 0 {
			continue
		}
		go func(comp string, e ComponentEntry) {
			target := s.componentTargetPath(comp)
			result, err := s.applier.ApplyComponent(comp, e, target)
			if err != nil {
				log.Printf("[update] auto-apply %s failed: %v", comp, err)
				return
			}
			if result.Applied {
				s.mu.Lock()
				s.installed[comp] = e.Version
				s.attestation.SetInstalledVersions(s.installed)
				s.persistLocked()
				s.mu.Unlock()
				log.Printf("[update] auto-applied critical component %s@%s", comp, e.Version)
			} else if result.RolledBack {
				log.Printf("[update] auto-apply %s rolled back: %s", comp, result.Message)
			}
		}(name, entry)
	}
}

func (s *Service) computeAvailableLocked() []AvailableUpdate {
	if s.cached == nil {
		return nil
	}
	var out []AvailableUpdate
	for name, entry := range s.cached.Components {
		installed := s.installed[name]
		if installed == "" {
			installed = "0"
		}
		belowMin := CompareVersion(installed, entry.MinimumVersion) < 0
		avail := CompareVersion(installed, entry.Version) < 0
		if !avail && !belowMin {
			continue
		}
		requireConfirm := entry.Critical && !s.settings.AutoApplyCritical
		out = append(out, AvailableUpdate{
			Component:       name,
			Installed:       installed,
			Available:       entry.Version,
			Critical:        entry.Critical,
			BelowMinimum:    belowMin,
			RequiresConfirm: requireConfirm || !entry.Critical,
		})
	}
	return out
}

func (s *Service) componentTargetPath(component string) string {
	switch component {
	case "go_backend":
		return filepath.Join(s.dataDir, "updates", "bin", "go_backend")
	case "flutter_web":
		return filepath.Join(s.dataDir, "updates", "flutter_web")
	case "flutter_native":
		return filepath.Join(s.dataDir, "updates", "flutter_native")
	case "python_keri_driver":
		return filepath.Join(s.dataDir, "updates", "python_keri_driver")
	default:
		return filepath.Join(s.dataDir, "updates", "components", component)
	}
}

func (s *Service) statePath() string {
	return filepath.Join(s.dataDir, "updates", "state.json")
}

func (s *Service) loadState() {
	raw, err := os.ReadFile(s.statePath())
	if err != nil {
		return
	}
	var st struct {
		Settings    Settings          `json:"settings"`
		Installed   map[string]string `json:"installed"`
		CachedRaw   json.RawMessage   `json:"cached_manifest"`
		LastChecked string            `json:"last_checked"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return
	}
	if st.Installed != nil {
		s.installed = st.Installed
	}
	if st.Settings.Channel != "" {
		s.settings = st.Settings
	} else {
		s.settings.AutoApplyCritical = st.Settings.AutoApplyCritical
	}
	if len(st.CachedRaw) > 0 {
		if m, err := VerifyManifest(st.CachedRaw, s.trust); err == nil {
			s.cachedRaw = append([]byte(nil), st.CachedRaw...)
			s.cached = m
		}
	}
	if st.LastChecked != "" {
		if t, err := time.Parse(time.RFC3339, st.LastChecked); err == nil {
			s.lastChecked = t
		}
	}
}

func (s *Service) persistLocked() {
	dir := filepath.Join(s.dataDir, "updates")
	_ = os.MkdirAll(dir, 0755)
	st := struct {
		Settings    Settings          `json:"settings"`
		Installed   map[string]string `json:"installed"`
		CachedRaw   json.RawMessage   `json:"cached_manifest,omitempty"`
		LastChecked string            `json:"last_checked,omitempty"`
	}{
		Settings:    s.settings,
		Installed:   s.installed,
		CachedRaw:   s.cachedRaw,
		LastChecked: formatTime(s.lastChecked),
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(s.statePath(), raw, 0644)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// CurrentPlatform returns the manifest platform key for this host.
func CurrentPlatform() string {
	switch runtime.GOOS {
	case "linux":
		return "linux_amd64"
	case "windows":
		return "windows_amd64"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "darwin_arm64"
		}
		return "darwin_amd64"
	default:
		return runtime.GOOS + "_" + runtime.GOARCH
	}
}