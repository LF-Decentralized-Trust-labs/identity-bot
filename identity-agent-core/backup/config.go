package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DestinationType identifies where archives are pushed.
type DestinationType string

const (
	DestLocalPath   DestinationType = "local_path"
	DestPairedAgent DestinationType = "paired_agent"
	DestCloudUser   DestinationType = "cloud_user_managed"
	DestCloudHosted DestinationType = "cloud_hosted" // commercial layer stub
)

// Destination describes one backup target.
type Destination struct {
	ID         string          `json:"id"`
	Type       DestinationType `json:"type"`
	Label      string          `json:"label"`
	LocalPath  string          `json:"local_path,omitempty"`
	PairedURL  string          `json:"paired_url,omitempty"`
	PairedRole string          `json:"paired_role,omitempty"` // backup_only
	// Elsewhere is the owner saying this destination is not in the same place
	// as the machine backing up to it.
	//
	// Only a person can answer this. Software knows what KIND of thing a
	// destination is and never where it physically sits, so a paired machine
	// at a relative's house and one on the same desk are identical from here.
	// Left alone it stays false, which counts as "cannot tell" rather than as
	// "here" — the difference being that the owner is asked rather than told.
	Elsewhere     bool   `json:"elsewhere,omitempty"`
	CloudProvider string `json:"cloud_provider,omitempty"`
	CloudBucket   string `json:"cloud_bucket,omitempty"`
	CloudPrefix   string `json:"cloud_prefix,omitempty"`
	CloudEndpoint string `json:"cloud_endpoint,omitempty"`
	CloudRegion   string `json:"cloud_region,omitempty"`
	RemoteURL     string `json:"remote_url,omitempty"`
	CredentialID  string `json:"credential_id,omitempty"`
	IAGated       bool   `json:"ia_gated"` // true = requires working IA to retrieve
	Enabled       bool   `json:"enabled"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	// LastFullAt is when this destination last received an archive that
	// restores on its own.
	//
	// Separate from LastSuccessAt because a delta is a success and is not a
	// recovery point: a destination holding only deltas holds nothing anybody
	// can restore from. Empty on every destination that predates this field,
	// which is correct — none of them is known to hold a full archive, and the
	// safe assumption is the one that sends another.
	LastFullAt      string `json:"last_full_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	LastArchiveSize int64  `json:"last_archive_size,omitempty"`
}

// Config is persisted backup configuration.
type Config struct {
	Enabled           bool          `json:"enabled"`
	DefaultTiers      []string      `json:"default_tiers"`
	Destinations      []Destination `json:"destinations"`
	ScheduleDaily     bool          `json:"schedule_daily"`
	WifiOnlyTier23    bool          `json:"wifi_only_tier23"`
	RecoveryPreset    string        `json:"recovery_preset"` // seed | seed_guardians_or | seed_guardians_and
	RedundancyWarning bool          `json:"redundancy_warning_ack"`
	// SealToPublicKeysB64 are the recovery public keys this agent seals backup
	// keys to — one per owner. Public keys only: an agent holding these can
	// write archives forever and open none of them. For an organisation there
	// is one per signer, and any single one restores the data.
	SealToPublicKeysB64 []string `json:"seal_to_public_keys_b64,omitempty"`

	// Split is who holds a share of this identity's recovery, and how many of
	// them are needed.
	//
	// Stored here because a scheduled backup runs when nobody is present, and
	// the choice has to outlive the screen it was made on. Without it, shares
	// were something a caller could pass to one export and nothing a person
	// could ever set — a mechanism with no way to reach it.
	//
	// Empty means the recovery words alone open this identity's archives,
	// which is what every archive written before this was. It is a real
	// configuration and not a broken one, and the screen says what it costs.
	Split HowTheWayInIsSplit `json:"split,omitempty"`

	// Offer is what this machine will hold for OTHER identities — the other
	// direction of backup entirely. Absent on every existing installation,
	// which decodes to the zero value and therefore to accepting nothing. See
	// Offer for why that default is deliberate.
	Offer Offer `json:"offer"`
}

// HistoryEntry is one backup run.
type HistoryEntry struct {
	ID           string   `json:"id"`
	Timestamp    string   `json:"timestamp"`
	Tiers        []string `json:"tiers"`
	SizeBytes    int      `json:"size_bytes"`
	SnapshotType string   `json:"snapshot_type"`
	Success      bool     `json:"success"`
	DurationMs   int64    `json:"duration_ms"`
	Destinations []string `json:"destinations"`
	Error        string   `json:"error,omitempty"`

	// Verified records that this archive was reopened and its contents checked
	// before it was kept. A run without it succeeded at making a file, which is
	// a different claim.
	Verified bool `json:"verified"`

	// OffDevice records that the archive reached somewhere the loss of this
	// device does not reach. A run without it produced a copy, not a backup.
	OffDevice bool `json:"off_device"`

	// SelfSufficient records that this archive restores on its own. An
	// incremental one does not, so it is not a recovery point no matter how
	// recent it is.
	SelfSufficient bool `json:"self_sufficient"`
}

// StatusResponse is returned by GET /api/backup/status.
type StatusResponse struct {
	Enabled             bool          `json:"enabled"`
	LastBackupAt        string        `json:"last_backup_at,omitempty"`
	Health              string        `json:"health"` // green | yellow | red
	Destinations        []Destination `json:"destinations"`
	RedundancyWarning   string        `json:"redundancy_warning,omitempty"`
	AntiDeadlockWarning string        `json:"anti_deadlock_warning,omitempty"`

	// LastVerifiedAt, LastOffDeviceAt and Protection answer the questions
	// LastBackupAt cannot: whether any archive has ever been proven to open,
	// whether any of them left this device, and what is missing. See BackupFacts.
	LastVerifiedAt  string `json:"last_verified_at,omitempty"`
	LastOffDeviceAt string `json:"last_off_device_at,omitempty"`
	Protection      string `json:"protection,omitempty"`
	// LocalDisaster says what a fire, a burglary or a flood in one place would
	// take, or is empty when something would survive it.
	//
	// On the wire beside Protection rather than folded into it, because they
	// answer different questions — losing a machine, losing a room — and
	// somebody can be fine on the first and ruined on the second. It also
	// carries the reason for a health that would otherwise go yellow with
	// nothing on the wire explaining why, which is the common configuration:
	// a paired machine becomes a destination automatically, and two machines
	// in one room is what most people will have.
	LocalDisaster       string         `json:"local_disaster,omitempty"`
	History             []HistoryEntry `json:"history"`
	ConsecutiveFailures int            `json:"consecutive_failures"`
}

// ConfigStore persists backup config, history, and delta state.
type ConfigStore struct {
	dir string
	mu  sync.RWMutex
}

func NewConfigStore(dataDir string) *ConfigStore {
	return &ConfigStore{dir: dataDir}
}

func (s *ConfigStore) configPath() string {
	return filepath.Join(s.dir, "backup_config.json")
}

func (s *ConfigStore) historyPath() string {
	return filepath.Join(s.dir, "backup_history.json")
}

func (s *ConfigStore) deltaStatePath() string {
	return filepath.Join(s.dir, "backup_delta_state.json")
}

func (s *ConfigStore) LoadDeltaState() (DeltaState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.deltaStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return ResetDeltaState(), nil
		}
		return DeltaState{}, err
	}
	var ds DeltaState
	if err := json.Unmarshal(data, &ds); err != nil {
		return DeltaState{}, err
	}
	if ds.SectionDigests == nil {
		ds.SectionDigests = map[string]string{}
	}
	return ds, nil
}

func (s *ConfigStore) SaveDeltaState(ds DeltaState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ds.SectionDigests == nil {
		ds.SectionDigests = map[string]string{}
	}
	data, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.deltaStatePath(), data, 0600)
}

func DefaultConfig() Config {
	return Config{
		Enabled: false,
		// Everything, which is what a backup is for.
		//
		// This was tier1+tier2, and tier3 is where the sweep lives — the step
		// that takes every file in the data directory rather than the ones
		// somebody remembered to name. So nothing requested it, and a backup
		// carried a hand-written list: the identity database, the login
		// relationships, the root seed, the duress policy. Everything else a
		// running agent holds — three further databases, the DIDComm keys, the
		// assets, the tokens, the workspaces, the certificates — was absent
		// from every archive, and would stay absent for anything added next.
		//
		// The tests that prove the sweep works pass tier3 explicitly, so the
		// safety net was demonstrably correct and demonstrably disconnected.
		//
		// Size is not the reason to leave it off: a real agent's data
		// directory measures in the low megabytes, and the bulk that could
		// grow without bound — sandbox payloads, caches, archives this agent
		// wrote — is excluded by name with a reason beside it.
		DefaultTiers:   []string{TierCritical, TierImportant, TierFull},
		Destinations:   []Destination{},
		ScheduleDaily:  true,
		WifiOnlyTier23: true,
		RecoveryPreset: "seed",
	}
}

func (s *ConfigStore) LoadConfig() (Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *ConfigStore) SaveConfig(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPath(), data, 0600)
}

func (s *ConfigStore) LoadHistory() ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.historyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []HistoryEntry{}, nil
		}
		return nil, err
	}
	var hist []HistoryEntry
	if err := json.Unmarshal(data, &hist); err != nil {
		return nil, err
	}
	return hist, nil
}

func (s *ConfigStore) AppendHistory(entry HistoryEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hist, _ := s.loadHistoryLocked()
	hist = append([]HistoryEntry{entry}, hist...)
	if len(hist) > 30 {
		hist = hist[:30]
	}
	data, err := json.MarshalIndent(hist, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.historyPath(), data, 0600)
}

func (s *ConfigStore) loadHistoryLocked() ([]HistoryEntry, error) {
	data, err := os.ReadFile(s.historyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []HistoryEntry{}, nil
		}
		return nil, err
	}
	var hist []HistoryEntry
	if err := json.Unmarshal(data, &hist); err != nil {
		return nil, err
	}
	return hist, nil
}

func RedundancyWarnings(dests []Destination) string {
	enabled := 0
	for _, d := range dests {
		if d.Enabled {
			enabled++
		}
	}
	if enabled < 2 {
		return "Recommend at least two backup destinations on different devices."
	}
	return ""
}

func AntiDeadlockWarning(dests []Destination) string {
	if len(dests) == 0 {
		return ""
	}
	allGated := true
	for _, d := range dests {
		if d.Enabled && !d.IAGated {
			allGated = false
			break
		}
	}
	if allGated {
		return "Every destination requires a working Identity Agent to retrieve. Add at least one copy on hardware you own."
	}
	return ""
}

func (s *ConfigStore) BuildStatus(cfg Config, hist []HistoryEntry, failures int) StatusResponse {
	// hist[0].Success was the old reading of "last backup", so a single failed
	// run at the top hid every successful one beneath it. FactsFrom scans.
	facts := FactsFrom(hist, cfg.Destinations, s.dir, failures)
	return StatusResponse{
		Enabled:             cfg.Enabled,
		LastBackupAt:        facts.LastBackupAt,
		LastVerifiedAt:      facts.LastVerifiedAt,
		LastOffDeviceAt:     facts.LastOffDeviceAt,
		Protection:          facts.Protection,
		LocalDisaster:       facts.LocalDisaster,
		Health:              facts.Health,
		Destinations:        cfg.Destinations,
		RedundancyWarning:   RedundancyWarnings(cfg.Destinations),
		AntiDeadlockWarning: AntiDeadlockWarning(cfg.Destinations),
		History:             hist,
		ConsecutiveFailures: failures,
	}
}

// UpsertDestination adds or updates a destination by ID.
func UpsertDestination(cfg *Config, dest Destination) {
	for i, d := range cfg.Destinations {
		if d.ID == dest.ID {
			cfg.Destinations[i] = dest
			return
		}
	}
	cfg.Destinations = append(cfg.Destinations, dest)
}

// ValidateDestination returns an error for invalid destination config.
func ValidateDestination(dest Destination) error {
	switch dest.Type {
	case DestLocalPath:
		if dest.LocalPath == "" {
			return fmt.Errorf("local_path destination requires local_path")
		}
	case DestPairedAgent:
		if dest.PairedURL == "" {
			return fmt.Errorf("paired_agent destination requires paired_url")
		}
	case DestCloudUser:
		if dest.CloudProvider == "" {
			return fmt.Errorf("cloud_user_managed destination requires cloud_provider")
		}
		if dest.CredentialID == "" {
			return fmt.Errorf("cloud_user_managed destination requires credential_id")
		}
	case DestCloudHosted:
		return fmt.Errorf("cloud_hosted is a commercial service — not yet available")
	default:
		return nil
	}
	return nil
}
