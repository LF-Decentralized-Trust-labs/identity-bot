package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/store"

	"github.com/google/uuid"
)

// Service orchestrates backup export, push, and status.
type Service struct {
	DataDir     string
	Store       store.Store
	ConfigStore *ConfigStore
	Pusher      *PairedPusher
	Scheduler   *Scheduler
	failures    int
}

func NewService(dataDir string, st store.Store) *Service {
	cs := NewConfigStore(dataDir)
	svc := &Service{
		DataDir:     dataDir,
		Store:       st,
		ConfigStore: cs,
		Pusher:      NewPairedPusher(),
	}
	svc.Scheduler = NewScheduler(svc)
	return svc
}

func (s *Service) Collector() *Collector {
	return &Collector{DataDir: s.DataDir, Store: s.Store}
}

// Export writes an encrypted archive to disk and optionally pushes to destinations.
func (s *Service) Export(mnemonic, passphrase, destPath string, tiers []string) (*ExportResult, error) {
	start := time.Now()
	collector := s.Collector()
	opts := DefaultCollectOptions(tiers)
	if len(tiers) == 0 {
		cfg, _ := s.ConfigStore.LoadConfig()
		opts.Tiers = cfg.DefaultTiers
	}
	// Tier 1 always included
	hasTier1 := false
	for _, t := range opts.Tiers {
		if t == TierCritical {
			hasTier1 = true
		}
	}
	if !hasTier1 {
		opts.Tiers = append([]string{TierCritical}, opts.Tiers...)
	}

	result, err := collector.CreateArchive(opts, ExportRequest{
		Mnemonic:   mnemonic,
		Passphrase: passphrase,
		Tiers:      opts.Tiers,
	})
	if err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	if destPath != "" {
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, err
		}
		if err := os.WriteFile(destPath, result.Bytes, 0600); err != nil {
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, err
		}
	}

	cfg, _ := s.ConfigStore.LoadConfig()
	destIDs := []string{}
	for _, d := range cfg.Destinations {
		if !d.Enabled {
			continue
		}
		switch d.Type {
		case DestLocalPath:
			path := d.LocalPath
			if path == "" {
				continue
			}
			name := fmt.Sprintf("backup-%s.iab", time.Now().UTC().Format("20060102-150405"))
			full := filepath.Join(path, name)
			if err := os.MkdirAll(path, 0755); err == nil {
				_ = os.WriteFile(full, result.Bytes, 0600)
				destIDs = append(destIDs, d.ID)
			}
		case DestPairedAgent:
			if err := s.Pusher.Push(d.PairedURL, result.Bytes); err == nil {
				destIDs = append(destIDs, d.ID)
			}
		}
	}

	s.recordSuccess(opts.Tiers, result.Size, destIDs, time.Since(start))
	s.failures = 0
	return result, nil
}

func (s *Service) recordSuccess(tiers []string, size int, dests []string, dur time.Duration) {
	_ = s.ConfigStore.AppendHistory(HistoryEntry{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Tiers:        tiers,
		SizeBytes:    size,
		SnapshotType: "full",
		Success:      true,
		DurationMs:   dur.Milliseconds(),
		Destinations: dests,
	})
}

func (s *Service) recordFailure(tiers []string, err error, dur time.Duration) {
	s.failures++
	_ = s.ConfigStore.AppendHistory(HistoryEntry{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Tiers:      tiers,
		Success:    false,
		DurationMs: dur.Milliseconds(),
		Error:      err.Error(),
	})
}

// Status returns current backup health.
func (s *Service) Status() (StatusResponse, error) {
	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return StatusResponse{}, err
	}
	hist, err := s.ConfigStore.LoadHistory()
	if err != nil {
		return StatusResponse{}, err
	}
	return s.ConfigStore.BuildStatus(cfg, hist, s.failures), nil
}

// SaveConfig persists configuration.
func (s *Service) SaveConfig(cfg Config) error {
	return s.ConfigStore.SaveConfig(cfg)
}

// LoadConfig returns current configuration.
func (s *Service) LoadConfig() (Config, error) {
	return s.ConfigStore.LoadConfig()
}

// ReceiveArchive stores an opaque archive on a backup-only device (ACT2 boundary).
func (s *Service) ReceiveArchive(identityAID string, data []byte) (string, error) {
	dir := filepath.Join(s.DataDir, "backup_receive", identityAID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s.iab", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}

// ListReceived returns opaque archive paths for a paired identity (no decrypt).
func (s *Service) ListReceived(identityAID string) ([]string, error) {
	dir := filepath.Join(s.DataDir, "backup_receive", identityAID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}