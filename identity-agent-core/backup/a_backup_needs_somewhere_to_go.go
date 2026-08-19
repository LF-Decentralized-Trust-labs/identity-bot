package backup

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Where a backup goes, and whether that place survives losing this device.
//
// A copy on the device that made it survives a corrupted file and does not
// survive the thing that actually happens — the device is lost, stolen,
// dropped or wiped. So "a backup ran" and "a backup reached somewhere that
// outlives this machine" are different facts, and only the second one is worth
// telling somebody they are safe on.
//
// Everything here answers that one question about a destination.

// Reach describes whether a destination outlives the device writing to it.
//
// Three values rather than two, because the honest answer for a filesystem path
// is often "cannot tell": /mnt/external-drive and /home/me/backups look alike
// and only one of them is a backup. Collapsing that into a boolean means either
// nagging somebody who did the right thing or reassuring somebody who did not.
type Reach int

const (
	// ReachUnknown is a path we cannot classify. Counted as protection, and
	// said out loud, because the person knows what that path is and we do not.
	ReachUnknown Reach = iota
	// ReachThisDeviceOnly is a copy that dies with the device. Never counted.
	ReachThisDeviceOnly
	// ReachSurvivesThisDevice is somewhere the loss of this machine does not reach.
	ReachSurvivesThisDevice
)

// ReachOf classifies one destination relative to the agent's own data directory.
func ReachOf(d Destination, dataDir string) Reach {
	switch d.Type {
	case DestPairedAgent:
		// Another machine entirely. The whole point of it.
		return ReachSurvivesThisDevice
	case DestCloudUser, DestCloudHosted:
		return ReachSurvivesThisDevice
	case DestLocalPath:
		if d.LocalPath == "" {
			return ReachThisDeviceOnly
		}
		if isInside(d.LocalPath, dataDir) {
			return ReachThisDeviceOnly
		}
		return ReachUnknown
	default:
		return ReachUnknown
	}
}

// isInside reports whether path sits within dir.
//
// Compared after resolving both to absolute, cleaned paths, so "./data/../data"
// and a trailing separator do not change the answer. A relative path that
// escapes dir starts with "..", which is the check.
func isInside(path, dir string) bool {
	if dir == "" {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ProtectionOf summarises what the configured destinations actually protect
// against, and returns the empty string when there is nothing to say.
//
// The previous version of this returned nothing at all when there were no
// destinations, so the one situation that most needed saying — a device backing
// up to nowhere — was the only one that stayed silent.
func ProtectionOf(dests []Destination, dataDir string) string {
	enabled := 0
	survives := 0
	unknown := 0
	onDevice := 0
	for _, d := range dests {
		if !d.Enabled {
			continue
		}
		enabled++
		switch ReachOf(d, dataDir) {
		case ReachSurvivesThisDevice:
			survives++
		case ReachUnknown:
			unknown++
		case ReachThisDeviceOnly:
			onDevice++
		}
	}

	switch {
	case enabled == 0:
		return "This device backs up to nowhere. Nothing that happens to it is recoverable. " +
			"Add a destination: another Identity Agent, a drive that is not this one, or a cloud account."
	case survives == 0 && unknown == 0:
		return fmt.Sprintf("Every destination is on this device (%d). A copy here survives a damaged file "+
			"and not a lost, stolen or wiped device. Add somewhere the loss of this machine does not reach.", onDevice)
	case survives == 0 && unknown > 0:
		return "The only destinations are filesystem paths, and we cannot tell whether they are on this " +
			"device. If they are, nothing is recoverable when this device is gone."
	case survives+unknown < 2:
		return "One destination. A second, somewhere the same accident cannot reach, is what makes it a backup " +
			"rather than a copy."
	}
	return ""
}

// destinationsForPairedMachines proposes a destination for each machine this
// identity has adopted.
//
// This is the one topology where a destination already exists and nobody has to
// choose anything: the person owns a second machine, it is already paired, and
// the archive is sealed before it leaves — so the machine holding it holds
// noise. Not offering it would mean a device backing up to nowhere while a
// perfectly good destination sat one table away.
//
// It is a proposal rather than an act: the caller decides whether to adopt
// these, and an existing destination for the same machine is never overwritten,
// so a person who turned one off stays turned off.
func destinationsForPairedMachines(machines []machineDestination, existing []Destination) []Destination {
	have := map[string]bool{}
	for _, d := range existing {
		if d.Type == DestPairedAgent && d.PairedURL != "" {
			have[d.PairedURL] = true
		}
		have[d.ID] = true
	}

	var out []Destination
	for _, m := range machines {
		if m.URL == "" || have[m.URL] {
			continue
		}
		id := "paired:" + m.AID
		if have[id] {
			continue
		}
		label := m.Label
		if label == "" {
			label = "A computer you paired"
		}
		out = append(out, Destination{
			ID:         id,
			Type:       DestPairedAgent,
			Label:      label,
			PairedURL:  m.URL,
			PairedRole: "backup_only",
			// Retrieving from it needs that agent running, which is exactly
			// why it must not be the only destination.
			IAGated: true,
			Enabled: true,
		})
	}
	return out
}

// machineDestination is the little of an adopted machine that backup cares
// about, so this file does not depend on the shape of the store's record.
type machineDestination struct {
	AID   string
	URL   string
	Label string
}

// pushLocalDestination writes the archive to a filesystem path.
//
// Split out so its errors have somewhere to go. Inline, both the MkdirAll and
// the WriteFile results were dropped on the floor.
func (s *Service) pushLocalDestination(d Destination, result *ExportResult) error {
	if d.LocalPath == "" {
		return fmt.Errorf("no path configured")
	}
	if err := os.MkdirAll(d.LocalPath, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", d.LocalPath, err)
	}
	name := fmt.Sprintf("backup-%s-%s.iab", result.SnapshotType,
		time.Now().UTC().Format("20060102-150405"))
	full := filepath.Join(d.LocalPath, name)
	if err := os.WriteFile(full, result.Bytes, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", full, err)
	}
	return nil
}

// noteDestinationResult records what happened to one destination, so a
// persistently failing one is visible without reading logs.
func (s *Service) noteDestinationResult(id string, err error, size int64, wasFull bool) {
	cfg, loadErr := s.ConfigStore.LoadConfig()
	if loadErr != nil {
		return
	}
	for i := range cfg.Destinations {
		if cfg.Destinations[i].ID != id {
			continue
		}
		if err != nil {
			cfg.Destinations[i].LastError = err.Error()
		} else {
			cfg.Destinations[i].LastError = ""
			now := time.Now().UTC().Format(time.RFC3339)
			cfg.Destinations[i].LastSuccessAt = now
			cfg.Destinations[i].LastArchiveSize = size
			// Only a full archive makes this a place somebody could recover
			// from. Recording deltas here would let a destination that has
			// never held a restorable archive look ready.
			if wasFull {
				cfg.Destinations[i].LastFullAt = now
			}
		}
		if saveErr := s.ConfigStore.SaveConfig(cfg); saveErr != nil {
			log.Printf("[backup] could not record the result for destination %s: %v", id, saveErr)
		}
		return
	}
}

// AdoptPairedMachinesAsDestinations gives this agent a destination it already
// has, and returns how many were added.
//
// Called before a backup runs, so a person who pairs a computer does not have
// to know that backup exists as a separate thing to configure. An agent with a
// paired machine and no destination is the gap this closes; an agent with
// neither still has nowhere to go and is told so by ProtectionOf.
func (s *Service) AdoptPairedMachinesAsDestinations() (int, error) {
	if s.Store == nil {
		return 0, nil
	}
	agents, err := s.Store.ListAdoptedAgents()
	if err != nil {
		return 0, fmt.Errorf("list the machines this identity has adopted: %w", err)
	}
	if len(agents) == 0 {
		return 0, nil
	}

	machines := make([]machineDestination, 0, len(agents))
	for _, a := range agents {
		machines = append(machines, machineDestination{
			AID: a.AID, URL: a.URL, Label: a.Label,
		})
	}

	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return 0, err
	}
	proposed := destinationsForPairedMachines(machines, cfg.Destinations)
	if len(proposed) == 0 {
		return 0, nil
	}
	for _, d := range proposed {
		UpsertDestination(&cfg, d)
		log.Printf("[backup] using paired machine %s as a backup destination", d.Label)
	}
	return len(proposed), s.ConfigStore.SaveConfig(cfg)
}
