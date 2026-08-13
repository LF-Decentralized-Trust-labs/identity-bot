package backup

import "time"

// What a person can be told about their own backups.
//
// Three separate facts, and until now the agent could only report the first:
//
//	a backup RAN          — a file was produced
//	a backup was VERIFIED — that file was reopened and its contents checked
//	a backup got OFF THIS DEVICE — it reached somewhere losing this machine
//	                        does not reach
//
// Health was computed from the first alone, so an agent whose every destination
// was failing, and whose archives had never been opened by anything, reported
// green. Somebody reading that screen would have concluded they were safe.
//
// These are reported separately rather than blended into one score, because
// "when did you last check it opens" is a question with an answer and a person
// is entitled to it.

// BackupFacts is what the agent knows about its own backups, in the terms
// somebody would ask.
type BackupFacts struct {
	// LastBackupAt is the most recent run that produced an archive.
	LastBackupAt string `json:"last_backup_at,omitempty"`
	// LastVerifiedAt is the most recent archive that was reopened and checked.
	// Empty means no archive has ever been proven to open.
	LastVerifiedAt string `json:"last_verified_at,omitempty"`
	// LastOffDeviceAt is the most recent archive that reached somewhere the
	// loss of this device does not reach. Empty means every archive ever made
	// is on the machine that made it.
	LastOffDeviceAt string `json:"last_off_device_at,omitempty"`
	// Protection says in plain words what is missing, or is empty when nothing is.
	Protection string `json:"protection,omitempty"`
	// Health is green, yellow or red, and accounts for all three facts above.
	Health string `json:"health"`
}

// FactsFrom reads the history and destinations and answers the three questions.
//
// History is newest-first.
func FactsFrom(hist []HistoryEntry, dests []Destination, dataDir string, consecutiveFailures int) BackupFacts {
	f := BackupFacts{Protection: ProtectionOf(dests, dataDir)}

	for _, h := range hist {
		if !h.Success {
			continue
		}
		if f.LastBackupAt == "" {
			f.LastBackupAt = h.Timestamp
		}
		if f.LastVerifiedAt == "" && h.Verified {
			f.LastVerifiedAt = h.Timestamp
		}
		if f.LastOffDeviceAt == "" && h.OffDevice {
			f.LastOffDeviceAt = h.Timestamp
		}
		if f.LastBackupAt != "" && f.LastVerifiedAt != "" && f.LastOffDeviceAt != "" {
			break
		}
	}

	f.Health = healthFrom(f, consecutiveFailures)
	return f
}

// healthFrom grades the three facts together.
//
// Red is reserved for "there is nothing to recover from", which now includes
// the two cases that used to read green: every archive is on the device that
// made it, and no archive has ever been opened. Both mean a person who lost
// this machine would find out, on the day, that they had nothing.
func healthFrom(f BackupFacts, consecutiveFailures int) string {
	if consecutiveFailures >= 3 {
		return "red"
	}
	if f.LastBackupAt == "" {
		return "red"
	}
	// Nothing has ever left this device, so nothing survives losing it.
	if f.LastOffDeviceAt == "" {
		return "red"
	}
	// Something is off-device but nothing has ever been proven to open. Not red
	// — there is an archive, and it very probably works — but nobody has
	// checked, and that is exactly the assumption this whole area exists to
	// stop making.
	if f.LastVerifiedAt == "" {
		return "yellow"
	}

	age := ageOf(f.LastOffDeviceAt)
	switch {
	case age < 0:
		return "yellow" // unparseable timestamp
	case age > 72*time.Hour:
		return "red"
	case age > 24*time.Hour:
		return "yellow"
	}

	// A recent copy that is off-device, and an older proof that archives open,
	// is worth distinguishing from both being current.
	if v := ageOf(f.LastVerifiedAt); v < 0 || v > 7*24*time.Hour {
		return "yellow"
	}
	return "green"
}

// ageOf returns how long ago a timestamp was, or -1 if it cannot be read.
func ageOf(ts string) time.Duration {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return -1
	}
	return time.Since(t)
}
