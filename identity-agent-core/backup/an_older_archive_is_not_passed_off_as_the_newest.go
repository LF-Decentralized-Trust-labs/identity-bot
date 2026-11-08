package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"identity-agent-core/internal/atomicfile"
)

// An older archive put back under a later name.
//
// A destination picks "the newest" archive by its name, and anyone who holds the
// account can upload an old, genuine archive under a name that sorts last. The
// archive opens, it is authentic, and restoring it rolls the identity back to
// the day it was made — undoing every rotation and revocation since.
//
// The name is not to be believed; the archive's own creation time is. It sits in
// the manifest the archive's authentication covers, so once an archive has been
// opened that time was written by whoever made it. This file says what to do
// with it: show it, and warn when it is not the newest this device knows of, or
// when the name claims a time the archive does not.

// freshnessSlack is how far the time in a file's name may differ from the
// archive's own before the name is called false. The name is stamped at upload
// and the archive a little earlier, as it is built.
const freshnessSlack = 10 * time.Minute

// Every name this agent gives an archive carries its time: "backup-full-<time>.iab"
// in a destination or a local folder, "<time>[-n].iab" on a machine holding it
// for someone else. The same rule reads all of them.
var archiveNameTime = regexp.MustCompile(`(?:^|[/\\])(?:backup-(?:full|delta)-)?(\d{8}-\d{6})(?:-\d+)?\.iab$`)

// ArchiveFreshnessWarnings returns what a person restoring from an archive
// should be told about when it was made. createdAt is the archive's own,
// objectKey the name it had in the destination (empty if it did not come from
// one), newestSeen the latest creation time this device has made or opened (zero
// if none).
func ArchiveFreshnessWarnings(createdAt, objectKey string, newestSeen time.Time) []string {
	made, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return []string{"This backup does not say when it was made, so it cannot be told from an older one."}
	}
	var out []string
	if !newestSeen.IsZero() && made.Before(newestSeen.Add(-freshnessSlack)) {
		out = append(out, fmt.Sprintf(
			"This is not the newest backup this device has seen: it was made %s, and this device has made or opened one from %s. "+
				"If you did not expect this, someone with access to where it was stored may have put an older copy back; "+
				"restoring it undoes everything since.",
			made.UTC().Format(time.RFC1123), newestSeen.UTC().Format(time.RFC1123)))
	}
	if m := archiveNameTime.FindStringSubmatch(objectKey); m != nil {
		if named, perr := time.Parse("20060102-150405", m[1]); perr == nil {
			if d := named.Sub(made); d > freshnessSlack || d < -freshnessSlack {
				out = append(out, fmt.Sprintf(
					"The file is named as if it was made %s, but the backup inside was made %s. "+
						"An older backup may have been renamed to look like the newest.",
					named.UTC().Format(time.RFC1123), made.UTC().Format(time.RFC1123)))
			}
		}
	}
	return out
}

func (s *ConfigStore) newestSeenPath() string {
	return filepath.Join(s.dir, "backup_newest_seen.json")
}

// NewestArchiveSeen is the latest creation time of any archive this device made
// (its history) or has opened for a restore. Zero when it has seen none, as a
// new machine has not.
func (s *ConfigStore) NewestArchiveSeen() time.Time {
	var newest time.Time
	if hist, err := s.LoadHistory(); err == nil {
		for _, h := range hist {
			if t, perr := time.Parse(time.RFC3339, h.Timestamp); perr == nil && h.Success && t.After(newest) {
				newest = t
			}
		}
	}
	s.mu.RLock()
	data, err := os.ReadFile(s.newestSeenPath())
	s.mu.RUnlock()
	if err == nil {
		var rec struct {
			CreatedAt string `json:"created_at"`
		}
		if json.Unmarshal(data, &rec) == nil {
			if t, perr := time.Parse(time.RFC3339, rec.CreatedAt); perr == nil && t.After(newest) {
				newest = t
			}
		}
	}
	return newest
}

// NoteArchiveSeen remembers that an archive made at createdAt was opened here,
// if it is later than any remembered, so an older one is noticed afterwards.
func (s *ConfigStore) NoteArchiveSeen(createdAt string) {
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil || !t.After(s.NewestArchiveSeen()) {
		return
	}
	data, _ := json.Marshal(map[string]string{"created_at": t.UTC().Format(time.RFC3339)})
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = atomicfile.Write(s.newestSeenPath(), data, 0o600)
}
