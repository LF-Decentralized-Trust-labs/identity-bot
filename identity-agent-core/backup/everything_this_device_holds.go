package backup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Everything on this device, rather than everything somebody remembered to list.
//
// The collector used to name each file it backed up. That is an ALLOW LIST, and
// an allow list fails silently in the one direction that matters: something new
// appears on the device, nobody adds it here, every backup reports success, and
// the gap is measured on the day of the restore. It also cannot work in
// principle — the core cannot know what databases a build on top of it keeps,
// and it should not have to.
//
// So the default is INCLUDE. This walks the data directory and takes every file
// it finds. What is left out is a short, explicit list, and each exclusion has a
// reason written next to it. Getting an exclusion wrong loses data; forgetting
// to add something new no longer does.
//
// Section names are "file:" plus the path relative to the data directory, always
// with forward slashes so an archive taken on one platform restores on another.

// FileSectionPrefix marks a section that is a file copied verbatim from the
// data directory, restored to the same relative path.
const FileSectionPrefix = "file:"

// skipReason says why a path is not carried, or "" when it is.
//
// Written as one function so the whole policy is readable in one place. Every
// branch names what would go wrong if it were carried.
func skipReason(rel string, info fs.FileInfo) string {
	base := filepath.Base(rel)
	slashed := filepath.ToSlash(rel)

	// Already captured by name, in a form that is consistent rather than a
	// mid-write copy of a live file.
	switch base {
	case "identity.db":
		return "captured as sqlite_identity_db"
	case "login_relationships.json":
		return "captured as login_relationships"
	}
	if slashed == "secureenclave/root_seed.key" {
		// Carried unwrapped as root_seed, deliberately: the on-disk copy may be
		// sealed to this device's hardware, and a restore onto new hardware
		// must not depend on the old device's secure element.
		return "captured as root_seed, unwrapped"
	}

	// SQLite's write-ahead log and shared-memory files are only meaningful
	// beside the exact database they belong to, mid-transaction. Restoring a
	// stale one next to a restored database is worse than not having it.
	if strings.HasSuffix(base, "-wal") || strings.HasSuffix(base, "-shm") ||
		strings.HasSuffix(base, "-journal") {
		return "SQLite transient file, meaningless without its live database"
	}

	// Archives this agent itself wrote. Without this a backup written inside
	// the data directory ends up inside the next backup, and the archive grows
	// without bound every run.
	if strings.HasSuffix(base, ".iab") {
		return "an archive this agent wrote; carrying it would nest backups inside backups"
	}

	// A recovery in progress holds a whole sealed archive, base64 inside a
	// JSON file — so it walks straight past the rule above and nests one
	// archive inside the next at four thirds the size, for as long as the
	// recovery waits out its window.
	//
	// Restoring one would be worse than the size: the file lands in the new
	// device's data directory and the next startup resurrects somebody's stale
	// recovery session from it.
	if strings.HasPrefix(slashed, "recovery_sessions/") {
		return "a recovery in progress; it holds a sealed archive and belongs to this device"
	}

	// Container images and app payloads: large, and re-fetched rather than
	// recovered. The sandbox INDEX is carried separately so a person can see
	// what they had.
	if strings.HasPrefix(slashed, "sandbox/") {
		return "sandbox payload; re-fetched rather than restored, and the index is carried instead"
	}

	// Reproducible by definition.
	if strings.HasPrefix(slashed, "cache/") || base == ".DS_Store" {
		return "regenerated on demand"
	}

	return ""
}

// SkippedFile records something deliberately not carried, so that "nothing else
// was here" and "something was here and we left it" stay distinguishable.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Size   int64  `json:"size_bytes"`
}

// collectEveryOtherFile walks the data directory and carries what is not
// explicitly excluded.
//
// A file that cannot be read fails the backup. Skipping it would produce an
// archive that is short by exactly the thing that was already in trouble, and
// report success.
func (c *Collector) collectEveryOtherFile(bundle *PayloadBundle) ([]SkippedFile, error) {
	if c.DataDir == "" {
		return nil, nil
	}
	var skipped []SkippedFile

	err := filepath.WalkDir(c.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read might hold anything. Refusing to
			// guess is the point of this whole file.
			return fmt.Errorf("read %s: %w", path, err)
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(c.DataDir, path)
		if rerr != nil {
			return fmt.Errorf("locate %s: %w", path, rerr)
		}

		info, ierr := d.Info()
		if ierr != nil {
			return fmt.Errorf("inspect %s: %w", rel, ierr)
		}

		// Symlinks are not followed: the target may sit outside the data
		// directory entirely, and copying it would quietly widen what a backup
		// contains beyond the agent's own storage.
		if info.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
				Reason: "symbolic link; its target is outside this agent's storage", Size: info.Size()})
			return nil
		}
		if !info.Mode().IsRegular() {
			skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
				Reason: "not a regular file", Size: info.Size()})
			return nil
		}

		if reason := skipReason(rel, info); reason != "" {
			skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
				Reason: reason, Size: info.Size()})
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", rel, rerr)
		}
		c.addRawSection(bundle, FileSectionPrefix+filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		return skipped, err
	}
	return skipped, nil
}

// FilePathOfSection returns the relative path a file section restores to, and
// whether the section is a file section at all.
//
// The path is rejected if it escapes the data directory. An archive is opened
// with the owner's own key, so this is not the main line of defence — but a
// restore writes files, and a section name is the one part of an archive that
// becomes a path, so it is checked rather than trusted.
func FilePathOfSection(name string) (string, bool) {
	if !strings.HasPrefix(name, FileSectionPrefix) {
		return "", false
	}
	rel := strings.TrimPrefix(name, FileSectionPrefix)
	if rel == "" {
		return "", false
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	return clean, true
}
