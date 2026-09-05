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
func skipReason(rel string) string {
	base := filepath.Base(rel)
	slashed := filepath.ToSlash(rel)

	// This agent's own working directories, where a backup or a restore
	// unpacks a plaintext copy of a database while it works.
	//
	// Named explicitly rather than left to the identity.db rule below. That
	// rule matches on basename, so a copy sitting inside one of these was
	// skipped as "already captured" — which is true of the real database and
	// false of the copy, and meant an abandoned plaintext duplicate of the
	// whole identity store was neither carried nor reported.
	if strings.HasPrefix(slashed, snapshotPrefix) || strings.HasPrefix(slashed, restoringPrefix) ||
		strings.Contains(slashed, "/"+snapshotPrefix) || strings.Contains(slashed, "/"+restoringPrefix) {
		return "this agent's own working copy, being written right now or left by a run that died"
	}

	// Already captured by name, in a form that is consistent rather than a
	// mid-write copy of a live file.
	//
	// Anchored to the top of the data directory. Matching identity.db
	// anywhere means a build on top of this core that keeps its own
	// identity.db in a subdirectory has it silently dropped from every
	// backup — an allow-list failure of exactly the kind this file exists to
	// remove.
	switch slashed {
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
	if slashed == "controller_grants.json" {
		// WHICH MACHINES MAY ACT FOR THIS IDENTITY, deliberately not carried.
		//
		// A backup is of an identity, never of an installation, per ADR-039.
		//
		// A grant is a statement about the machines that exist right now, and a
		// backup is a statement about a moment that has passed. Restoring one
		// into the other is the single way a revoked controller comes back: take
		// a backup, revoke a machine, restore the backup, and the machine is
		// authorised again with nothing having said so.
		//
		// Revocation is otherwise complete, because the Identity Agent holding
		// the grant is the only party that consults it — there is no published
		// list and nobody else to tell. So this is the one place it could leak,
		// and closing it here is cheaper than reconciling a restored list against
		// anything.
		//
		// The cost is that a restored Identity Agent has no controllers and each
		// machine must be granted again. That is the right cost: after a restore,
		// which machines may act is exactly the question an owner should be asked
		// rather than have answered from a file.
		return "not carried: which machines may act is decided now, not restored"
	}
	if strings.HasPrefix(slashed, "secureenclave/machine_key.sep") {
		// THIS MACHINE'S OWN KEY, and it belongs to the machine rather than to
		// the identity. It is wrapped by a secure element that exists in exactly
		// one processor, so a copy is useless anywhere else — carrying it would
		// put an unusable file in every archive and, worse, restore it onto new
		// hardware where the Identity Agent would find a key it can never use.
		//
		// Nothing is lost by leaving it. A machine mints its own on first run,
		// and its authority comes from a grant the owner makes, not from the key
		// surviving a move. The right thing after a restore is to be granted
		// again as the new machine that it is.
		return "not carried: this machine's own key, usable only in this processor"
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
		if err != nil && os.IsNotExist(err) {
			// A directory that vanished mid-walk, for the same reasons as a
			// file below. There is nothing left to carry or to report a size
			// for.
			return nil
		}
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

		// Whether to carry it is decided from the path alone, BEFORE anything
		// touches the file.
		//
		// The excluded set is mostly transient — a write-ahead log, a shared
		// memory file, a journal — and those come and go continuously while an
		// agent is running. Stating them first meant a backup taken during
		// ordinary use could fail with "no such file" for a file it was about
		// to exclude anyway. Found by running a collection against a copy of a
		// real agent's data directory, which is the first thing here that ever
		// had live sidecars in it.
		if reason := skipReason(rel); reason != "" {
			skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
				Reason: reason, Size: sizeIfStillThere(d)})
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			if os.IsNotExist(ierr) {
				// Gone between being listed and being read. Recorded rather
				// than ignored, and rather than failing the whole backup: a
				// file that no longer exists cannot be carried, and saying so
				// is the honest outcome.
				skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
					Reason: "removed while the backup was running"})
				return nil
			}
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

		// A database is copied through SQLite, never read as bytes.
		//
		// Reading one as a file is what produced the fault this whole change
		// began with: they run in write-ahead-log mode, so the file on disk is
		// short by every transaction since the last checkpoint — on a young
		// database, all of them — and the archive is valid and empty. The
		// sidecar that holds those transactions is excluded above, correctly,
		// because it is meaningless apart from its database.
		//
		// Recognised by its header rather than its name, and copied without
		// anybody registering it, because a registry is an allow list wearing
		// a different hat: somebody adds a database, nobody registers it,
		// every backup succeeds, and the gap surfaces on the day of the
		// restore.
		if LooksLikeADatabase(path) {
			data, derr := snapshotAnotherDatabase(path, c.DataDir)
			if derr != nil {
				return derr
			}
			c.addRawSection(bundle, FileSectionPrefix+filepath.ToSlash(rel), data)
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				skipped = append(skipped, SkippedFile{Path: filepath.ToSlash(rel),
					Reason: "removed while the backup was running"})
				return nil
			}
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

// sizeIfStillThere reports a file's size, or zero if it has already gone.
// Only used for recording what was skipped, where an unknown size is a far
// better outcome than failing a backup.
func sizeIfStillThere(d fs.DirEntry) int64 {
	info, err := d.Info()
	if err != nil {
		return 0
	}
	return info.Size()
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
