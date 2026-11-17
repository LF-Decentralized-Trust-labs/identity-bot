package backup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"identity-agent-core/activitylog"
	"identity-agent-core/atomicfile"
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
//
// Names are compared in lower case: the file systems of macOS and Windows do
// not tell Sandbox.DB from sandbox.db, so neither does this list.
func skipReason(rel string) string {
	base := strings.ToLower(filepath.Base(rel))
	slashed := strings.ToLower(filepath.ToSlash(rel))

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

	// A write in progress, or a copy left by one that stopped part way. It is
	// a whole or partial duplicate of whatever was being written beside it,
	// which is carried in its own right, and some of what is written that way
	// is private key material: a holding in shares_held, the messaging keys.
	if atomicfile.IsTemp(base) {
		return "a write in progress, or a copy left by one that stopped; the file it was writing is carried itself"
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
	if strings.HasPrefix(slashed, "local-owner-secret") {
		// What makes a request from this computer the owner's, for one start of
		// this core on this computer. A new one is chosen at every start, so a
		// copy is useless after a restore and a disclosure while it travels.
		// HasPrefix also covers the .tmp it is written through.
		return "belongs to one start of the core on this computer"
	}
	if strings.HasPrefix(slashed, "mcp_tokens.json") {
		// The AI agents' bearer tokens, stored hashed, not carried for the same
		// reason bodies and controller grants are not: a restore must not bring
		// back a token revoked after the archive was made. Tokens are minted
		// again after a restore, by the owner provisioning each agent.
		return "which tokens may act is decided after a restore, not restored"
	}
	if strings.HasPrefix(slashed, "agent_bodies.json") {
		// WHICH MACHINES MAY SPEAK AS THIS IDENTITY'S AI AGENTS, not carried,
		// for the same reason controller grants are not: a restore must not
		// bring back a body that was removed after the archive was made. A body
		// is re-enrolled after a restore, by a person comparing its words again.
		return "which machines are AI agents' bodies is decided after a restore, not restored"
	}
	if strings.HasPrefix(slashed, "controller_grants.json") {
		// WHICH MACHINES MAY ACT FOR THIS IDENTITY, deliberately not carried.
		//
		// HasPrefix rather than equality, matching the machine-key rule below,
		// because save() writes controller_grants.json.tmp and renames over the
		// real file. A walk that lands inside that window would otherwise carry
		// a full copy of the grant list. Restoring one could not re-authorise
		// anything — load() reads only the real name — but it would put every
		// machine that may act for this identity into an archive, which is the
		// disclosure this rule exists to prevent.
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
		// Restoring onto a fresh installation therefore leaves it with no
		// controllers, and each machine must be granted again. That is the right
		// cost: after a restore, which machines may act is exactly the question
		// an owner should be asked rather than have answered from a file.
		//
		// Restoring in place leaves the grants already on disk untouched, because
		// a restore writes the sections an archive names and deletes nothing.
		// Those are the current grants rather than a resurrected past, so there
		// is nothing to reconcile — but it does mean this rule bounds what an
		// archive can carry, not what a restore ends up holding.
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

	if slashed == "redeemed_ceremony_invites.json" || slashed == "redeemed_ceremony_invites.json.tmp" {
		// An ownership change this device is part of, kept so a restart does not
		// strand it. The codes in it open one ceremony of one organisation, for a
		// few days; an archive that carried them would hand that to whoever holds
		// the archive, and a restore onto another device would resurrect a change
		// that device never agreed to.
		return "not carried: an ownership change in progress belongs to the device that agreed to it"
	}

	if slashed == "backup_config.json" || strings.HasPrefix(slashed, "backup_config.json.") ||
		slashed == "backup_history.json" || slashed == "backup_newest_seen.json" || slashed == "backup_delta_state.json" ||
		strings.HasPrefix(slashed, "backup/credentials_") {
		// WHERE THIS MACHINE BACKS UP TO, and the keys that open the sign-ins
		// to them. They belong to the machine, not to the identity, like
		// machine_key.sep above.
		//
		// The credential files are sealed by a key that is itself wrapped by
		// this machine's hardware. Restored onto another machine the key cannot
		// be opened, loadOrCreateMasterKey refuses to make a new one beside
		// files it cannot read, and the credential store fails for good: every
		// backup from the new machine stops and signing in to Drive again
		// fails. The destinations and the history and delta state that describe
		// them are the same: a restored delta state would tell the new machine
		// its destinations already hold sections they have never seen.
		//
		// A restore therefore keeps the destinations the new machine already
		// has, and the person signs in to Drive again on it.
		return "not carried: where this machine backs up to, and the keys to its sign-ins, belong to this machine"
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

	// Container images and programs an older build kept for its
	// sandboxed apps. Large, and nothing this build runs reads them.
	if strings.HasPrefix(slashed, "sandbox/") {
		return "container images and programs an older build kept for its sandboxed apps; nothing restores them"
	}

	// The activity log's old name. A build with this rule renames sandbox.db
	// to activity.db when it opens the log, so a sandbox.db beside an
	// activity.db is a stale copy an older build left, after a downgrade and
	// an upgrade again. Carried, it would be restored over the log, which is
	// carried in its own right as activity.db. The sweep carries a sandbox.db
	// that has no activity.db beside it (collectEveryOtherFile), because then
	// it is the only copy of the log: the rename was refused, for one.
	if slashed == activitylog.LegacyFileName {
		return "the activity log's old name, left by an older build; the log is carried as activity.db"
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

	// Whether the log is here under its own name. Without it, a sandbox.db is
	// the only copy of the log (its rename was refused, or never ran), so it
	// is carried, and a restore writes it as activity.db.
	_, lerr := os.Lstat(filepath.Join(c.DataDir, activitylog.FileName))
	logIsHere := lerr == nil

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
		reason := skipReason(rel)
		if reason != "" && isTheLegacyLog(rel) && !logIsHere {
			reason = ""
		}
		if reason != "" {
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
	// IsLocal rather than a check for "..": on Windows it also refuses a
	// device name such as NUL or CON, which is no file at all, and a colon,
	// which names a drive or an alternate stream of another file.
	// "." is the data directory itself, which no file restores to.
	clean := filepath.Clean(filepath.FromSlash(rel))
	if !filepath.IsLocal(clean) || clean == "." {
		return "", false
	}
	return clean, true
}

// NotRestored says why a restore leaves rel alone, or "" when it puts it
// back: whatever the backup deliberately leaves out is never written by a
// restore either, whatever an archive carries. One list for both, skipReason.
//
// The one exception is the activity log's old name. A backup never carries a
// sandbox.db, but an archive an older build wrote carries the log under that
// name, and FilesToRestore decides where it goes.
func NotRestored(rel string) string {
	if isTheLegacyLog(rel) {
		return ""
	}
	return skipReason(rel)
}

// sameFile is how two paths under the data directory are compared: the file
// systems of macOS and Windows do not tell case apart.
func sameFile(rel string) string {
	return strings.ToLower(filepath.ToSlash(filepath.Clean(rel)))
}

// isTheLegacyLog reports whether rel names the activity log's old name.
func isTheLegacyLog(rel string) bool { return sameFile(rel) == activitylog.LegacyFileName }

// FileToRestore is a file section a restore writes, at Rel under the data
// directory.
type FileToRestore struct {
	Rel string
	Raw []byte
}

// TheLogIsCarriedUnderItsOwnName is why a restore leaves out an archive's
// sandbox.db when the same archive carries activity.db.
const TheLogIsCarriedUnderItsOwnName = "the activity log's old name, in an archive that also carries the log as activity.db; it is a stale copy, and restoring it would replace the log"

// FilesToRestore resolves an archive's sections into the files a restore
// writes, sorted by path, and the file sections it leaves out with the reason
// for each. A file section whose name is not a path inside the data directory,
// or two that name the same file (compared with forward slashes and in lower
// case, as macOS and Windows compare them), refuse the whole archive, before
// anything is written.
//
// An archive an older build wrote carries the activity log as sandbox.db, and
// it is restored as activity.db, the log's own name, so it replaces the log
// rather than sitting beside it unread. Only when the archive does not also
// carry activity.db: then sandbox.db is a stale copy an older build left
// beside the log, and since the files are written in path order it would be
// written last, over the real log. So it is left out, and said.
func FilesToRestore(sections map[string][]byte) ([]FileToRestore, []SkippedFile, error) {
	type section struct {
		rel string
		raw []byte
	}
	var resolved []section
	named := map[string]string{}
	for name, raw := range sections {
		rel, ok := FilePathOfSection(name)
		if !ok {
			if strings.HasPrefix(name, FileSectionPrefix) {
				return nil, nil, fmt.Errorf("this archive names a file section with an unusable path: %q", name)
			}
			continue
		}
		if other, dup := named[sameFile(rel)]; dup {
			return nil, nil, fmt.Errorf("this archive names one file twice: %q and %q", other, name)
		}
		named[sameFile(rel)] = name
		resolved = append(resolved, section{rel: rel, raw: raw})
	}
	_, carriesTheLog := named[activitylog.FileName]

	var files []FileToRestore
	var left []SkippedFile
	for _, s := range resolved {
		rel, raw := s.rel, s.raw
		if isTheLegacyLog(rel) {
			if carriesTheLog {
				left = append(left, SkippedFile{Path: activitylog.LegacyFileName,
					Reason: TheLogIsCarriedUnderItsOwnName, Size: int64(len(raw))})
				continue
			}
			rel = activitylog.FileName
		}
		if why := NotRestored(rel); why != "" {
			left = append(left, SkippedFile{Path: filepath.ToSlash(rel), Reason: why, Size: int64(len(raw))})
			continue
		}
		files = append(files, FileToRestore{Rel: rel, Raw: raw})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
	sort.Slice(left, func(i, j int) bool { return left[i].Path < left[j].Path })
	return files, left, nil
}
