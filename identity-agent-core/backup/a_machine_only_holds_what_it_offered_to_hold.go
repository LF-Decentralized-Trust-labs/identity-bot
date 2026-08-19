package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Holding somebody else's archive is something a machine OFFERS, not something
// it can be made to do.
//
// This is the other direction of backup. Elsewhere in this package an agent
// pushes its own sealed archive somewhere; here a machine volunteers to be that
// somewhere for other identities. The archive arrives already sealed, so the
// holder can never read it — but "cannot read it" is not the same as "anyone
// may use it", and until now nothing separated the two.
//
// What the receiving path did before:
//
//   - accepted an archive from anybody who could reach the agent, with no
//     record of ever having offered. POST /api/backup/receive is a PUBLIC
//     route, so that is any host that can open a connection.
//   - filed it under whatever identifier the caller supplied, joined straight
//     onto a filesystem path. An identifier of "../../.." resolves upward, so
//     the caller chose the directory as well as the bytes.
//   - never looked at how much room was left, so a machine could be filled by
//     repetition alone.
//
// Three separate things, one shape: the machine had no say in what it held.
// Everything below is that say.
// archiveSuffix is what a stored archive is called. One constant because three
// places have to agree: what we write, what we list, and what we serve back.
const archiveSuffix = ".iab"

// partialSuffix marks an archive still being written.
const partialSuffix = ".partial"

// unattributed is where archives go when nothing recorded whose they were.
//
// Deliberately not a valid identifier, so nothing can push here and Held()
// skips it — it is a place for a person to look, not a destination.
const unattributed = "not-attributed"

type Offer struct {
	// Accepting is whether this machine has volunteered at all. False on every
	// existing installation, which is the point — a machine that never offered
	// must not start holding archives because somebody upgraded it.
	Accepting bool `json:"accepting"`

	// AcceptingNewIdentities can be turned off on its own: somebody already
	// pushing here keeps working, and nobody new is taken on.
	//
	// Separated because collapsing them produces the failure the setting exists
	// to prevent. If turning off new identities also stopped existing deltas,
	// a machine somebody added, was confirmed, and relied on would quietly hold
	// nothing but the first archive.
	AcceptingNewIdentities bool `json:"accepting_new_identities"`

	// ReserveBytes is disk this machine will not fill with other people's
	// archives, however much room appears to be free. Somebody hosting a backup
	// is doing a favour; it must not cost them a working computer.
	ReserveBytes int64 `json:"reserve_bytes"`
}

// DefaultOffer is what a machine that has never been asked holds: nothing, for
// nobody.
func DefaultOffer() Offer {
	return Offer{
		Accepting:              false,
		AcceptingNewIdentities: false,
		ReserveBytes:           5 << 30, // 5 GiB
	}
}

// RefusedToHold is why this machine will not take an archive.
//
// A distinct type because every one of these must reach the pushing agent as a
// refusal it can act on, because an identity that believes it has an off-site
// copy and does not is worse off than one that knows it has none. Silence is
// the failure mode; this is what makes refusal loud.
type RefusedToHold struct {
	Reason string
}

func (e *RefusedToHold) Error() string { return e.Reason }

// AcceptableAID reports whether this is something we are willing to use as a
// directory name.
//
// The check is deliberately narrow rather than clever. A KERI AID is a CESR
// primitive: a one-character code and 43 characters of base64url, no separators
// and no dots. Anything outside that alphabet is not an AID, so there is no
// need to reason about which traversal sequences a filesystem might collapse —
// the characters that make traversal possible are simply not in the set.
//
// Written this way because the alternative is a blocklist, and a blocklist of
// path tricks is a promise to have thought of all of them.
func AcceptableAID(aid string) error {
	const codeAndKey = 44
	if len(aid) != codeAndKey {
		return &RefusedToHold{Reason: fmt.Sprintf(
			"that is not an identifier: an AID is %d characters and this one is %d",
			codeAndKey, len(aid))}
	}
	for i := 0; i < len(aid); i++ {
		c := aid[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return &RefusedToHold{Reason: fmt.Sprintf(
				"that is not an identifier: %q is not a character an AID can contain",
				string(c))}
		}
	}
	return nil
}

// AcceptableArchiveName reports whether this is a name we are willing to open.
//
// Same reasoning as AcceptableAID and the same shape: an allowlist of what a
// name this package produces can contain, rather than a blocklist of tricks. We
// write "20060102-150405.iab" and "20060102-150405-1.iab", so digits, hyphens
// and the .iab suffix are the whole vocabulary. A blocklist would have to
// anticipate every separator every filesystem collapses.
func AcceptableArchiveName(name string) error {
	if !strings.HasSuffix(name, archiveSuffix) || len(name) <= len(archiveSuffix) {
		return &RefusedToHold{Reason: "that is not an archive name"}
	}
	for i := 0; i < len(name)-len(archiveSuffix); i++ {
		c := name[i]
		if (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return &RefusedToHold{Reason: "that is not an archive name"}
	}
	return nil
}

// MayAccept decides whether an archive for this identity can be taken, and says
// why not in words the far end can show somebody.
//
// alreadyHeld reports whether this machine is already holding archives for the
// identity, which is what separates "we are not taking anyone new" from "we are
// not taking anything at all".
func (o Offer) MayAccept(aid string, alreadyHeld bool) error {
	if err := AcceptableAID(aid); err != nil {
		return err
	}
	if !o.Accepting {
		return &RefusedToHold{Reason: "this machine does not hold archives for " +
			"other identities. Somebody at it has to offer that first"}
	}
	if !alreadyHeld && !o.AcceptingNewIdentities {
		// Refused at the moment somebody asks, not silently later. An identity
		// told no here can go and find a destination that will say yes.
		return &RefusedToHold{Reason: "this machine is not taking on new " +
			"identities at the moment. The ones it already holds are unaffected"}
	}
	return nil
}

// RoomFor reports whether an archive of this size can be stored without eating
// into the reserve.
//
// Refusing an archive that will not fit is not the harsh option. The harsh
// option is accepting it, failing partway, and leaving a destination that
// reports success and holds a truncated file.
func (o Offer) RoomFor(dir string, size int64) error {
	free, err := freeBytes(dir)
	if err != nil {
		// Could not ask the filesystem. Accepting is the safer direction here:
		// refusing every archive because a stat failed would turn an unreadable
		// disk into an outage for everyone pointed at this machine.
		return nil
	}
	if free-size < o.ReserveBytes {
		return &RefusedToHold{Reason: fmt.Sprintf(
			"this machine is full. It has %s free and keeps %s in reserve, so a "+
				"%s archive does not fit. Your earlier archives are untouched",
			human(free), human(o.ReserveBytes), human(size))}
	}
	return nil
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// HeldFor is what this machine holds for one identity.
//
// Metadata and nothing else, and that is the design rather than an omission.
// Whoever owns the hardware needs to manage disk, notice a backup that stopped
// arriving, and decide what to remove. They must never be able to read any of
// it.
type HeldFor struct {
	IdentityAID string `json:"identity_aid"`
	Archives    int    `json:"archives"`
	TotalBytes  int64  `json:"total_bytes"`
	// LastArrivedAt is what makes a stalled backup visible. An identity that
	// stopped pushing three months ago looks exactly like a healthy one if all
	// you show is a count.
	LastArrivedAt string `json:"last_arrived_at,omitempty"`
}

// Unattributed is what this machine holds that names no identity.
//
// Archives written before a push had to say who it was from cannot be
// attributed — the sender is exactly what was missing. They are still
// somebody's off-site copy, so they are counted and reported, separately from
// the identities, and never as one.
type Unattributed struct {
	Archives      int    `json:"archives"`
	TotalBytes    int64  `json:"total_bytes"`
	LastArrivedAt string `json:"last_arrived_at,omitempty"`
	// Where they are, because acting on them means going and looking.
	Directory string `json:"directory,omitempty"`
}

// UnattributedArchives reports what is held that belongs to nobody nameable.
//
// Separate from Held because it is a different kind of answer. Held returns
// identities, and this is the pile that has no identity — folding it in would
// mean inventing an identifier for it, which is the one thing that cannot be
// done honestly here.
func (s *Service) UnattributedArchives() (*Unattributed, error) {
	dir := filepath.Join(s.DataDir, "backup_receive", unattributed)
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	u := &Unattributed{Directory: dir}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), archiveSuffix) {
			continue
		}
		info, ierr := f.Info()
		if ierr != nil {
			continue
		}
		u.Archives++
		u.TotalBytes += info.Size()
		if at := info.ModTime().UTC().Format(time.RFC3339); at > u.LastArrivedAt {
			u.LastArrivedAt = at
		}
	}
	if u.Archives == 0 {
		return nil, nil
	}
	return u, nil
}

// Held lists everything this machine is holding, for every identity.
//
// The route that existed took an AID and listed that identity's archives, so
// you could only ask about somebody you already knew of. Nothing could answer
// "what is this machine holding", which is the one question the person who owns
// the hardware actually has — and a household has more identities than
// always-on computers, so more than one is the normal case rather than an edge.
func (s *Service) Held() ([]HeldFor, error) {
	root := filepath.Join(s.DataDir, "backup_receive")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []HeldFor{}, nil
		}
		return nil, err
	}

	held := make([]HeldFor, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Anything that is not a well-formed AID is skipped rather than
		// reported. A directory with a name like that can only predate the
		// check above, and listing it would put an attacker's chosen string on
		// somebody's screen.
		if AcceptableAID(e.Name()) != nil {
			continue
		}
		one := HeldFor{IdentityAID: e.Name()}
		files, ferr := os.ReadDir(filepath.Join(root, e.Name()))
		if ferr != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".iab") {
				continue
			}
			info, ierr := f.Info()
			if ierr != nil {
				continue
			}
			one.Archives++
			one.TotalBytes += info.Size()
			at := info.ModTime().UTC().Format(time.RFC3339)
			if at > one.LastArrivedAt {
				one.LastArrivedAt = at
			}
		}
		if one.Archives > 0 {
			held = append(held, one)
		}
	}
	sort.Slice(held, func(i, j int) bool {
		return held[i].IdentityAID < held[j].IdentityAID
	})
	return held, nil
}

// StopHoldingFor removes everything this machine holds for one identity.
//
// Deliberate and named, never automatic. Evicting somebody's only backup to
// make room is not a decision a machine gets to take on its own, so nothing in
// this package calls this — it exists for a person who chose it.
//
// The caller is responsible for telling that identity's agent, and that is the
// part that matters: an identity which thinks it has a destination and does not
// is in the worst position of the three.
func (s *Service) StopHoldingFor(aid string) error {
	if err := AcceptableAID(aid); err != nil {
		return err
	}
	dir := filepath.Join(s.DataDir, "backup_receive", aid)
	// Confirmed to be where we think it is before anything is deleted. The
	// check above already makes traversal impossible; this is the second lock
	// on a door that removes data recursively.
	root := filepath.Join(s.DataDir, "backup_receive")
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel != aid {
		return &RefusedToHold{Reason: "that is not somewhere this machine keeps archives"}
	}
	return os.RemoveAll(dir)
}

// AcceptableExportName reports whether this is a name we will write an archive
// under.
//
// Same reasoning as the two above: an allowlist of what a name may contain
// rather than a blocklist of what it may not. Export names are chosen by
// people, so letters are allowed where the received-archive names are pure
// timestamps — but nothing that can traverse, and nothing hidden.
func AcceptableExportName(name string) error {
	if !strings.HasSuffix(name, archiveSuffix) || len(name) <= len(archiveSuffix) {
		return &RefusedToHold{Reason: "an archive is named with a .iab ending"}
	}
	if strings.HasPrefix(name, ".") {
		return &RefusedToHold{Reason: "an archive is not named with a leading dot"}
	}
	for i := 0; i < len(name)-len(archiveSuffix); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return &RefusedToHold{Reason: "an archive name holds letters, digits, hyphens and underscores"}
		}
	}
	return nil
}
