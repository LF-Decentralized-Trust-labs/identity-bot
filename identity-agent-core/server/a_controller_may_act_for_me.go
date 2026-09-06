package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"identity-agent-core/iacrypto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// What an identity has agreed somebody's computer may do on its behalf.
//
// A controller is a machine somebody reaches their Identity Agent FROM. It
// holds its own key and is NAMED BY that key — never a delegated identifier,
// because a delegated inception names its parent to anybody who can reach the
// machine, and that publishes the one identifier the design keeps pairwise. So
// what an agent stores about a controller is not a lineage. It is a grant: this
// identity may act for me, at this grade, until this.
//
// See this_machine_as_a_controller.go for what "named by its key" means and what
// it gives up. This comment used to say the controller "founds its own root",
// which the code has not done since a controller became a non-transferable
// identifier — there is no inception event to found.
//
// NOTHING HERE AUTHORISES ANYTHING YET, and that separation is deliberate. This
// records what the owner agreed and answers whether it still stands. What a
// controller may reach when it does stand is a second question with its own
// shape — permitted by default with a named deny list, gated per action on how
// strongly the person was authenticated — and building the two together is how
// a store becomes a permission by accident.
//
// THE OWNER GRANTS, NEVER THE AGENT. The routes below are owner-only, which
// means in practice the device holding the key: an agent that could authorise
// its own controllers could be talked into authorising somebody else's, and the
// person would never be asked. That is the same reason an app driving a
// founding cannot claim its own machine.

// ControllerGrade says what kind of machine this is, which decides only how
// permanent the record is.
//
// Both grades hold their own key and both are named by it. The difference is
// whether the person expects to still be using the machine: one they keep earns
// a durable record they can find and remove, one they borrowed should not leave
// a device on an identity for an afternoon that ended.
type ControllerGrade string

const (
	// GradeEnrolled is a machine somebody keeps. It appears in their devices
	// and lasts until they say otherwise.
	GradeEnrolled ControllerGrade = "enrolled"
	// GradeScoped is a machine somebody borrowed. It expires.
	GradeScoped ControllerGrade = "scoped"
)

// scopedGrantLifetime bounds a borrowed machine when nothing else says.
//
// A borrowed grant is not for a single afternoon. Setting a machine up, working
// across it over several sittings, and coming back to it days later is the
// ordinary shape, and a window that expires under the person mid-use is worse
// than not having the borrowed grade at all — it turns "I am using this for a
// while" into a ceremony they redo every few hours. So it is generous.
//
// The permanent grade (GradeEnrolled) is what a machine somebody KEEPS should
// be, and it never expires. So the two grades are exactly: keep it, which is
// forever, or borrow it, which is a bounded but roomy window. This value is an
// interim — the borrowed default will likely settle shorter (a week is the
// natural resting point) once the permanent path carries the machines meant to
// last — but a short window now only gets in the way of proving anything out.
const scopedGrantLifetime = 30 * 24 * time.Hour

// maxScopedGrantLifetime is the longest a borrowed machine may be given,
// whatever the caller asks for.
//
// Without this, scopedGrantLifetime is only a default, and a caller passing its
// own expiry could grant a library computer a century — which is the borrowed
// grade in name and the permanent one in effect. A bound the caller cannot
// exceed is the only version of "it expires" that means anything.
//
// At least the default, so the default a borrowed grant is given is never
// itself refused by this cap. A machine meant to last past this belongs in the
// permanent grade, which is what "keep it" records.
const maxScopedGrantLifetime = 30 * 24 * time.Hour

// ControllerGrant is one machine's permission to act for this identity.
type ControllerGrant struct {
	// ControllerAID is the machine's own identifier, which IS its public key —
	// the non-transferable form, with no inception event and nothing published.
	// The PRIVATE half is not derivable here — it never leaves that machine,
	// which is what makes revoking this grant enough to stop it. The public half
	// IS read back out of the identifier, in Grant, because an identifier that is
	// a key cannot name a different one.
	//
	// This said "the root the controller founded for itself" until the phrase
	// was withdrawn. It described an earlier design and it kept sending readers
	// to look for an inception that has never existed — the same wording the
	// header of this file already corrects, still standing on the field where a
	// reader actually lands.
	ControllerAID string `json:"controller_aid"`

	// PublicKey is what its requests are checked against. Without it the grant
	// names an identity nothing can recognise, which is most of the point of
	// having granted it.
	PublicKey string `json:"public_key"`

	// Label is what the person will see when they come to remove this. A grant
	// nobody can identify is a grant nobody revokes.
	Label string `json:"label"`

	Grade     ControllerGrade `json:"grade"`
	GrantedAt time.Time       `json:"granted_at"`

	// ExpiresAt is zero for an enrolled machine and set for a borrowed one.
	// Zero means "until the owner says otherwise", never "forever unchecked" —
	// the owner can remove it, which is the only permanence a grant has.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Live reports whether this grant still stands, and says why when it does not.
func (g ControllerGrant) Live(now time.Time) (bool, string) {
	if g.ControllerAID == "" || g.PublicKey == "" {
		return false, "this grant names no identity to act, or no key to check it by"
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return false, "this authorisation was for a machine somebody borrowed, and it has expired"
	}
	return true, ""
}

// controllerGrants is the store. A small file of its own beside the others, so
// adding it changed no existing load path.
type controllerGrants struct {
	dataDir string
}

// grantsLock serialises the read-modify-write of the grants file.
//
// It is package-level and NOT a field, which is deliberate: every accessor
// builds its own controllerGrants value, so a mutex on the struct would be a
// fresh lock per call and would exclude nothing. Two grants arriving together
// would each read the file, each add their own entry to what they read, and the
// second write would drop the first — losing an authorisation, or worse,
// resurrecting one that was concurrently revoked.
//
// One lock for the process rather than one per directory. An agent serves a
// single identity, so there is nothing to contend with, and a global lock that
// is obviously right beats a keyed one that is nearly right.
var grantsLock sync.Mutex

func (s *CoreServer) controllers() *controllerGrants {
	return &controllerGrants{dataDir: s.DataDir}
}

func (c *controllerGrants) path() string {
	return filepath.Join(c.dataDir, "controller_grants.json")
}

// load reads the file. Callers hold the lock.
//
// Read per call rather than cached, so a grant removed by one path is gone for
// every other immediately — a revocation that takes effect on restart is not a
// revocation.
//
// A FILE THAT CANNOT BE READ IS AN ERROR, NEVER AN EMPTY LIST. Those two look
// identical to a caller and are opposites: "this identity has authorised no
// machines" versus "what it authorised could not be read". Collapsing them
// loses the grants permanently, because the next Grant or Revoke writes the
// empty map back over the file — one unreadable read, and three authorised
// machines are gone with nothing said. Not exotic either: save fsyncs nothing,
// so an unclean shutdown can truncate this file.
//
// A missing file is genuinely no grants, and only that case returns empty.
func (c *controllerGrants) load() (map[string]ControllerGrant, error) {
	out := map[string]ControllerGrant{}
	b, err := os.ReadFile(c.path())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the record of which machines may act for this identity "+
			"could not be read, so it was left untouched: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the record of which machines may act for this identity is "+
			"not readable as JSON, so it was left untouched rather than replaced: %w", err)
	}
	return out, nil
}

func (c *controllerGrants) save(all map[string]ControllerGrant) error {
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return err
	}
	tmp := c.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path())
}

// Grant records that a machine may act for this identity.
//
// Replaces any grant for the same identity rather than adding a second: two
// live grants for one controller would mean revoking one and being surprised.
func (c *controllerGrants) Grant(g ControllerGrant, now time.Time) (ControllerGrant, error) {
	g.ControllerAID = strings.TrimSpace(g.ControllerAID)
	g.PublicKey = strings.TrimSpace(g.PublicKey)
	g.Label = strings.TrimSpace(g.Label)

	if g.ControllerAID == "" {
		return ControllerGrant{}, fmt.Errorf("a grant must name the identity it is for")
	}
	if g.PublicKey == "" {
		return ControllerGrant{}, fmt.Errorf(
			"a grant must carry the key its requests are checked against, or it names " +
				"an identity nothing can recognise")
	}
	if g.Label == "" {
		return ControllerGrant{}, fmt.Errorf(
			"a grant must say which machine it is for, or nobody can tell which one to remove")
	}

	// A controller's identifier IS its key, so the two must agree.
	//
	// Without this a grant could record identifier X against key Y, and what got
	// admitted afterwards would be whatever holds Y — while the owner's list, and
	// anything they later revoked, named X. The check needs no network and no
	// stored state: the identifier decodes to the key or it does not.
	named, err := theKeyThisIdentifierNames(g.ControllerAID)
	if err != nil {
		return ControllerGrant{}, fmt.Errorf(
			"%q is not a controller's identifier: a controller is named by its own key, "+
				"which is what lets this be checked without asking anybody: %w",
			g.ControllerAID, err)
	}
	// Decoded by the same rules the identifier was, because the next line
	// compares them. A machine's key is P-256 where an identity's is Ed25519,
	// and reading the identifier as a machine's while reading the key as an
	// identity's makes a correct grant look like a forged one.
	offered, err := iacrypto.KeyFromMachineVerkey(g.PublicKey)
	if err != nil {
		return ControllerGrant{}, fmt.Errorf("the key offered is unusable: %w", err)
	}
	if !bytes.Equal(named, offered) {
		return ControllerGrant{}, fmt.Errorf(
			"this grant names one machine and carries a different machine's key, so what " +
				"it would admit is not what it appears to authorise")
	}
	switch g.Grade {
	case GradeEnrolled:
		// No expiry: a machine somebody keeps lasts until they say otherwise.
		g.ExpiresAt = time.Time{}
	case GradeScoped:
		switch {
		case g.ExpiresAt.IsZero():
			// The default window, clamped to the cap. These two constants are
			// equal today, but lowering the cap below the default without also
			// lowering the default would otherwise hand out a grant longer than
			// the cap allows, silently, because this branch is reached instead of
			// the cap check below. Clamping enforces the "at least the default"
			// invariant the cap's own comment states, rather than trusting it.
			window := scopedGrantLifetime
			if window > maxScopedGrantLifetime {
				window = maxScopedGrantLifetime
			}
			g.ExpiresAt = now.Add(window)
		case !g.ExpiresAt.After(now):
			// Storing this would report success for an authorisation that never
			// worked, and the owner would be told their machine was approved. A
			// granting device with a stale clock produces exactly this.
			return ControllerGrant{}, fmt.Errorf(
				"this authorisation would already have expired when it was granted — " +
					"check the clock on the device granting it")
		case g.ExpiresAt.After(now.Add(maxScopedGrantLifetime)):
			return ControllerGrant{}, fmt.Errorf(
				"a machine somebody borrowed cannot be authorised for longer than %s; "+
					"a machine they keep is the other grade", maxScopedGrantLifetime)
		}
	default:
		return ControllerGrant{}, fmt.Errorf(
			"%q is neither a machine somebody keeps nor one they borrowed", g.Grade)
	}
	g.GrantedAt = now

	grantsLock.Lock()
	defer grantsLock.Unlock()
	all, err := c.load()
	if err != nil {
		return ControllerGrant{}, err
	}
	all[g.ControllerAID] = g
	if err := c.save(all); err != nil {
		return ControllerGrant{}, err
	}
	return g, nil
}

// Live returns the grant for an identity, if one stands.
//
// An expired grant is reported as absent rather than returned with a flag: a
// caller that has to remember to check is a caller that will one day forget,
// and this is the check that stands between a borrowed computer and an
// identity.
// The error is returned rather than folded into the bool, so a caller cannot
// mistake "this record could not be read" for "this machine was never
// authorised". Both deny, which is the safe direction, but only one of them
// should be reported to the owner as a fault rather than as a decision.
func (c *controllerGrants) Live(aid string, now time.Time) (ControllerGrant, bool, error) {
	grantsLock.Lock()
	defer grantsLock.Unlock()
	all, err := c.load()
	if err != nil {
		return ControllerGrant{}, false, err
	}
	g, ok := all[strings.TrimSpace(aid)]
	if !ok {
		return ControllerGrant{}, false, nil
	}
	if live, _ := g.Live(now); !live {
		return ControllerGrant{}, false, nil
	}
	return g, true, nil
}

// All returns every grant, expired ones included.
//
// Deliberately unfiltered: this is what the owner is shown, and a machine whose
// authorisation ran out yesterday is something they may still want to know
// about — that it existed, and that it stopped.
func (c *controllerGrants) All() ([]ControllerGrant, error) {
	grantsLock.Lock()
	defer grantsLock.Unlock()
	all, err := c.load()
	if err != nil {
		return nil, err
	}
	out := make([]ControllerGrant, 0, len(all))
	for _, g := range all {
		out = append(out, g)
	}
	return out, nil
}

// Revoke removes a grant. Removing one that is not there is not an error: the
// caller wanted it gone, and it is.
//
// A file that cannot be read stops this rather than writing an empty one. It
// looks like over-caution on a route whose job is removal — but writing `{}`
// here would revoke every OTHER machine too, silently, while reporting that the
// one named was removed.
func (c *controllerGrants) Revoke(aid string) error {
	grantsLock.Lock()
	defer grantsLock.Unlock()
	all, err := c.load()
	if err != nil {
		return err
	}
	delete(all, strings.TrimSpace(aid))
	return c.save(all)
}
