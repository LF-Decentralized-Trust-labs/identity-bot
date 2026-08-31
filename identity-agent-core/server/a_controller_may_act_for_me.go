package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// What an identity has agreed somebody's computer may do on its behalf.
//
// A controller is a machine somebody reaches their Identity Agent FROM. It
// holds its own key and founds its own root — never a delegated identifier,
// because a delegated inception names its parent to anybody who can reach the
// machine, and that publishes the one identifier the design keeps pairwise. So
// what an agent stores about a controller is not a lineage. It is a grant: this
// identity may act for me, at this grade, until this.
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
// Both grades hold their own key and both are named pairwise. The difference is
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
// Long enough to be useful for the afternoon somebody is actually at that
// computer, short enough that forgetting to revoke it is not the same as
// granting it forever — which is the whole reason the borrowed grade exists.
const scopedGrantLifetime = 12 * time.Hour

// ControllerGrant is one machine's permission to act for this identity.
type ControllerGrant struct {
	// ControllerAID is the root the controller founded for itself. Not derived
	// here and not derivable here: the private half never leaves that machine,
	// which is what makes revoking this grant enough to stop it.
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
	mu      sync.Mutex
	dataDir string
}

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
func (c *controllerGrants) load() map[string]ControllerGrant {
	out := map[string]ControllerGrant{}
	if b, err := os.ReadFile(c.path()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
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
	switch g.Grade {
	case GradeEnrolled:
		// No expiry: a machine somebody keeps lasts until they say otherwise.
		g.ExpiresAt = time.Time{}
	case GradeScoped:
		if g.ExpiresAt.IsZero() {
			g.ExpiresAt = now.Add(scopedGrantLifetime)
		}
	default:
		return ControllerGrant{}, fmt.Errorf(
			"%q is neither a machine somebody keeps nor one they borrowed", g.Grade)
	}
	g.GrantedAt = now

	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.load()
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
func (c *controllerGrants) Live(aid string, now time.Time) (ControllerGrant, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.load()[strings.TrimSpace(aid)]
	if !ok {
		return ControllerGrant{}, false
	}
	if live, _ := g.Live(now); !live {
		return ControllerGrant{}, false
	}
	return g, true
}

// All returns every grant, expired ones included.
//
// Deliberately unfiltered: this is what the owner is shown, and a machine whose
// authorisation ran out yesterday is something they may still want to know
// about — that it existed, and that it stopped.
func (c *controllerGrants) All() []ControllerGrant {
	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.load()
	out := make([]ControllerGrant, 0, len(all))
	for _, g := range all {
		out = append(out, g)
	}
	return out
}

// Revoke removes a grant. Removing one that is not there is not an error: the
// caller wanted it gone, and it is.
func (c *controllerGrants) Revoke(aid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.load()
	delete(all, strings.TrimSpace(aid))
	return c.save(all)
}
