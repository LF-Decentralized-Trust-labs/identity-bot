package brainsignin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// A lease is one run holding a sign-in. It expires unless renewed, so a run
// whose machine crashed frees its place without anybody returning it. Leases
// are kept in the Identity Agent's one record of everything it lends (the
// lending package), with every other kind of lend; what is here is how long
// they hold, and each account's cap.

// LeaseTTL is how long a lease holds without being renewed. A body renews well
// inside it while its run goes on.
const LeaseTTL = 5 * time.Minute

// RenewEvery is how often a body renews a lease it holds.
const RenewEvery = LeaseTTL / 3

// LapsedKept is how long a lease that ended — lapsed unrenewed, or no longer
// covered by its AI agent's grant — is remembered for its body to give back,
// with a sign-in its program refreshed, which would otherwise be lost.
const LapsedKept = 7 * 24 * time.Hour

// PoolOr is the account a lease counts against: pool, or for a sign-in that
// names no account, its AI agent alone.
func PoolOr(pool, agent string) string {
	if pool != "" {
		return pool
	}
	return "agent/" + agent
}

// Caps are the caps on simultaneous runs, one per account, kept beside the
// vault.
//
// An account's cap is one number, shared by every AI agent signed in to it:
// kept here, by the account (Record.Pool), not on each AI agent's sign-in, so
// AI agents on one account cannot hold different caps. A sign-in that names
// no account — a model server with no key — has a cap of its own, by its AI
// agent.
type Caps struct {
	dir string
	mu  sync.Mutex
}

var capStores sync.Map

// CapsIn is the caps kept in dir. One directory is one record, with one lock,
// however many times it is asked for.
func CapsIn(dir string) *Caps {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	v, _ := capStores.LoadOrStore(dir, &Caps{dir: dir})
	return v.(*Caps)
}

func (c *Caps) path() string { return filepath.Join(c.dir, "brain_sign_in_caps.json") }

func (c *Caps) load() (map[string]int, error) {
	b, err := os.ReadFile(c.path())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Cap is the cap on simultaneous runs of the account pool, as its owner set it,
// and whether one is set.
func (c *Caps) Cap(pool, agent string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	caps, err := c.load()
	if err != nil {
		return 0, false
	}
	n, ok := caps[PoolOr(pool, agent)]
	return n, ok
}

// SetCap sets the cap on simultaneous runs of the account pool, for every AI
// agent signed in to it.
func (c *Caps) SetCap(pool, agent string, n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	caps, err := c.load()
	if err != nil {
		return err
	}
	caps[PoolOr(pool, agent)] = n
	b, err := json.MarshalIndent(caps, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path())
}

// LegacyLease is a lease as it was kept before every lend was kept in one
// record: in a file of its own beside the vault. It is read once, to move it.
type LegacyLease struct {
	ID       string     `json:"id"`
	Agent    string     `json:"agent"`
	Host     string     `json:"host"`
	Pool     string     `json:"pool,omitempty"`
	Lent     string     `json:"lent,omitempty"`
	LentAt   time.Time  `json:"lent_at"`
	Expires  time.Time  `json:"expires"`
	LapsedAt *time.Time `json:"lapsed_at,omitempty"`
}

func legacyLeasesPath(dir string) string { return filepath.Join(dir, "brain_sign_in_leases.json") }

// LegacyLeases are the leases kept in dir's own file, if there is one.
func LegacyLeases(dir string) ([]LegacyLease, bool, error) {
	b, err := os.ReadFile(legacyLeasesPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var out []LegacyLease
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, true, fmt.Errorf("the record of runs holding sign-ins cannot be read: %v", err)
	}
	return out, true, nil
}

// RetireLegacyLeases removes dir's own lease file, once its leases are moved.
func RetireLegacyLeases(dir string) error {
	err := os.Remove(legacyLeasesPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
