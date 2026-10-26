package brainsignin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// A lease is one run holding a sign-in. It expires unless renewed, so a run
// whose machine crashed frees its place without anybody returning it.

// LeaseTTL is how long a lease holds without being renewed. A body renews well
// inside it while its run goes on.
const LeaseTTL = 5 * time.Minute

// RenewEvery is how often a body renews a lease it holds.
const RenewEvery = LeaseTTL / 3

// ErrInUse is a sign-in whose cap on simultaneous runs is reached.
var ErrInUse = errors.New("this sign-in already has its runs in use")

// ErrNoLease is a lease this body does not hold: never lent, already
// returned, or expired.
var ErrNoLease = errors.New("this body holds no such lease")

// Lease is one run's hold on an AI agent's sign-in. It carries no secret.
type Lease struct {
	ID string `json:"id"`
	// Agent is the AI agent's asset id: whose sign-in is held.
	Agent string `json:"agent"`
	// Host is the body holding it, by its machine key's identifier.
	Host string `json:"host"`
	// Pool is the account whose runs the lease counts against (Record.Pool).
	// Empty on a lease from before caps counted accounts, which counts against
	// its AI agent alone.
	Pool string `json:"pool,omitempty"`
	// Lent is a fingerprint of the sign-in this run was lent, so a sign-in the
	// run's program refreshed is kept only while it is still the one lent.
	Lent    string    `json:"lent,omitempty"`
	LentAt  time.Time `json:"lent_at"`
	Expires time.Time `json:"expires"`
}

// Leases are the runs holding sign-ins, kept beside the vault so a restart of
// the Identity Agent does not forget runs still going and let a sign-in be
// lent past its cap.
type Leases struct {
	path string
	mu   sync.Mutex
}

var leaseStores sync.Map

// LeasesIn is the lease record kept in dir. One directory is one record, with
// one lock, however many times it is asked for.
func LeasesIn(dir string) *Leases {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	v, _ := leaseStores.LoadOrStore(dir, &Leases{path: filepath.Join(dir, "brain_sign_in_leases.json")})
	return v.(*Leases)
}

// ErrLeasesUnreadable is a lease record that cannot be read. Nothing is lent
// while it is: an empty count would let a sign-in past its cap.
var ErrLeasesUnreadable = errors.New("the record of runs holding sign-ins cannot be read")

func (l *Leases) load() ([]Lease, error) {
	b, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLeasesUnreadable, err)
	}
	var out []Lease
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLeasesUnreadable, err)
	}
	return out, nil
}

func (l *Leases) save(all []Lease) error {
	if all == nil {
		all = []Lease{}
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// live splits leases into those still held at now and those expired.
func live(all []Lease, now time.Time) (held, expired []Lease) {
	for _, x := range all {
		if now.Before(x.Expires) {
			held = append(held, x)
		} else {
			expired = append(expired, x)
		}
	}
	return held, expired
}

// pool is the account a lease counts against.
func (x Lease) pool() string { return poolOr(x.Pool, x.Agent) }

// poolOr is pool, or for a sign-in that names no account, its AI agent alone.
func poolOr(pool, agent string) string {
	if pool != "" {
		return pool
	}
	return "agent/" + agent
}

// Lend takes a place for one run of agent's sign-in on host, if the cap allows
// (0 is no cap). The cap counts every run holding a sign-in of the same
// account (pool), whichever AI agent it is for, so ten AI agents signed in to
// one subscription cannot run more at once than one could. lent is a
// fingerprint of the sign-in lent. It returns the lease, and any leases that
// had expired and were let go, so the caller can record them.
func (l *Leases) Lend(agent, pool, lent, host string, maxRuns int, now time.Time) (Lease, []Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return Lease{}, nil, err
	}
	held, expired := live(all, now)
	pool = poolOr(pool, agent)
	if maxRuns > 0 {
		n := 0
		for _, x := range held {
			if x.pool() == pool {
				n++
			}
		}
		if n >= maxRuns {
			if len(expired) > 0 {
				_ = l.save(held)
			}
			return Lease{}, expired, ErrInUse
		}
	}
	id := make([]byte, 18)
	if _, err := rand.Read(id); err != nil {
		return Lease{}, expired, err
	}
	lease := Lease{ID: "bl_" + base64.RawURLEncoding.EncodeToString(id), Agent: agent, Host: host,
		Pool: pool, Lent: lent, LentAt: now, Expires: now.Add(LeaseTTL)}
	if err := l.save(append(held, lease)); err != nil {
		return Lease{}, expired, err
	}
	return lease, expired, nil
}

// Lapsed removes and returns every lease that expired unrenewed by now, so
// each can be recorded once.
func (l *Leases) Lapsed(now time.Time) ([]Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return nil, err
	}
	held, expired := live(all, now)
	if len(expired) == 0 {
		return nil, nil
	}
	return expired, l.save(held)
}

// Renew extends a lease host holds on agent's sign-in.
func (l *Leases) Renew(id, host, agent string, now time.Time) (Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return Lease{}, err
	}
	held, _ := live(all, now)
	for i := range held {
		if held[i].ID == id && held[i].Host == host && held[i].Agent == agent {
			held[i].Expires = now.Add(LeaseTTL)
			if err := l.save(held); err != nil {
				return Lease{}, err
			}
			return held[i], nil
		}
	}
	return Lease{}, ErrNoLease
}

// Return gives back a lease host holds on agent's sign-in.
func (l *Leases) Return(id, host, agent string, now time.Time) (Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return Lease{}, err
	}
	for i, x := range all {
		if x.ID == id && x.Host == host && x.Agent == agent {
			rest := append(append([]Lease{}, all[:i]...), all[i+1:]...)
			held, _ := live(rest, now)
			if err := l.save(held); err != nil {
				return Lease{}, err
			}
			if !now.Before(x.Expires) {
				return x, ErrNoLease
			}
			return x, nil
		}
	}
	return Lease{}, ErrNoLease
}

// InUse is how many runs hold agent's sign-in at now.
func (l *Leases) InUse(agent string, now time.Time) int {
	return l.count(func(x Lease) bool { return x.Agent == agent }, now)
}

// InUseByAccount is how many runs hold a sign-in of the account pool at now,
// for every AI agent signed in to it.
func (l *Leases) InUseByAccount(pool, agent string, now time.Time) int {
	pool = poolOr(pool, agent)
	return l.count(func(x Lease) bool { return x.pool() == pool }, now)
}

func (l *Leases) count(match func(Lease) bool, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, _ := l.load()
	held, _ := live(all, now)
	n := 0
	for _, x := range held {
		if match(x) {
			n++
		}
	}
	return n
}

// Forget drops every lease on agent's sign-in, when the sign-in itself is
// removed or replaced: a run still going keeps what it was given, and nothing
// it renews or returns can hold the new sign-in's places.
func (l *Leases) Forget(agent string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, x := range all {
		if x.Agent != agent {
			kept = append(kept, x)
		}
	}
	return l.save(kept)
}
