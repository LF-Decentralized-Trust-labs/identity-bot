// Package lending is the one record of everything an Identity Agent lends to
// an AI agent's bodies for a run: a brain's sign-in, access to a service such
// as GitHub. It is kept in the Identity Agent's vault, since what a service
// lent may itself be a secret the Identity Agent has to withdraw.
//
// Every kind of lend is held, renewed, given back, lapsed and ended the same
// way, here. What differs by service is plugged in (Service): whether the
// grant still covers a lend, and how what was lent is withdrawn at the service.
// So one sweep ends every lend its grant no longer covers, of every kind, at
// once.
package lending

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrInUse is a lend refused because the runs its pool allows are all in use.
var ErrInUse = errors.New("this is already lent to as many runs as it may be")

// ErrNoLend is a lend this body does not hold: never lent, already given
// back, or ended so long ago it was forgotten.
var ErrNoLend = errors.New("this body holds no such lend")

// ErrUnreadable is a ledger that cannot be read. Nothing is lent while it is:
// an empty count would let a lend past its cap, and a lend nobody can find
// cannot be withdrawn.
var ErrUnreadable = errors.New("the record of what is lent cannot be read")

// Lend is one run's hold on something lent to an AI agent's body.
type Lend struct {
	ID string `json:"id"`
	// Kind is the service it is lent for (Service.Kind).
	Kind string `json:"kind"`
	// Agent is the AI agent's asset id.
	Agent string `json:"agent"`
	// Host is the body holding it, by its machine key's identifier.
	Host string `json:"host"`
	// Pool is what a cap on simultaneous runs counts it against; empty counts
	// it against nothing.
	Pool string `json:"pool,omitempty"`
	// Lent is a fingerprint of what was lent, never the thing itself.
	Lent    string    `json:"lent,omitempty"`
	LentAt  time.Time `json:"lent_at"`
	Expires time.Time `json:"expires"`
	// Data is what the service needs to check and withdraw the lend. It may
	// hold the very credential lent, which is why the ledger is in the vault.
	Data json.RawMessage `json:"data,omitempty"`
	// EndedAt is when it stopped being lent — given back, lapsed unrenewed, or
	// no longer covered by its grant — and Ended says why. An ended lend holds
	// no place. It is remembered for its service's KeptAfterEnd, so a body
	// that was out of reach can still give it back.
	EndedAt  *time.Time `json:"ended_at,omitempty"`
	Ended    string     `json:"ended,omitempty"`
	Returned bool       `json:"returned,omitempty"`
	// Withdrawing are parts of it that ended, but that the service could not
	// be reached to withdraw yet. Each is tried again until the lend expires.
	Withdrawing []json.RawMessage `json:"withdrawing,omitempty"`
}

// IsOpen reports whether the lend still holds at now.
func (x Lend) IsOpen(now time.Time) bool { return x.EndedAt == nil && now.Before(x.Expires) }

// Service is what one kind of lend plugs into the ledger.
type Service struct {
	Kind string
	// IDPrefix begins the id of each of its lends.
	IDPrefix string
	// KeptAfterEnd is how long an ended lend is remembered for its body to give
	// back, with whatever its run sends back with it.
	KeptAfterEnd time.Duration
	// Check says what of an open lend its grant no longer covers, or nil when
	// it still covers all of it. Nil Check is a lend nothing but time ends.
	Check func(x Lend) *Narrowed
	// Parts are what is withdrawn at the service when a lend ends whole. Nil
	// is a lend with nothing to withdraw: a sign-in, which the run keeps.
	Parts func(data json.RawMessage) []json.RawMessage
	// Withdraw ends one part at the service. Nil when it is withdrawn, or was
	// already gone.
	Withdraw func(ctx context.Context, part json.RawMessage) error
}

// Narrowed is what of a lend its grant no longer covers.
type Narrowed struct {
	Why string
	// Keep is the lend's data narrowed to what is still covered. Nil ends the
	// lend whole.
	Keep json.RawMessage
	// Withdraw are the parts no longer covered, when it is not ended whole.
	Withdraw []json.RawMessage
}

// Ended is a lend that stopped holding, for its caller to record.
type Ended struct {
	Lend Lend
	Why  string
	// Lapsed is a lend ended by time: not renewed, or expired.
	Lapsed bool
	// Partly is a lend narrowed rather than ended: part of it was withdrawn.
	Partly bool
	// Withdrawn is every part ended now also withdrawn at its service.
	Withdrawn bool
}

// Store is where the ledger is kept: the Identity Agent's vault.
type Store interface {
	Read(out any) (bool, error)
	Write(v any) error
}

// Ledger is the record of everything lent.
type Ledger struct {
	store    Store
	services map[string]Service
	mu       sync.Mutex
}

// New is a ledger kept in store, for these services.
func New(store Store, services ...Service) *Ledger {
	l := &Ledger{store: store, services: map[string]Service{}}
	for _, s := range services {
		l.services[s.Kind] = s
	}
	return l
}

type kept struct {
	Lends []Lend `json:"lends"`
}

func (l *Ledger) load() ([]Lend, error) {
	var k kept
	if _, err := l.store.Read(&k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	return k.Lends, nil
}

func (l *Ledger) save(all []Lend) error {
	if all == nil {
		all = []Lend{}
	}
	return l.store.Write(kept{Lends: all})
}

// part is one thing to withdraw, and the lend it is of.
type part struct {
	lend, kind string
	data       json.RawMessage
}

// end stops x holding at now, why, and queues what its service withdraws.
func (l *Ledger) end(x *Lend, why string, now time.Time) {
	t := now
	x.EndedAt, x.Ended = &t, why
	if svc, ok := l.services[x.Kind]; ok && svc.Parts != nil && len(x.Data) > 0 {
		x.Withdrawing = append(x.Withdrawing, svc.Parts(x.Data)...)
	}
}

// tidy applies time to every lend: an open one past its expiry ends, lapsed;
// a part still to withdraw is let go once the lend has expired, since it has
// lapsed at the service by itself; and an ended lend with nothing left to
// withdraw is forgotten once given back, or once its service's KeptAfterEnd
// has passed.
func (l *Ledger) tidy(all []Lend, now time.Time) ([]Lend, []Ended, bool) {
	var out []Lend
	var ended []Ended
	changed := false
	for _, x := range all {
		if x.EndedAt == nil && !now.Before(x.Expires) {
			t := now
			x.EndedAt, x.Ended = &t, "lapsed"
			changed = true
			ended = append(ended, Ended{Lend: x, Why: "lapsed", Lapsed: true, Withdrawn: true})
		}
		if x.EndedAt == nil {
			out = append(out, x)
			continue
		}
		if len(x.Withdrawing) > 0 && !now.Before(x.Expires) {
			x.Withdrawing = nil
			changed = true
		}
		if len(x.Withdrawing) == 0 {
			svc := l.services[x.Kind]
			if x.Returned || !now.Before(x.EndedAt.Add(svc.KeptAfterEnd)) {
				changed = true
				continue
			}
		}
		out = append(out, x)
	}
	return out, ended, changed
}

// pending is every part waiting to be withdrawn.
func pending(all []Lend) []part {
	var out []part
	for _, x := range all {
		for _, d := range x.Withdrawing {
			out = append(out, part{lend: x.ID, kind: x.Kind, data: d})
		}
	}
	return out
}

// withdraw tries each part at its service, without the ledger locked: a
// service out of reach must not hold up a lend of another kind. What was
// withdrawn is then taken off the ledger. It reports, by lend, whether every
// part of it tried was withdrawn, and, by kind, how many parts were not.
func (l *Ledger) withdraw(ctx context.Context, parts []part, now time.Time) (map[string]bool, map[string]int) {
	if len(parts) == 0 {
		return nil, nil
	}
	all := map[string]bool{}
	failed := map[string]int{}
	var done []part
	for _, p := range parts {
		svc, ok := l.services[p.kind]
		if _, seen := all[p.lend]; !seen {
			all[p.lend] = true
		}
		if !ok || svc.Withdraw == nil {
			done = append(done, p)
			continue
		}
		if err := svc.Withdraw(ctx, p.data); err != nil {
			all[p.lend] = false
			failed[p.kind]++
			continue
		}
		done = append(done, p)
	}
	if len(done) == 0 {
		return all, failed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	lends, err := l.load()
	if err != nil {
		// Left to withdraw again: the next sweep finds them still queued.
		return all, failed
	}
	for i := range lends {
		var left []json.RawMessage
		for _, d := range lends[i].Withdrawing {
			gone := false
			for _, p := range done {
				if p.lend == lends[i].ID && bytes.Equal(p.data, d) {
					gone = true
					break
				}
			}
			if !gone {
				left = append(left, d)
			}
		}
		lends[i].Withdrawing = left
	}
	lends, _, _ = l.tidy(lends, now)
	_ = l.save(lends)
	return all, failed
}

// settle marks each ended lend withdrawn or not, from what withdraw reported.
func settle(ended []Ended, withdrawn map[string]bool) []Ended {
	for i := range ended {
		if ok, tried := withdrawn[ended[i].Lend.ID]; tried {
			ended[i].Withdrawn = ok
		}
	}
	return ended
}

func newID(prefix string) (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Limit is what a new lend must stay within.
type Limit struct {
	// MaxInPool caps the open lends of its kind with the same Pool; 0 is no cap.
	MaxInPool int
	// OnePerBody ends every other open lend of its kind its body holds for its
	// AI agent, so a body holds at most one at a time.
	OnePerBody bool
}

// Lend records x, opened at now, within lim. It returns x with its id, and
// every lend that ended on the way, for the caller to record.
func (l *Ledger) Lend(ctx context.Context, x Lend, lim Limit, now time.Time) (Lend, []Ended, error) {
	l.mu.Lock()
	all, err := l.load()
	if err != nil {
		l.mu.Unlock()
		return Lend{}, nil, err
	}
	all, ended, changed := l.tidy(all, now)
	if lim.MaxInPool > 0 {
		n := 0
		for _, y := range all {
			if y.Kind == x.Kind && y.Pool == x.Pool && y.IsOpen(now) {
				n++
			}
		}
		if n >= lim.MaxInPool {
			if changed {
				_ = l.save(all)
			}
			l.mu.Unlock()
			return Lend{}, ended, ErrInUse
		}
	}
	var queued []part
	if lim.OnePerBody {
		for i := range all {
			y := &all[i]
			if y.Kind == x.Kind && y.Agent == x.Agent && y.Host == x.Host && y.IsOpen(now) {
				l.end(y, "the same body was lent it again", now)
				ended = append(ended, Ended{Lend: *y, Why: y.Ended, Withdrawn: len(y.Withdrawing) == 0})
				for _, d := range y.Withdrawing {
					queued = append(queued, part{lend: y.ID, kind: y.Kind, data: d})
				}
			}
		}
	}
	if x.ID == "" {
		if x.ID, err = newID(l.services[x.Kind].IDPrefix); err != nil {
			l.mu.Unlock()
			return Lend{}, ended, err
		}
	}
	x.LentAt = now
	if err := l.save(append(all, x)); err != nil {
		l.mu.Unlock()
		return Lend{}, ended, err
	}
	l.mu.Unlock()
	withdrawn, _ := l.withdraw(ctx, queued, now)
	return x, settle(ended, withdrawn), nil
}

// Renew extends an open lend host holds for agent until now+ttl.
func (l *Ledger) Renew(kind, id, host, agent string, ttl time.Duration, now time.Time) (Lend, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return Lend{}, err
	}
	all, _, _ = l.tidy(all, now)
	for i := range all {
		x := &all[i]
		if x.Kind == kind && x.ID == id && x.Host == host && x.Agent == agent && x.IsOpen(now) {
			x.Expires = now.Add(ttl)
			if err := l.save(all); err != nil {
				return Lend{}, err
			}
			return *x, nil
		}
	}
	return Lend{}, ErrNoLend
}

// Find is the lend host holds for agent, open or ended but still remembered,
// without giving it back.
func (l *Ledger) Find(kind, id, host, agent string, now time.Time) (Lend, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return Lend{}, false, err
	}
	all, _, _ = l.tidy(all, now)
	for _, x := range all {
		if x.Kind == kind && x.ID == id && x.Host == host && x.Agent == agent && !x.Returned {
			return x, true, nil
		}
	}
	return Lend{}, false, nil
}

// Returned is a lend given back.
type Returned struct {
	Lend Lend
	// WasOpen is a lend still holding when it was given back; otherwise it had
	// ended already (lapsed, or no longer covered).
	WasOpen bool
	// Withdrawn is everything of it withdrawn at its service.
	Withdrawn bool
}

// Return gives back the lend host holds for agent, open or ended but still
// remembered, and withdraws at its service whatever of it is not withdrawn
// yet. A part the service cannot be reached for stays queued, and is tried
// again until the lend expires.
func (l *Ledger) Return(ctx context.Context, kind, id, host, agent string, now time.Time) (Returned, error) {
	got, err := l.returnWhere(ctx, func(x Lend) bool {
		return x.Kind == kind && x.ID == id && x.Host == host && x.Agent == agent
	}, now)
	if err != nil {
		return Returned{}, err
	}
	if len(got) == 0 {
		return Returned{}, ErrNoLend
	}
	return got[0], nil
}

// ReturnEvery gives back every open lend of kind that host holds for agent:
// a body that started again holds nothing from before.
func (l *Ledger) ReturnEvery(ctx context.Context, kind, host, agent string, now time.Time) ([]Returned, error) {
	return l.returnWhere(ctx, func(x Lend) bool {
		return x.Kind == kind && x.Host == host && x.Agent == agent && x.IsOpen(now)
	}, now)
}

func (l *Ledger) returnWhere(ctx context.Context, match func(Lend) bool, now time.Time) ([]Returned, error) {
	l.mu.Lock()
	all, err := l.load()
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	all, _, _ = l.tidy(all, now)
	var got []Returned
	var queued []part
	for i := range all {
		x := &all[i]
		if x.Returned || !match(*x) {
			continue
		}
		open := x.IsOpen(now)
		if open {
			l.end(x, "given back", now)
		}
		x.Returned = true
		for _, d := range x.Withdrawing {
			queued = append(queued, part{lend: x.ID, kind: x.Kind, data: d})
		}
		got = append(got, Returned{Lend: *x, WasOpen: open, Withdrawn: len(x.Withdrawing) == 0})
	}
	if len(got) == 0 {
		l.mu.Unlock()
		return nil, nil
	}
	all, _, _ = l.tidy(all, now)
	if err := l.save(all); err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	withdrawn, _ := l.withdraw(ctx, queued, now)
	for i := range got {
		if ok, tried := withdrawn[got[i].Lend.ID]; tried {
			got[i].Withdrawn = ok
		}
	}
	return got, nil
}

// Count is how many open lends match at now. A ledger that cannot be read
// counts none: it is what a view shows, and nothing is lent from it.
func (l *Ledger) Count(match func(Lend) bool, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, _ := l.load()
	n := 0
	for _, x := range all {
		if x.IsOpen(now) && match(x) {
			n++
		}
	}
	return n
}

// Open is every open lend of kind at now.
func (l *Ledger) Open(kind string, now time.Time) ([]Lend, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return nil, err
	}
	var out []Lend
	for _, x := range all {
		if x.Kind == kind && x.IsOpen(now) {
			out = append(out, x)
		}
	}
	return out, nil
}

// All is every lend the ledger remembers, open or ended.
func (l *Ledger) All() ([]Lend, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.load()
}

// Forget drops every lend of kind for agent, open or ended, withdrawing
// nothing: for a sign-in removed or replaced, whose places are not places on
// the next one.
func (l *Ledger) Forget(kind, agent string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return err
	}
	var kept []Lend
	for _, x := range all {
		if x.Kind != kind || x.Agent != agent {
			kept = append(kept, x)
		}
	}
	if len(kept) == len(all) {
		return nil
	}
	return l.save(kept)
}

// Lapse ends every lend that expired unrenewed by now, and returns each once,
// so it can be recorded. It asks no service anything.
func (l *Ledger) Lapse(now time.Time) ([]Ended, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return nil, err
	}
	all, ended, changed := l.tidy(all, now)
	if !changed {
		return nil, nil
	}
	return ended, l.save(all)
}

// Sweep is the one check of everything lent: every lend that lapsed ends;
// every open lend its grant no longer covers ends, or is narrowed to what it
// still covers, as its service says; and everything ended and not withdrawn
// yet is withdrawn at its service, this time or the next.
func (l *Ledger) Sweep(ctx context.Context, now time.Time) ([]Ended, error) {
	ended, _, err := l.endWhere(ctx, func(x Lend) *Narrowed {
		svc, ok := l.services[x.Kind]
		if !ok || svc.Check == nil {
			return nil
		}
		return svc.Check(x)
	}, now)
	return ended, err
}

// EndAll ends every open lend of kind, why, and withdraws it. It returns what
// ended, and how many parts of kind — a lend can hold more than one — its
// service could not be reached to withdraw yet.
func (l *Ledger) EndAll(ctx context.Context, kind, why string, now time.Time) ([]Ended, int, error) {
	ended, failed, err := l.endWhere(ctx, func(x Lend) *Narrowed {
		if x.Kind != kind {
			return nil
		}
		return &Narrowed{Why: why}
	}, now)
	return ended, failed[kind], err
}

// endWhere ends or narrows each open lend check says to, then withdraws
// everything waiting to be. It also says, by kind, how many parts tried were
// not withdrawn.
func (l *Ledger) endWhere(ctx context.Context, check func(Lend) *Narrowed, now time.Time) ([]Ended, map[string]int, error) {
	l.mu.Lock()
	all, err := l.load()
	if err != nil {
		l.mu.Unlock()
		return nil, nil, err
	}
	all, ended, changed := l.tidy(all, now)
	for i := range all {
		x := &all[i]
		if !x.IsOpen(now) {
			continue
		}
		n := check(*x)
		if n == nil {
			continue
		}
		changed = true
		if n.Keep != nil {
			x.Data = n.Keep
			x.Withdrawing = append(x.Withdrawing, n.Withdraw...)
			ended = append(ended, Ended{Lend: *x, Why: n.Why, Partly: true, Withdrawn: len(n.Withdraw) == 0})
			continue
		}
		l.end(x, n.Why, now)
		ended = append(ended, Ended{Lend: *x, Why: n.Why, Withdrawn: len(x.Withdrawing) == 0})
	}
	queued := pending(all)
	if changed {
		all, _, _ = l.tidy(all, now)
		if err := l.save(all); err != nil {
			l.mu.Unlock()
			return ended, nil, err
		}
	}
	l.mu.Unlock()
	withdrawn, failed := l.withdraw(ctx, queued, now)
	return settle(ended, withdrawn), failed, nil
}

// Import adds lends kept elsewhere before this ledger, each once: a lend
// already here by its id is left as it is.
func (l *Ledger) Import(lends []Lend) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.load()
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, x := range all {
		have[x.ID] = true
	}
	for _, x := range lends {
		if !have[x.ID] {
			all = append(all, x)
		}
	}
	return l.save(all)
}
