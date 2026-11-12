package lockgate

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"identity-agent-core/secureenclave"
)

// State is whether the identity this process serves can be used right now.
type State string

const (
	// StateUngated: the profile has no gate (made before one existed). It is
	// served as it always was, and says so; nothing about it is locked.
	StateUngated State = "ungated"
	// StateLocked: gated, and no key is held. The seed is not read.
	StateLocked State = "locked"
	// StateOpen: gated and logged in; the key is held in memory.
	StateOpen State = "open"
)

// ErrNotLoggedOut is the answer when a lock could not complete because the
// device-held copy of GK could not be deleted. The identity is then still open
// and must be shown as logged in, never as locked.
var ErrNotLoggedOut = errors.New("could not log out: the device-held key could not be deleted, so the identity is still open")

type heldKey struct {
	profile string
	gk      GK
}

var (
	ringMu sync.RWMutex
	ring   = map[string]heldKey{}
)

// sealer looks the key up at each use and works on a copy, so a lock zeroing
// the held key cannot leave a seal running under an all-zero one.
type sealer struct{ dataDir string }

func (s sealer) key() (string, GK, error) {
	ringMu.RLock()
	defer ringMu.RUnlock()
	h, ok := ring[s.dataDir]
	if !ok {
		return "", nil, secureenclave.ErrIdentityLocked
	}
	return h.profile, append(GK(nil), h.gk...), nil
}

func (s sealer) Seal(plain []byte) ([]byte, error) {
	p, k, err := s.key()
	if err != nil {
		return nil, err
	}
	defer k.Zero()
	return Seal(k, p, plain)
}

func (s sealer) Open(sealed []byte) ([]byte, error) {
	p, k, err := s.key()
	if err != nil {
		return nil, err
	}
	defer k.Zero()
	return Open(k, p, sealed)
}

// lookup is what secureenclave asks, per data directory.
func lookup(dataDir string) (secureenclave.GateSealer, bool) {
	if !(&Profile{dir: dataDir}).Gated() {
		return nil, false
	}
	ringMu.RLock()
	_, ok := ring[dataDir]
	ringMu.RUnlock()
	if !ok {
		return nil, true
	}
	return sealer{dataDir: dataDir}, true
}

// Install makes the seed layer ask this package whether a profile is gated and
// open. Call once at start; returns the function that undoes it.
func Install() (restore func()) {
	r1 := secureenclave.UseGate(lookup)
	r2 := secureenclave.UseGateRequirement(func(dataDir string) bool {
		requiredMu.RLock()
		defer requiredMu.RUnlock()
		return required[dataDir]
	})
	return func() { r2(); r1() }
}

var (
	requiredMu sync.RWMutex
	required   = map[string]bool{}
)

// Require says that the profile at dataDir must have a gate before any seed is
// stored in it (a build with gates, a profile made now). If making the gate
// failed, the store is refused and the next start tries again.
func Require(dataDir string) {
	requiredMu.Lock()
	required[dataDir] = true
	requiredMu.Unlock()
}

func hold(dataDir, profile string, gk GK) {
	ringMu.Lock()
	if old, ok := ring[dataDir]; ok && &old.gk[0] != &gk[0] {
		old.gk.Zero()
	}
	ring[dataDir] = heldKey{profile: profile, gk: gk}
	ringMu.Unlock()
}

func drop(dataDir string) {
	ringMu.Lock()
	if old, ok := ring[dataDir]; ok {
		old.gk.Zero()
		delete(ring, dataDir)
	}
	ringMu.Unlock()
}

// Session is one identity's gate in a running core: its state, and the moves
// between locked and open.
type Session struct {
	P *Profile
	G *Gate
}

// NewSession ties a profile to its gate.
func NewSession(p *Profile, g *Gate) *Session {
	g.Profile = p
	return &Session{P: p, G: g}
}

// State is derived from what is on disk and in memory, never from a flag that
// could disagree with them.
func (s *Session) State() State {
	if !s.P.Gated() {
		return StateUngated
	}
	ringMu.RLock()
	_, ok := ring[s.P.dir]
	ringMu.RUnlock()
	if ok {
		return StateOpen
	}
	return StateLocked
}

// Reopen is what a core does at start. A logged-in profile (device-held copy
// present) opens by reading it, with nobody present: the phone killed by its
// operating system. A logged-out one stays locked.
func (s *Session) Reopen() error {
	if !s.P.Gated() {
		return nil
	}
	// A secret change a crash cut short is finished before anything is read, so
	// the device-held key and the seed agree.
	if err := s.P.FinishPendingChange(); err != nil {
		return fmt.Errorf("a change of the identity secret was cut short and could not be finished: %w", err)
	}
	gk, err := s.P.ReadDeviceHeld()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Present and unreadable: the hardware key is gone or changed. Locked,
		// and the person is told why; the phrase restores.
		return fmt.Errorf("the device-held key is there and cannot be opened: %w", err)
	}
	hold(s.P.dir, s.P.id, gk)
	return nil
}

// Found makes the gate for a profile being made and opens it: the new profile
// is logged in.
func (s *Session) Found() error {
	gk, err := s.P.Create()
	if err != nil {
		return err
	}
	hold(s.P.dir, s.P.id, gk)
	return nil
}

// Unlock opens a locked profile from a log-in result. secret is the optional
// identity secret, "" when the owner set none.
func (s *Session) Unlock(r ProviderResult, secret string) error {
	if s.State() == StateUngated {
		return ErrNoGate
	}
	gk, err := s.G.Release(r, secret)
	if err != nil {
		return err
	}
	if s.State() == StateOpen {
		// Already open: the result was valid, and nothing changes.
		gk.Zero()
		return nil
	}
	if err := s.P.WriteDeviceHeld(gk); err != nil {
		gk.Zero()
		return fmt.Errorf("could not write the device-held key, so the identity stays locked: %w", err)
	}
	hold(s.P.dir, s.P.id, gk)
	return nil
}

// Lock logs the identity out: deletes the device-held copy (and proves it gone),
// then zeroes and drops the key. If the deletion fails the identity stays open
// and ErrNotLoggedOut is returned. The caller has already stopped the identity
// answering and drained what was in progress (section 5).
func (s *Session) Lock() error {
	if s.State() == StateUngated {
		return ErrNoGate
	}
	if err := s.P.DeleteDeviceHeld(); err != nil {
		return fmt.Errorf("%w: %v", ErrNotLoggedOut, err)
	}
	drop(s.P.dir)
	return nil
}

// Key is the key sealing the profile while it is open, for re-sealing. The copy
// returned is the caller's to zero.
func (s *Session) Key() (GK, error) {
	ringMu.RLock()
	h, ok := ring[s.P.dir]
	ringMu.RUnlock()
	if !ok {
		return nil, secureenclave.ErrIdentityLocked
	}
	return append(GK(nil), h.gk...), nil
}

// ChangeSecret sets (secret != "") or removes (secret == "") the optional
// identity secret, re-sealing the stored seed first. current is the secret now
// in force, "" if none, and must be right: it is checked through the gate's own
// counter, so this is no way round the delay.
func (s *Session) ChangeSecret(current, secret string) error {
	if s.State() != StateOpen {
		return secureenclave.ErrIdentityLocked
	}
	if err := s.P.FinishPendingChange(); err != nil {
		return err
	}
	base, err := s.P.readGateCopy()
	if err != nil {
		return err
	}
	defer base.Zero()
	have, err := s.P.effective(base, current, s.G.now())
	if err != nil {
		return err
	}
	if &have[0] != &base[0] {
		defer have.Zero()
	}
	var cerr error
	if secret == "" {
		cerr = s.P.RemoveSecret(have)
	} else {
		cerr = s.P.SetSecret(have, secret)
	}
	if cerr != nil {
		return cerr
	}
	// The held key is now the new effective key.
	if gk, err := s.P.ReadDeviceHeld(); err == nil {
		hold(s.P.dir, s.P.id, gk)
	}
	return nil
}
