package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// A relay is how an Identity Agent that only dials out stays reachable at an
// address it can hand out and expect to still work later (ADR-048).
//
// The Identity Agent opens one session to the relay, admitted on a signature by
// a pairwise enrolment identifier, and the relay passes requests for its
// addresses down that session as real HTTP. An address is either public (one
// stable address anybody may find) or private (one unlinkable address per
// relationship). Which one an identity uses is its own choice; a relay serves
// one mode only.
//
// The relay learns the enrolment identifier and its key log, and nothing else.
// It is never the root: enrolment is per relay, so two operators cannot tell
// that two enrolments are the same identity.

// Kind is how an address was made.
type Kind string

const (
	// KindPrivate is a private address, held by a secret only this Identity
	// Agent knows.
	KindPrivate Kind = "private"
	// KindName is a public name claimed at the relay.
	KindName Kind = "name"
	// KindDomain is the identity's own domain, served by the relay once DNS
	// proves it.
	KindDomain Kind = "domain"
)

// Allocation is one address this Identity Agent holds at a relay.
type Allocation struct {
	// Label names the address in each stream's preamble: a private label, a
	// public name, or a domain.
	Label string `json:"label"`
	// URL is where a counterparty reaches it.
	URL string `json:"url"`
	// RAID is the identifier the address serves.
	RAID string `json:"raid,omitempty"`
	// Mode is what this Identity Agent asked for, from its own records. A
	// request's preamble says what the relay claims; this is what is believed.
	Mode relayproto.Mode `json:"mode"`
	Kind Kind            `json:"kind"`
	// Secret holds a private address. The relay stores only a commitment to
	// it, so after the relay restarts this is what proves the address is ours.
	Secret string `json:"secret,omitempty"`
	// Ending is set on a per-relationship address whose relationship has
	// ended. It answers nothing from then on, and is given back to the relay as
	// soon as the relay can be asked, on a later session if not on this one.
	Ending bool `json:"ending,omitempty"`
}

// ForRelationship reports whether this is a private address made for one
// relationship, as opposed to the Identity Agent's primary address, which
// serves its enrolment identifier and is shared by every relationship made
// before addresses were per relationship (ADR-048 §6).
func (a Allocation) ForRelationship(primary string) bool {
	return a.Kind == KindPrivate && a.RAID != "" && a.RAID != primary
}

// Config is what an Identity Agent needs to be reachable through one relay.
type Config struct {
	// BaseURL is the relay's https:// root. The descriptor is fetched from it,
	// so a different operator is a different value here and nothing else.
	BaseURL string

	// Mode is the kind of address wanted. It must match what the relay serves.
	Mode relayproto.Mode

	// EnrollmentAID is the identifier presented to THIS relay, minted for it and
	// used nowhere else. A public allocation uses its own, never the one used
	// for private allocations (ADR-048 §1).
	EnrollmentAID string

	// KEL returns the enrolment identifier's signed key log as a CESR stream,
	// asked for at every admission and renewal.
	KEL func() []byte

	// Session signs admissions and renewals; Requests signs allocate and
	// release. Both use the enrolment identifier's current key.
	Session  relayproto.Signer
	Requests Signer

	// RAID is the identifier the primary address serves.
	RAID string
	// Name is the public name to hold, in public mode. A public relay gives
	// addresses only at a name or a proven domain.
	Name string

	// Handler answers what arrives through the relay. Requests reach it only
	// after the allocation they arrived on is found in this manager's records,
	// and, for a private address, only when PrivateMayReach allows them.
	Handler http.Handler

	// PrivateMayReach decides what a private address may reach on this
	// Identity Agent. Nil refuses everything on a private address.
	PrivateMayReach func(*http.Request) bool

	// TLS and HTTPClient are for tests; nil uses the system defaults.
	TLS        *tls.Config
	HTTPClient *http.Client
}

// Status is what the rest of the Identity Agent can see about one relay.
type Status struct {
	Provider string          `json:"provider"`
	Mode     relayproto.Mode `json:"mode"`
	// State is "connecting" until the relay serves an address, "active" while
	// it does, and "failed" when the relay refused something trying again
	// will not change (a name somebody else holds, say).
	State  State  `json:"state"`
	Active bool   `json:"active"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
	// Reason is the last failure in plain words, and ReasonCode the same as
	// a short code a screen can act on (see the Reason* constants).
	Reason     string `json:"reason,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	CheckedAt  string `json:"checked_at,omitempty"`
}

// State is where a relay connection is.
type State string

const (
	StateConnecting State = "connecting"
	StateActive     State = "active"
	StateFailed     State = "failed"
)

// Reason codes for the last failure.
const (
	ReasonUnreachable = "unreachable"
	ReasonTaken       = "taken"
	ReasonReserved    = "reserved"
	ReasonQuota       = "quota"
	ReasonInvalidName = "invalid_name"
	ReasonNoName      = "no_name"
	ReasonWrongMode   = "wrong_mode"
	ReasonRefused     = "refused"
	ReasonNotHTTPS    = "not_https"
)

// explain turns a failure into a reason code, plain words, and whether trying
// again could change it.
func explain(err error) (code, words string, permanent bool) {
	var refused *RefusedError
	switch {
	case errors.As(err, &refused):
		switch refused.Code {
		case ReasonTaken:
			return ReasonTaken, "That name is already held by somebody else.", true
		case ReasonReserved:
			return ReasonReserved, "That name is reserved by the relay and cannot be claimed.", true
		case ReasonQuota:
			return ReasonQuota, "This identity already holds as many names as the relay allows.", true
		case ReasonInvalidName:
			return ReasonInvalidName, "A name is 3 to 32 lowercase letters, digits and single inner hyphens.", true
		}
		msg := refused.Message
		if msg == "" {
			msg = refused.Body
		}
		return ReasonRefused, "The relay refused: " + msg, false
	case errors.Is(err, errNoName):
		return ReasonNoName, "Choose a name for your public address. A public relay gives an address only at a name or a proven domain, and none is set.", true
	case errors.Is(err, errWrongMode):
		return ReasonWrongMode, err.Error(), true
	case errors.Is(err, ErrNotHTTPS):
		return ReasonNotHTTPS, "A relay's address must start with https://.", true
	}
	return ReasonUnreachable, "The relay cannot be reached: " + errString(err), false
}

var (
	errNoName    = errors.New("a public relay gives an address only at a name or a proven domain, and none is set")
	errWrongMode = errors.New("the relay serves the other kind of address")

	// ErrNotHTTPS is a relay address that is not https. Everything sent to a
	// relay is either signed or carried over the session, and both depend on
	// the relay's certificate, so a plain-http relay is never used.
	ErrNotHTTPS = errors.New("a relay's address must start with https://")
)

// CheckBaseURL is the one rule for a relay's address: an https URL with a
// host. Every path to a relay passes through it, in Start, and settings use it
// to refuse an address before it is saved.
func CheckBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, raw)
	}
	return nil
}

// Manager keeps one Identity Agent connected to one relay, and reconnects when
// the session drops: the network goes, the machine sleeps, the relay restarts.
type Manager struct {
	cfg Config

	mu      sync.RWMutex
	status  Status
	allocs  []Allocation // the primary address first
	cancel  context.CancelFunc
	done    chan struct{}
	client  *Client
	stopped bool

	// onChange fires when the address appears, changes or is lost, so the
	// Identity Agent republishes where it currently is.
	onChange    []func(url string, active bool)
	onAllocated []func([]Allocation)

	// held serialises everything that changes which addresses are held: the
	// pass that holds them again after an admission, making one for a
	// relationship, and giving one back. Without it a relationship's address
	// made while a reconnection was holding the others could be dropped from
	// the records by the reconnection finishing.
	held sync.Mutex
}

// NewManager prepares a relay client. Nothing happens until Start.
func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg, status: Status{Provider: providerName(cfg.BaseURL), Mode: cfg.Mode, State: StateConnecting}}
}

// OnChange registers a callback for the address appearing, changing or being
// lost. Losing it is reported as well as gaining it: an Identity Agent that only
// hears about success cannot tell "reachable" from "was reachable once".
func (m *Manager) OnChange(fn func(url string, active bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, fn)
}

// OnAllocated registers a callback for the addresses held changing, so they
// can be remembered, secrets included, and held again after a restart.
func (m *Manager) OnAllocated(fn func([]Allocation)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onAllocated = append(m.onAllocated, fn)
}

func (m *Manager) newClient() *Client {
	c := NewClient(m.cfg.BaseURL, m.cfg.Requests)
	if m.cfg.HTTPClient != nil {
		c.HTTPClient = m.cfg.HTTPClient
	}
	return c
}

// Start checks the relay is one this Identity Agent can use, then keeps a
// session to it until Stop. It returns the first failure to reach the relay,
// so the caller can try again later; once it returns nil, reconnecting is this
// manager's job.
func (m *Manager) Start(parent context.Context) error {
	if m.cfg.BaseURL == "" {
		return fmt.Errorf("relay: no operator configured")
	}
	if err := CheckBaseURL(m.cfg.BaseURL); err != nil {
		return m.fail(err)
	}
	if m.cfg.EnrollmentAID == "" || m.cfg.KEL == nil || m.cfg.Session == nil || m.cfg.Requests == nil {
		return fmt.Errorf("relay: an enrolment identifier, its key log and its signers are required")
	}
	if m.cfg.Mode != relayproto.ModePublic && m.cfg.Mode != relayproto.ModePrivate {
		return fmt.Errorf("relay: mode must be public or private, not %q", m.cfg.Mode)
	}
	if m.cfg.Handler == nil {
		return fmt.Errorf("relay: nothing to answer requests with")
	}
	m.mu.Lock()
	switch {
	case m.stopped:
		m.mu.Unlock()
		return ErrStopped
	case m.cancel != nil:
		m.mu.Unlock()
		return fmt.Errorf("relay: already started")
	}
	m.mu.Unlock()

	client := m.newClient()
	desc, err := client.FetchDescriptor(parent)
	if err != nil {
		return m.fail(fmt.Errorf("discover %s: %w", m.cfg.BaseURL, err))
	}
	if desc.Mode != m.cfg.Mode {
		return m.fail(fmt.Errorf("%w: %s serves %s addresses; this Identity Agent wants %s ones",
			errWrongMode, m.cfg.BaseURL, desc.Mode, m.cfg.Mode))
	}

	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	m.mu.Lock()
	if m.stopped {
		// Stopped while the descriptor was being fetched.
		m.mu.Unlock()
		cancel()
		return ErrStopped
	}
	m.cancel, m.done, m.client = cancel, done, client
	m.mu.Unlock()
	go func() {
		defer close(done)
		m.run(ctx, desc.TunnelEndpoint)
	}()
	return nil
}

// Reconnection waits, doubling from minBackoff up to maxBackoff. A session that
// lasted longer than steadySession resets it, so a relay that drops now and
// then is retried promptly rather than after the longest wait.
var (
	minBackoff    = time.Second
	maxBackoff    = time.Minute
	steadySession = time.Minute
)

// run keeps the session up until ctx ends.
func (m *Manager) run(ctx context.Context, endpoint string) {
	backoff := minBackoff
	for ctx.Err() == nil {
		started := time.Now()
		err := m.session(ctx, endpoint)
		if ctx.Err() != nil {
			return
		}
		if m.markLost(err) {
			// Trying again cannot change it: the name is somebody else's,
			// say. It waits for the settings to change.
			return
		}
		if time.Since(started) > steadySession {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// session holds one admitted session: dial, serve, claim the address, and
// return when the session ends.
func (m *Manager) session(ctx context.Context, endpoint string) error {
	sess, err := relayproto.Dial(ctx, &relayproto.AgentConfig{
		URL: endpoint, AID: m.cfg.EnrollmentAID, KEL: m.cfg.KEL, Signer: m.cfg.Session, TLS: m.cfg.TLS,
	})
	if err != nil {
		return err
	}
	defer sess.Close()
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()

	served := make(chan error, 1)
	go func() { served <- sess.Serve(http.HandlerFunc(m.serve)) }()

	// The relay keeps which session serves which address only in memory, so
	// every address is held again on every session.
	m.held.Lock()
	held, err := m.hold(ctx)
	if err != nil {
		m.held.Unlock()
		return err
	}
	m.markActive(held)
	m.held.Unlock()

	select {
	case err := <-served:
		return err
	case <-sess.Done():
		return errors.New("the relay session ended")
	}
}

// hold makes sure the relay serves every address this Identity Agent holds,
// on the session just admitted, and makes the primary one if there is none.
func (m *Manager) hold(ctx context.Context) ([]Allocation, error) {
	m.mu.RLock()
	client, held := m.client, append([]Allocation(nil), m.allocs...)
	m.mu.RUnlock()
	aid := m.cfg.EnrollmentAID

	var out []Allocation
	for _, a := range held {
		if a.Ending {
			// A relationship that has ended: give its address back now if
			// the relay can be asked, and keep asking on every session until
			// it has been.
			if err := client.Release(ctx, aid, a.Label, a.Secret); err != nil && !alreadyGone(err) {
				log.Printf("[relay] could not give back %s yet: %v", a.URL, err)
				out = append(out, a)
			}
			continue
		}
		switch a.Kind {
		case KindPrivate:
			err := client.Bind(ctx, aid, a.Label, a.Secret)
			var refused *RefusedError
			if errors.As(err, &refused) && (refused.Status == http.StatusNotFound || refused.Status == http.StatusForbidden) {
				// The relay no longer has it, or the secret held for it is not
				// the one it was made with. Either way it is not this Identity
				// Agent's to hold, and a new one is made below.
				log.Printf("[relay] %s will not hold %s for this Identity Agent any more: %v", m.cfg.BaseURL, a.URL, err)
				continue
			}
			if err != nil {
				return nil, err
			}
		case KindName:
			if _, err := client.ClaimName(ctx, aid, a.Label); err != nil {
				return nil, err
			}
		}
		out = append(out, a)
	}

	switch m.cfg.Mode {
	case relayproto.ModePrivate:
		if !holdsPrimaryPrivate(out, m.cfg.RAID) {
			secret, commitment := NewSecret()
			label, url, err := client.Allocate(ctx, aid, commitment)
			if err != nil {
				return nil, err
			}
			out = append([]Allocation{{Label: label, URL: url, RAID: m.cfg.RAID, Mode: relayproto.ModePrivate,
				Kind: KindPrivate, Secret: secret}}, out...)
		}
	case relayproto.ModePublic:
		if m.cfg.Name != "" && !holdsName(out, m.cfg.Name) {
			url, err := client.ClaimName(ctx, aid, m.cfg.Name)
			if err != nil {
				return nil, err
			}
			out = append([]Allocation{{Label: m.cfg.Name, URL: url, RAID: m.cfg.RAID, Mode: relayproto.ModePublic,
				Kind: KindName}}, out...)
		}
		if len(out) == 0 {
			return nil, errNoName
		}
	}
	return out, nil
}

// holdsPrimaryPrivate reports whether the address that serves primary (the
// Identity Agent's own enrolment identifier) is among as. An address made for
// a relationship does not count: it serves that relationship's identifier.
func holdsPrimaryPrivate(as []Allocation, primary string) bool {
	for _, a := range as {
		if a.Kind == KindPrivate && !a.Ending && !a.ForRelationship(primary) {
			return true
		}
	}
	return false
}

// alreadyGone is a refusal that says the relay no longer has the address,
// which is what giving it back wanted anyway.
func alreadyGone(err error) bool {
	var refused *RefusedError
	return errors.As(err, &refused) && refused.Status == http.StatusNotFound
}

func holdsName(as []Allocation, name string) bool {
	for _, a := range as {
		if a.Kind == KindName && a.Label == name {
			return true
		}
	}
	return false
}

// serve answers one relayed request, after checking it arrived on an address
// this Identity Agent holds and may be reached through that way.
//
// The allocation comes from the stream's preamble, which a caller cannot set.
// What the allocation may reach comes from this manager's own record of it,
// never from the preamble's mode, which is only what the relay claims.
func (m *Manager) serve(w http.ResponseWriter, r *http.Request) {
	p, ok := relayproto.PreambleFrom(r.Context())
	var a *Allocation
	if ok {
		a = m.lookup(p.Allocation)
	}
	if a == nil {
		http.Error(w, "not an address of this Identity Agent", http.StatusNotFound)
		return
	}
	// A browser loading a page is the relay's to answer, with its own page;
	// none reaches this Identity Agent through a relay (ADR-048).
	if relayproto.IsBrowserNavigation(r) {
		http.Error(w, "an Identity Agent address does not serve pages", http.StatusNotFound)
		return
	}
	if a.Mode == relayproto.ModePrivate && (m.cfg.PrivateMayReach == nil || !m.cfg.PrivateMayReach(r)) {
		http.Error(w, "not reachable at a private address", http.StatusNotFound)
		return
	}
	answer := newProtocolOnly(w, r, a.Mode)
	m.cfg.Handler.ServeHTTP(answer, r)
	answer.finish()
}

// Lookup is the address this Identity Agent holds under label, from its own
// records; nil if it holds none.
func (m *Manager) Lookup(label string) *Allocation { return m.lookup(label) }

func (m *Manager) lookup(label string) *Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.allocs {
		if strings.EqualFold(m.allocs[i].Label, label) && !m.allocs[i].Ending {
			a := m.allocs[i]
			return &a
		}
	}
	return nil
}

// markActive records the addresses held and that they are reachable, and
// announces only a change of the primary one.
func (m *Manager) markActive(held []Allocation) {
	m.mu.Lock()
	wasActive, wasURL := m.status.Active, m.status.URL
	m.allocs = held
	url := held[0].URL
	m.status.Active, m.status.URL, m.status.Error = true, url, ""
	m.status.State, m.status.Reason, m.status.ReasonCode = StateActive, "", ""
	m.status.CheckedAt = nowRFC3339()
	fns := append([]func([]Allocation){}, m.onAllocated...)
	m.mu.Unlock()

	for _, fn := range fns {
		fn(append([]Allocation(nil), held...))
	}
	if !wasActive || wasURL != url {
		log.Printf("[relay] reachable at %s", url)
		m.notify(url, true)
	}
}

// markLost records that the session is down, and why, and reports whether
// the reason is one trying again cannot change. The address is kept, because
// it is asked for again on reconnect, but is no longer offered as reachable.
func (m *Manager) markLost(err error) (permanent bool) {
	code, words, permanent := explain(err)
	m.mu.Lock()
	wasActive := m.status.Active
	m.status.Active = false
	m.status.State = StateConnecting
	if permanent {
		m.status.State = StateFailed
	}
	m.status.Error = errString(err)
	m.status.Reason, m.status.ReasonCode = words, code
	m.status.CheckedAt = nowRFC3339()
	url := m.status.URL
	m.mu.Unlock()
	if wasActive {
		log.Printf("[relay] lost %s: %v", url, err)
		m.notify(url, false)
	} else {
		log.Printf("[relay] could not reach %s yet: %v", m.cfg.BaseURL, err)
	}
	return permanent
}

// Remember restores the addresses held from an earlier start, so the first
// session holds them again rather than making new ones.
func (m *Manager) Remember(held []Allocation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allocs = nil
	for _, a := range held {
		if a.Label == "" {
			continue
		}
		// The mode is this manager's, whatever the record says: a record
		// cannot make a private address public.
		a.Mode = m.cfg.Mode
		m.allocs = append(m.allocs, a)
	}
	if len(m.allocs) > 0 {
		m.status.URL = m.allocs[0].URL
	}
}

// Allocations are the addresses this manager holds, connected or not.
func (m *Manager) Allocations() []Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Allocation(nil), m.allocs...)
}

// Allocation is the primary address, connected or not; nil before the relay
// has granted one.
func (m *Manager) Allocation() *Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.allocs) == 0 {
		return nil
	}
	a := m.allocs[0]
	return &a
}

// ErrStopped is Start's answer once Stop has been called: a manager is
// stopped for good, so a start racing a stop never brings it back.
var ErrStopped = errors.New("relay: this manager has been stopped")

// Stop ends the session for good. It does not give the address back: an address handed
// to counterparties must still work after a restart. Release does that.
func (m *Manager) Stop() {
	m.mu.Lock()
	m.stopped = true
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	wasActive := m.status.Active
	m.status.Active = false
	m.status.State = StateConnecting
	m.status.CheckedAt = nowRFC3339()
	url := m.status.URL
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if wasActive && url != "" {
		m.notify(url, false)
	}
}

// Release gives an address back to the relay and forgets it.
func (m *Manager) Release(ctx context.Context, label string) error {
	a := m.lookup(label)
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if a == nil || client == nil {
		return nil
	}
	var err error
	switch a.Kind {
	case KindPrivate:
		err = client.Release(ctx, m.cfg.EnrollmentAID, a.Label, a.Secret)
	case KindName:
		err = client.ReleaseName(ctx, m.cfg.EnrollmentAID, a.Label)
	case KindDomain:
		err = client.ReleaseDomain(ctx, m.cfg.EnrollmentAID, a.Label)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	kept := m.allocs[:0]
	for _, x := range m.allocs {
		if x.Label != a.Label {
			kept = append(kept, x)
		}
	}
	m.allocs = kept
	held := append([]Allocation(nil), kept...)
	fns := append([]func([]Allocation){}, m.onAllocated...)
	m.mu.Unlock()
	for _, fn := range fns {
		fn(held)
	}
	return nil
}

// ErrNoSession is the answer to making or giving back a relationship's address
// while the relay is not connected: the relay only answers a request signed by
// an enrolment identifier that holds a live session.
var ErrNoSession = errors.New("relay: not connected, so the relay cannot be asked for an address now")

// AllocateFor makes a private address for one relationship, serving raid (the
// pairwise identifier that relationship is given), and holds it. One already
// held for raid is returned rather than another made.
//
// Each address is its own random label, never derived from raid or from
// another address, so two counterparties given two of them cannot link them by
// what they were handed (ADR-048 §6, ADR-036). The relay can: it sees every
// address arrive on this one session (ADR-048 §11).
func (m *Manager) AllocateFor(ctx context.Context, raid string) (*Allocation, error) {
	if m.cfg.Mode != relayproto.ModePrivate {
		return nil, fmt.Errorf("relay: only a private relay gives an address per relationship")
	}
	if raid == "" || raid == m.cfg.RAID {
		return nil, fmt.Errorf("relay: an address per relationship needs the relationship's own identifier")
	}
	m.held.Lock()
	defer m.held.Unlock()

	m.mu.RLock()
	client, active := m.client, m.status.Active
	for _, a := range m.allocs {
		if a.RAID == raid && a.Kind == KindPrivate && !a.Ending {
			m.mu.RUnlock()
			return &a, nil
		}
	}
	m.mu.RUnlock()
	if client == nil || !active {
		return nil, ErrNoSession
	}

	secret, commitment := NewSecret()
	label, url, err := client.Allocate(ctx, m.cfg.EnrollmentAID, commitment)
	if err != nil {
		return nil, err
	}
	a := Allocation{Label: label, URL: url, RAID: raid, Mode: relayproto.ModePrivate, Kind: KindPrivate, Secret: secret}
	m.mu.Lock()
	m.allocs = append(m.allocs, a)
	held := append([]Allocation(nil), m.allocs...)
	fns := append([]func([]Allocation){}, m.onAllocated...)
	m.mu.Unlock()
	for _, fn := range fns {
		fn(held)
	}
	return &a, nil
}

// AddressFor is the private address held for one relationship's identifier;
// nil if there is none.
func (m *Manager) AddressFor(raid string) *Allocation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.allocs {
		if a.RAID == raid && a.Kind == KindPrivate && !a.Ending {
			a := a
			return &a
		}
	}
	return nil
}

// ReleaseFor ends the address held for a relationship's identifier. From this
// call it answers nothing. It is given back to the relay now if the relay can
// be asked; if not, the error says so, the address stays marked as ending and
// is given back on a later session. Ending a relationship that has no address
// of its own (one made before addresses were per relationship) does nothing.
func (m *Manager) ReleaseFor(ctx context.Context, raid string) error {
	m.held.Lock()
	defer m.held.Unlock()

	m.mu.Lock()
	var mine *Allocation
	for i := range m.allocs {
		a := &m.allocs[i]
		if a.RAID == raid && a.ForRelationship(m.cfg.RAID) && !a.Ending {
			a.Ending = true
			c := *a
			mine = &c
			break
		}
	}
	if mine == nil {
		m.mu.Unlock()
		return nil
	}
	client, active := m.client, m.status.Active
	held := append([]Allocation(nil), m.allocs...)
	fns := append([]func([]Allocation){}, m.onAllocated...)
	m.mu.Unlock()
	for _, fn := range fns {
		fn(held)
	}
	if client == nil || !active {
		return ErrNoSession
	}
	if err := client.Release(ctx, m.cfg.EnrollmentAID, mine.Label, mine.Secret); err != nil && !alreadyGone(err) {
		return err
	}
	m.mu.Lock()
	kept := m.allocs[:0]
	for _, x := range m.allocs {
		if x.Label != mine.Label {
			kept = append(kept, x)
		}
	}
	m.allocs = kept
	held = append([]Allocation(nil), kept...)
	m.mu.Unlock()
	for _, fn := range fns {
		fn(held)
	}
	return nil
}

// RequestDomain asks the public relay to serve the identity's own domain, and
// returns the DNS record that proves it.
func (m *Manager) RequestDomain(ctx context.Context, domain string) (*DomainProof, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil || m.cfg.Mode != relayproto.ModePublic {
		return nil, fmt.Errorf("a custom domain is served by a connected public relay")
	}
	return client.RequestDomain(ctx, m.cfg.EnrollmentAID, domain)
}

// VerifyDomain asks the relay to check the DNS record, and holds the domain as
// an address once it does.
func (m *Manager) VerifyDomain(ctx context.Context, domain string) (*Allocation, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil || m.cfg.Mode != relayproto.ModePublic {
		return nil, fmt.Errorf("a custom domain is served by a connected public relay")
	}
	url, err := client.VerifyDomain(ctx, m.cfg.EnrollmentAID, domain)
	if err != nil {
		return nil, err
	}
	a := Allocation{Label: strings.ToLower(domain), URL: url, RAID: m.cfg.RAID, Mode: relayproto.ModePublic, Kind: KindDomain}
	m.mu.Lock()
	// Verifying a domain already held is harmless, and holds it once.
	for _, held := range m.allocs {
		if held.Kind == KindDomain && held.Label == a.Label {
			m.mu.Unlock()
			return &a, nil
		}
	}
	m.allocs = append(m.allocs, a)
	held := append([]Allocation(nil), m.allocs...)
	fns := append([]func([]Allocation){}, m.onAllocated...)
	m.mu.Unlock()
	for _, fn := range fns {
		fn(held)
	}
	return &a, nil
}

// URL is the current address, or empty when the relay is not up. Empty while
// inactive is deliberate: returning the last known address would let a dead
// relay masquerade as a live one.
func (m *Manager) URL() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.status.Active {
		return ""
	}
	return m.status.URL
}

// GetStatus reports what this relay is doing, including while it is down.
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// Config returns the configuration this manager was built with.
func (m *Manager) Config() Config {
	return m.cfg
}

func (m *Manager) fail(err error) error {
	code, words, permanent := explain(err)
	m.mu.Lock()
	m.status.Active = false
	m.status.State = StateConnecting
	if permanent {
		m.status.State = StateFailed
	}
	m.status.Reason, m.status.ReasonCode = words, code
	m.status.Error = err.Error()
	m.status.CheckedAt = nowRFC3339()
	m.mu.Unlock()
	return err
}

func (m *Manager) notify(url string, active bool) {
	m.mu.RLock()
	fns := append([]func(string, bool){}, m.onChange...)
	m.mu.RUnlock()
	for _, fn := range fns {
		fn(url, active)
	}
}

// providerName is the operator's host, so somebody can see which operators they
// rely on.
func providerName(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return baseURL
	}
	return u.Host
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
