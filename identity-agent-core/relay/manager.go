package relay

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// A relay is how an agent stays reachable at an address it can hand out and
// expect to still work later.
//
// The distinction from a tunnel is what the address is FOR, not how the packets
// move. A tunnel is generic plumbing: it forwards a port and knows nothing about
// who is behind it, which is exactly right for something immediate and
// throwaway. Its address is a byproduct of the vendor's product and dies when
// you leave.
//
// A relay is the same plumbing plus an allocation you can prove is yours. You
// enroll an AID, sign your requests, and the operator can authenticate you
// without being able to impersonate you or quietly reassign your hostname. That
// matters for the case a tunnel cannot serve: a relationship where somebody has
// to be able to find you months from now.
//
// What a relay does NOT give you is a portable URL. Moving from one operator to
// another produces a different hostname, exactly as switching tunnels would. The
// portability is in the protocol — one client, no account, any operator that
// publishes a service descriptor — not in the address. The address is expected
// to change, which is why an agent must publish where it currently is rather
// than relying on a string it handed out once.
//
// The relay learns an AID and a public key, and nothing else. It is deliberately
// never the root: enrollment is per-relay, and an agent that uses several
// operators presents an unrelated AID to each, so no operator can tell that two
// enrollments are the same person.

// Config is what an agent needs to be reachable through one relay operator.
type Config struct {
	// BaseURL is the operator's service root. The descriptor is fetched from
	// it, so a different operator is a different value here and nothing else.
	BaseURL string

	// EnrollmentAID is the AID presented to THIS operator. It should be a
	// pairwise AID minted for this enrollment and used nowhere else — see the
	// note above about what an operator can and cannot learn.
	EnrollmentAID string

	// PublicKeyB64 is the verification key for EnrollmentAID.
	PublicKeyB64 string

	// OOBIUrl is the agent's current OOBI, given to the operator at enrollment.
	OOBIUrl string

	// RAID is the resource this allocation serves. Distinct pairwise AIDs get
	// distinct allocations, so a counterparty's address is not shared with
	// anybody else's.
	RAID string

	// LocalBase is where inbound requests are delivered — the agent's own HTTP
	// server.
	LocalBase string
}

// Status is what the rest of the agent can see about one relay.
type Status struct {
	Provider  string `json:"provider"`
	Active    bool   `json:"active"`
	URL       string `json:"url,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// Manager runs one agent's relationship with one relay operator: discover,
// enroll, allocate, then keep the tunnel up.
//
// It deliberately holds no opinion about WHICH operator to use or how many to
// run. That belongs a layer up, where diversity across operators is decided;
// here the job is to make a single one work and to be honest about whether it
// currently does.
type Manager struct {
	cfg    Config
	signer Signer

	mu         sync.RWMutex
	status     Status
	allocToken string
	tunnel     *TunnelAgent
	cancel     context.CancelFunc

	// onChange fires when the public URL appears, changes or is lost. This is
	// the hook that lets the agent republish where it currently is instead of
	// leaving counterparties pointed at an address that stopped working.
	onChange []func(url string, active bool)
}

// NewManager prepares a relay client. Nothing happens until Start.
func NewManager(cfg Config, signer Signer) *Manager {
	return &Manager{
		cfg:    cfg,
		signer: signer,
		status: Status{Provider: providerName(cfg.BaseURL)},
	}
}

// OnChange registers a callback for the public URL appearing, changing or being
// lost.
//
// Losing it is reported as well as gaining it, and that is the point: an agent
// that only hears about success cannot tell the difference between "reachable"
// and "was reachable once". Both are needed to keep a published endpoint honest.
func (m *Manager) OnChange(fn func(url string, active bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, fn)
}

// Start brings the relay up: fetch the descriptor, enroll, allocate, connect.
//
// Each step needs the one before it, so this reports the first failure rather
// than continuing — an allocation obtained without an enrollment would be a
// hostname nobody can prove belongs to this agent.
func (m *Manager) Start(parent context.Context) error {
	if m.cfg.BaseURL == "" {
		return fmt.Errorf("relay: no operator configured")
	}
	if m.cfg.EnrollmentAID == "" {
		return fmt.Errorf("relay: an enrollment AID is required — a relay allocation must be provably somebody's")
	}

	ctx, cancel := context.WithCancel(parent)

	client := NewClient(m.cfg.BaseURL, "", m.signer)

	desc, err := client.FetchDescriptor(ctx)
	if err != nil {
		cancel()
		return m.fail(fmt.Errorf("discover %s: %w", m.cfg.BaseURL, err))
	}

	enroll, err := client.Enroll(ctx, m.cfg.EnrollmentAID, m.cfg.OOBIUrl, m.cfg.PublicKeyB64)
	if err != nil {
		cancel()
		return m.fail(fmt.Errorf("enroll with %s: %w", m.cfg.BaseURL, err))
	}

	alloc, err := client.Allocate(ctx, m.cfg.EnrollmentAID, m.cfg.RAID)
	if err != nil {
		cancel()
		return m.fail(fmt.Errorf("allocate from %s: %w", m.cfg.BaseURL, err))
	}

	// The descriptor's endpoint is the default, but an allocation may direct
	// this agent somewhere else — a specific node, say. Prefer what the
	// allocation said, because it is the more specific answer.
	endpoint := alloc.TunnelEndpoint
	if endpoint == "" {
		endpoint = enroll.TunnelEndpoint
	}
	if endpoint == "" {
		endpoint = desc.TunnelEndpoint
	}
	if endpoint == "" {
		cancel()
		return m.fail(fmt.Errorf("relay %s offered no tunnel endpoint", m.cfg.BaseURL))
	}

	agent := NewTunnelAgent(endpoint, alloc.AllocationToken, m.cfg.LocalBase)

	m.mu.Lock()
	m.cancel = cancel
	m.tunnel = agent
	m.allocToken = alloc.AllocationToken
	// An allocation is a promise of an address, not yet a working one. Active
	// stays false until the socket is actually up, and markActive announces it
	// from there — publishing an endpoint that has been allocated but not
	// connected would send counterparties somewhere nothing is listening.
	m.status = Status{
		Provider:  providerName(m.cfg.BaseURL),
		Active:    false,
		URL:       strings.TrimRight(alloc.PublicURL, "/"),
		Hostname:  alloc.PublicHostname,
		CheckedAt: nowRFC3339(),
	}
	url := m.status.URL
	m.mu.Unlock()

	go m.run(ctx, agent)

	log.Printf("[relay] allocated %s from %s, connecting", url, providerName(m.cfg.BaseURL))
	return nil
}

// run keeps the tunnel connected, and reports honestly when it is not.
//
// A relay that has dropped is worse than one that was never configured: the
// address is still published, so counterparties keep trying somewhere nothing
// is listening. Marking the status inactive is what lets the layer above notice
// and republish.
//
// This drives session() rather than Run(), which does its own reconnection but
// swallows the error — reconnecting quietly is the right behaviour for a
// transport and the wrong behaviour for something that has to answer "are you
// reachable right now".
func (m *Manager) run(ctx context.Context, agent *TunnelAgent) {
	// Report recovery from where it is actually known — the moment the socket
	// comes up — rather than inferring it. A session is only observable from
	// the outside when it ENDS, so without this hook a reconnected relay would
	// stay marked lost until the next failure.
	agent.mu.Lock()
	agent.onConnect = func() { m.markActive() }
	agent.mu.Unlock()

	backoff := time.Second
	const maxBackoff = time.Minute

	for {
		err := agent.session(ctx)
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		wasActive := m.status.Active
		m.status.Active = false
		m.status.Error = errString(err)
		m.status.CheckedAt = nowRFC3339()
		url := m.status.URL
		m.mu.Unlock()

		if wasActive {
			log.Printf("[relay] lost %s: %v", url, err)
			m.notify(url, false)
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

// markActive records that the socket is up, and says so only on the transition.
// Firing every reconnect would make a flapping relay generate a republication
// storm, which is the opposite of the stability this is meant to provide.
func (m *Manager) markActive() {
	m.mu.Lock()
	was := m.status.Active
	m.status.Active = true
	m.status.Error = ""
	m.status.CheckedAt = nowRFC3339()
	url := m.status.URL
	m.mu.Unlock()

	if !was {
		log.Printf("[relay] reachable at %s", url)
		m.notify(url, true)
	}
}

// Stop disconnects and releases the allocation.
//
// Releasing matters as a courtesy and as hygiene: an operator that is told the
// hostname is finished with can reuse it, and an agent that vanishes without
// saying so leaves an allocation nobody will ever collect.
func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	token := m.allocToken
	url := m.status.URL
	m.cancel = nil
	m.tunnel = nil
	m.allocToken = ""
	m.status.Active = false
	m.status.CheckedAt = nowRFC3339()
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if token != "" {
		ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		client := NewClient(m.cfg.BaseURL, "", m.signer)
		if err := client.Release(ctx, m.cfg.EnrollmentAID, token); err != nil {
			// Worth saying but not worth failing over: the allocation will
			// expire on its own, and the agent is stopping regardless.
			log.Printf("[relay] release failed (allocation will expire): %v", err)
		}
	}

	if url != "" {
		m.notify(url, false)
	}
}

// URL is the current public address, or empty when the relay is not up.
//
// Empty while inactive is deliberate. Returning the last known address would
// let a dead relay masquerade as a live one, which is precisely the failure this
// package exists to make visible.
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

// Config returns the operator and AID this manager was built for.
func (m *Manager) Config() Config {
	return m.cfg
}

func (m *Manager) fail(err error) error {
	m.mu.Lock()
	m.status.Active = false
	m.status.Error = err.Error()
	m.status.CheckedAt = nowRFC3339()
	m.mu.Unlock()
	return err
}

func (m *Manager) notify(url string, active bool) {
	m.mu.RLock()
	callbacks := make([]func(string, bool), len(m.onChange))
	copy(callbacks, m.onChange)
	m.mu.RUnlock()
	for _, cb := range callbacks {
		cb(url, active)
	}
}

// providerName is the operator's host, for logs and for showing somebody which
// operators they are relying on.
func providerName(baseURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
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
