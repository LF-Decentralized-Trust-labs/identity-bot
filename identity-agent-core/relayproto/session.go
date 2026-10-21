package relayproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// ServiceConfig is what a relay supplies to admit Identity Agents.
type ServiceConfig struct {
	Verifier *Verifier
	// Registry holds the relay's sessions. Accept puts every admitted session
	// in it, and checks a newcomer against the session it would replace.
	Registry *Registry
	// OnAdmit and OnRenew are called with every admission and renewal that
	// has verified and become the identifier's session, so the relay can store
	// the key event log it now holds for the identifier (Verifier.Enrolled
	// reads it back). An error ends the session. The store must keep a log
	// only if it extends the one already stored, so that two admissions
	// racing cannot leave the older one behind.
	OnAdmit func(*Verified) error
	OnRenew func(*Verified) error
	// MaxSessions bounds how many identifiers the relay holds sessions for at
	// once; zero means DefaultMaxSessions. An identifier that already holds a
	// session may always replace it, so a full relay never locks an owner out
	// of reconnecting.
	MaxSessions int
	// Budget, when set, is asked before each admission whether the relay has
	// room for another session, for a relay that budgets memory its own way.
	Budget func() error
	// Lease is how long one admission lasts; zero means LeaseLifetime.
	Lease time.Duration
	// RenewBefore is how long before a lease ends the relay challenges again;
	// zero means RenewBefore.
	RenewBefore time.Duration
	// Upgrader, when set, upgrades the websocket; its Subprotocols are
	// replaced with this protocol's.
	Upgrader *websocket.Upgrader
	// Logf receives one line per admission, renewal, refusal and session end.
	// Nil means the standard logger: the record of who connected is not
	// optional.
	Logf func(format string, args ...any)

	limitersOnce            sync.Once
	publicRate, privateRate *AllocationLimiter
}

func (c *ServiceConfig) now() time.Time { return time.Now() }

func (c *ServiceConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (c *ServiceConfig) maxSessions() int {
	if c.MaxSessions > 0 {
		return c.MaxSessions
	}
	return DefaultMaxSessions
}

// rate returns the relay-wide per-allocation request limiter for a mode.
func (c *ServiceConfig) rate(m Mode) *AllocationLimiter {
	c.limitersOnce.Do(func() {
		c.publicRate = NewAllocationLimiter(PublicRequestsPerMinute)
		c.privateRate = NewAllocationLimiter(PrivateRequestsPerMinute)
	})
	if m == ModePrivate {
		return c.privateRate
	}
	return c.publicRate
}

// Session is one admitted Identity Agent, as the relay holds it.
type Session struct {
	ID  string
	AID string

	cfg      *ServiceConfig
	mux      *yamux.Session
	exporter []byte
	slots    chan struct{}

	mu        sync.Mutex
	key       string
	kel       []byte
	expiresAt time.Time
	inFlight  map[string]int // requests in flight, per allocation
	closed    chan struct{}
	closeOnce sync.Once
}

// Accept upgrades a request to the relay's websocket endpoint, admits the
// Identity Agent on it, and puts the session in the registry. The request must
// have arrived over TLS terminated by this process: the admission is bound to
// that TLS connection, so a relay behind a proxy that terminates TLS cannot
// use this protocol.
func Accept(w http.ResponseWriter, r *http.Request, cfg *ServiceConfig) (*Session, error) {
	if cfg.Registry == nil || cfg.Verifier == nil {
		http.Error(w, "relay misconfigured", http.StatusInternalServerError)
		return nil, errors.New("a relay needs a Verifier and a Registry")
	}
	if r.TLS == nil {
		http.Error(w, "the relay protocol runs only over TLS this relay terminates", http.StatusUpgradeRequired)
		return nil, errors.New("request did not arrive over TLS")
	}
	exporter, err := ChannelBinding(*r.TLS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUpgradeRequired)
		return nil, err
	}
	if cfg.Budget != nil {
		if err := cfg.Budget(); err != nil {
			http.Error(w, "this relay is full", http.StatusServiceUnavailable)
			return nil, err
		}
	}
	up := websocket.Upgrader{HandshakeTimeout: HandshakeTimeout}
	if cfg.Upgrader != nil {
		up = *cfg.Upgrader
	}
	up.Subprotocols = []string{Subprotocol}
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	if ws.Subprotocol() != Subprotocol {
		ws.Close()
		return nil, fmt.Errorf("the Identity Agent did not offer %s", Subprotocol)
	}

	// Nothing before admission may cost more than an admission at its limit.
	ws.SetReadLimit(MaxAdmissionBytes)
	ws.SetReadDeadline(cfg.now().Add(HandshakeTimeout))
	ch := NewChallenge(cfg.Verifier.Service, cfg.now())
	if err := ws.WriteJSON(ch); err != nil {
		ws.Close()
		return nil, err
	}
	var a Admission
	if err := ws.ReadJSON(&a); err != nil {
		ws.Close()
		return nil, fmt.Errorf("read the admission: %w", err)
	}
	refuse := func(err error) (*Session, error) {
		cfg.logf("relay admission refused aid=%q ip=%q: %v", a.Statement.AID, r.RemoteAddr, err)
		ws.WriteJSON(Admitted{Error: err.Error()})
		ws.Close()
		return nil, err
	}
	var live []byte
	if cur, ok := cfg.Registry.Get(a.Statement.AID); ok {
		live = cur.KEL()
	}
	v, err := cfg.Verifier.verify(a, ch, exporter, cfg.now(), live)
	if err != nil {
		return refuse(err)
	}
	s := &Session{
		ID: randomToken(16), AID: v.AID, cfg: cfg, exporter: exporter,
		slots: make(chan struct{}, MaxStreamsPerSession), key: v.Key, kel: v.KEL,
		expiresAt: cfg.now().Add(cfg.lease()), inFlight: map[string]int{},
		closed: make(chan struct{}),
	}
	if err := cfg.Registry.mayReplace(s); err != nil {
		return refuse(err)
	}
	if err := ws.WriteJSON(Admitted{Session: s.ID, ExpiresAt: s.expiresAt.UTC().Format(time.RFC3339)}); err != nil {
		ws.Close()
		return nil, err
	}
	// From here the websocket carries only the session. The relay is the
	// yamux client: it is the side that opens streams. It never accepts one,
	// so an admitted Identity Agent has no way to reach anything through the
	// relay.
	ws.SetReadDeadline(time.Time{})
	mux, err := yamux.Client(newWSConn(ws), muxConfig())
	if err != nil {
		ws.Close()
		return nil, err
	}
	s.mux = mux
	// Put checks again, atomically: another admission for the identifier
	// may have landed since mayReplace.
	if err := cfg.Registry.Put(s); err != nil {
		cfg.logf("relay admission refused aid=%q ip=%q: %v", s.AID, r.RemoteAddr, err)
		mux.Close()
		return nil, err
	}
	// Only a session that is now the identifier's own is recorded. Telling the
	// relay earlier would let a newcomer the registry then refused leave its
	// older log in the record.
	if cfg.OnAdmit != nil {
		if err := cfg.OnAdmit(v); err != nil {
			cfg.logf("relay admission not recorded aid=%q session=%s: %v", s.AID, s.ID, err)
			s.Close()
			return nil, err
		}
	}
	go s.refuseIdentityAgentStreams()
	go s.keepLeased()
	cfg.logf("relay admission accepted aid=%q session=%s key=%s ip=%q", s.AID, s.ID, v.Key, r.RemoteAddr)
	return s, nil
}

func (c *ServiceConfig) lease() time.Duration {
	if c.Lease > 0 {
		return c.Lease
	}
	return LeaseLifetime
}

func (c *ServiceConfig) renewBefore() time.Duration {
	if c.RenewBefore > 0 {
		return c.RenewBefore
	}
	return RenewBefore
}

func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = MaxStreamsPerSession
	c.MaxStreamWindowSize = StreamWindowBytes
	c.StreamCloseTimeout = StreamCloseTimeout
	// The relay's own keep-alive, so an idle session survives proxies and
	// NAT that drop quiet connections, and a dead one is noticed.
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.LogOutput = io.Discard
	return c
}

func (s *Session) refuseIdentityAgentStreams() {
	for {
		st, err := s.mux.Accept()
		if err != nil {
			s.Close()
			return
		}
		st.Close()
	}
}

// keepLeased renews the admission before each lease ends, and closes the
// session as soon as a renewal fails.
func (s *Session) keepLeased() {
	for {
		renewAt := s.ExpiresAt().Add(-s.cfg.renewBefore())
		wait := time.Until(renewAt)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-s.closed:
			return
		case <-s.mux.CloseChan():
			s.Close()
			return
		case <-time.After(wait):
		}
		if err := s.renew(); err != nil {
			s.cfg.logf("relay lease not renewed aid=%q session=%s: %v", s.AID, s.ID, err)
			s.Close()
			return
		}
	}
}

// renew challenges the Identity Agent again on a control stream. The control
// stream is not a request, so it takes no request slot.
func (s *Session) renew() error {
	st, err := s.mux.OpenStream()
	if err != nil {
		return err
	}
	defer st.Close()
	// The answer has to arrive before the lease it renews runs out.
	deadline := time.Now().Add(HandshakeTimeout)
	if exp := s.ExpiresAt(); exp.Before(deadline) {
		deadline = exp
	}
	st.SetDeadline(deadline)
	if err := writePreamble(st, Preamble{Mode: modeRenew}); err != nil {
		return err
	}
	ch := NewChallenge(s.cfg.Verifier.Service, s.cfg.now())
	ch.Renewal = true
	if err := json.NewEncoder(st).Encode(ch); err != nil {
		return err
	}
	var a Admission
	if err := json.NewDecoder(io.LimitReader(st, MaxAdmissionBytes)).Decode(&a); err != nil {
		return fmt.Errorf("read the renewal: %w", err)
	}
	if a.Statement.AID != s.AID {
		return fmt.Errorf("the renewal is for %q, not %q", a.Statement.AID, s.AID)
	}
	// The session's own log is the newest the relay has seen for this
	// identifier; the renewal's log must extend it.
	v, err := s.cfg.Verifier.verify(a, ch, s.exporter, s.cfg.now(), s.KEL())
	if err == nil && s.cfg.OnRenew != nil {
		err = s.cfg.OnRenew(v)
	}
	if err != nil {
		json.NewEncoder(st).Encode(Admitted{Error: err.Error()})
		return err
	}
	s.mu.Lock()
	s.key, s.kel = v.Key, v.KEL
	s.expiresAt = s.cfg.now().Add(s.cfg.lease())
	exp := s.expiresAt
	s.mu.Unlock()
	s.cfg.logf("relay lease renewed aid=%q session=%s key=%s", s.AID, s.ID, v.Key)
	return json.NewEncoder(st).Encode(Admitted{Session: s.ID, ExpiresAt: exp.UTC().Format(time.RFC3339)})
}

// KEL is the key event log the session was last admitted or renewed against.
func (s *Session) KEL() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kel
}

// ExpiresAt is when the current lease ends.
func (s *Session) ExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.closed }

// Close ends the session and every stream on it, inner websockets included.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.mux != nil {
			s.mux.Close()
		}
		s.cfg.logf("relay session ended aid=%q session=%s", s.AID, s.ID)
	})
	return nil
}

var (
	errSessionFull    = errors.New("too many requests in flight to this Identity Agent")
	errAllocationFull = errors.New("too many requests in flight on this address")
)

// open starts a stream for one request, carrying p.
func (s *Session) open(ctx context.Context, p Preamble) (net.Conn, error) {
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("the session has ended")
	default:
		return nil, errSessionFull
	}
	release := func() { <-s.slots }
	// A stream this end has closed lives on until the Identity Agent closes
	// it too, or StreamCloseTimeout passes. It still costs memory, so it still
	// counts: the slot alone would be free the moment this end closed.
	// The renewal's control stream is opened outside this check, so a full
	// session can still renew.
	if s.mux.NumStreams() >= MaxStreamsPerSession {
		release()
		return nil, errSessionFull
	}
	st, err := s.mux.OpenStream()
	if err != nil {
		release()
		return nil, err
	}
	if err := writePreamble(st, p); err != nil {
		st.Close()
		release()
		return nil, err
	}
	return newStreamConn(st, p, release), nil
}

// takeAllocation counts a request against its allocation's in-flight limit.
func (s *Session) takeAllocation(p Preamble) (func(), bool) {
	limit := PublicInFlightPerAllocation
	if p.Mode == ModePrivate {
		limit = PrivateInFlightPerAllocation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight[p.Allocation] >= limit {
		return nil, false
	}
	s.inFlight[p.Allocation]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.inFlight[p.Allocation]--; s.inFlight[p.Allocation] <= 0 {
			delete(s.inFlight, p.Allocation)
		}
	}, true
}

// Forward carries one request to the Identity Agent on the allocation p
// names. The relay looks up p from its own records of which allocation the
// request's host is; it never takes any part of p from the request. Forward
// applies what the relay enforces itself; everything else is the Identity
// Agent's to decide.
//
//   - Requests per minute and requests in flight are limited per allocation,
//     by mode, so one address cannot starve the others.
//   - A private allocation passes only what [PrivateMayReach] allows, at its
//     exact path, without an upgrade, with a body no larger than
//     MaxPrivateBodyBytes. The Identity Agent applies its own rule as well;
//     this is defence in depth against a mistake on either side.
//   - A large body, or one of unknown length, is offered with
//     Expect: 100-continue. That lets an Identity Agent refuse on headers
//     before the body crosses; it is a courtesy, not a gate.
//   - Each request gets its own stream and the stream is never reused, so one
//     allocation's request can never be read as another's.
func (s *Session) Forward(w http.ResponseWriter, r *http.Request, p Preamble) {
	if p.Host == "" || p.Allocation == "" {
		http.Error(w, "the relay has no record of this address", http.StatusBadGateway)
		return
	}
	if p.Mode != ModePublic && p.Mode != ModePrivate {
		http.Error(w, "the relay has no record of this address", http.StatusBadGateway)
		return
	}
	if p.Mode == ModePrivate {
		if !privateRequestAllowed(r) {
			http.NotFound(w, r)
			return
		}
		if r.ContentLength > MaxPrivateBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxPrivateBodyBytes)
	}
	if !s.cfg.rate(p.Mode).Allow(p.Allocation) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	done, ok := s.takeAllocation(p)
	if !ok {
		http.Error(w, errAllocationFull.Error(), http.StatusServiceUnavailable)
		return
	}
	defer done()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = p.Host
			pr.Out.Host = p.Host
			pr.SetXForwarded()
			if pr.Out.Body != nil && pr.Out.Body != http.NoBody &&
				(pr.Out.ContentLength > LargeBodyBytes || pr.Out.ContentLength < 0) {
				pr.Out.Header.Set("Expect", "100-continue")
			}
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return s.open(ctx, p)
			},
			DisableKeepAlives:      true,
			ExpectContinueTimeout:  10 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
		},
		FlushInterval: -1, // stream responses as they are written
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			status := http.StatusBadGateway
			if errors.Is(err, errSessionFull) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "the Identity Agent could not be reached", status)
		},
	}
	proxy.ServeHTTP(w, r)
}

// privateRequestAllowed applies [PrivateMayReach] to a request as it will
// reach the Identity Agent: its exact path, with no percent-encoding that
// could be read two ways, and no protocol upgrade.
func privateRequestAllowed(r *http.Request) bool {
	if r.URL.EscapedPath() != r.URL.Path {
		return false
	}
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	return PrivateMayReach(r.Method, r.URL.Path)
}

// Registry holds the relay's admitted sessions, one per identifier.
type Registry struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewRegistry makes an empty registry.
func NewRegistry() *Registry { return &Registry{sessions: map[string]*Session{}} }

// Put makes s the identifier's session. A session it replaces is closed, and
// its streams with it, once s is in place, so a request is never routed to
// neither.
//
// A newcomer must hold the same key event log as the session it replaces, or
// a longer one. One holding a shorter log has a key that has since been
// rotated away and is refused, whatever the relay's stored record said.
func (g *Registry) Put(s *Session) error {
	g.mu.Lock()
	old := g.sessions[s.AID]
	if err := g.admissible(s, old); err != nil {
		g.mu.Unlock()
		return err
	}
	g.sessions[s.AID] = s
	g.mu.Unlock()
	if old != nil && old != s {
		old.Close()
	}
	go func() {
		<-s.Done()
		g.remove(s)
	}()
	return nil
}

func (g *Registry) mayReplace(s *Session) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admissible(s, g.sessions[s.AID])
}

// admissible is checked with the registry locked, so the count and the
// replacement are decided together.
func (g *Registry) admissible(s, old *Session) error {
	if old == nil && s.cfg != nil && len(g.sessions) >= s.cfg.maxSessions() {
		return errors.New("this relay holds its maximum number of sessions")
	}
	return extends(s, old)
}

func extends(s, old *Session) error {
	if old != nil && old != s && !logExtends(s.KEL(), old.KEL()) {
		return fmt.Errorf("the key event log presented for %q does not extend the live session's", s.AID)
	}
	return nil
}

// remove forgets s only if it is still the identifier's session. A session
// that ends after being replaced must not take its replacement with it.
func (g *Registry) remove(s *Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions[s.AID] == s {
		delete(g.sessions, s.AID)
	}
}

// Get returns the identifier's live session.
func (g *Registry) Get(aid string) (*Session, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[aid]
	return s, ok
}

// Len is how many sessions the registry holds.
func (g *Registry) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

// Revoke ends the identifier's session at once: for a relay that sees a
// rotation or revocation in the identifier's key state between leases.
func (g *Registry) Revoke(aid string) {
	g.mu.Lock()
	s := g.sessions[aid]
	delete(g.sessions, aid)
	g.mu.Unlock()
	if s != nil {
		s.Close()
	}
}
