package relayproto

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// ServiceConfig is what a relay supplies to admit Identity Agents.
type ServiceConfig struct {
	Verifier *Verifier
	// Lease is how long one admission lasts; zero means LeaseLifetime.
	Lease time.Duration
	// RenewBefore is how long before a lease ends the relay challenges again;
	// zero means RenewBefore.
	RenewBefore time.Duration
	// Upgrader, when set, upgrades the websocket; its Subprotocols are
	// replaced with this protocol's.
	Upgrader *websocket.Upgrader
	// Logf, when set, receives one line per admission, renewal and refusal.
	Logf func(format string, args ...any)
}

func (c *ServiceConfig) now() time.Time { return time.Now() }

func (c *ServiceConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
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
	closed    chan struct{}
	closeOnce sync.Once
}

// Accept upgrades a request to the relay's websocket endpoint and admits the
// Identity Agent on it. The request must have arrived over TLS terminated by
// this process: the admission is bound to that TLS connection, so a relay
// behind a proxy that terminates TLS cannot use this protocol.
func Accept(w http.ResponseWriter, r *http.Request, cfg *ServiceConfig) (*Session, error) {
	if r.TLS == nil {
		http.Error(w, "the relay protocol runs only over TLS this relay terminates", http.StatusUpgradeRequired)
		return nil, errors.New("request did not arrive over TLS")
	}
	exporter, err := ChannelBinding(*r.TLS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUpgradeRequired)
		return nil, err
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
		return nil, fmt.Errorf("the agent did not offer %s", Subprotocol)
	}

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
	v, err := cfg.Verifier.Verify(a, ch, exporter, cfg.now())
	if err != nil {
		cfg.logf("relay admission refused aid=%s ip=%s: %v", a.Statement.AID, r.RemoteAddr, err)
		ws.WriteJSON(Admitted{Error: err.Error()})
		ws.Close()
		return nil, err
	}
	s := &Session{
		ID: randomToken(16), AID: v.AID, cfg: cfg, exporter: exporter,
		slots: make(chan struct{}, MaxStreamsPerSession), key: v.Key, kel: v.KEL,
		expiresAt: cfg.now().Add(cfg.lease()), closed: make(chan struct{}),
	}
	if err := ws.WriteJSON(Admitted{Session: s.ID, ExpiresAt: s.expiresAt.UTC().Format(time.RFC3339)}); err != nil {
		ws.Close()
		return nil, err
	}
	ws.SetReadDeadline(time.Time{})

	// The relay is the yamux client: it is the side that opens streams. It
	// never accepts one, so an admitted agent has no way to reach anything
	// through the relay.
	mux, err := yamux.Client(newWSConn(ws), muxConfig())
	if err != nil {
		ws.Close()
		return nil, err
	}
	s.mux = mux
	go s.refuseAgentStreams()
	go s.keepLeased()
	cfg.logf("relay admission accepted aid=%s session=%s key=%s ip=%s", s.AID, s.ID, v.Key, r.RemoteAddr)
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
	// The relay's own keep-alive, so an idle session survives proxies and
	// NAT that drop quiet connections, and a dead one is noticed.
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.LogOutput = io.Discard
	return c
}

func (s *Session) refuseAgentStreams() {
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
// session when renewal fails or the lease runs out.
func (s *Session) keepLeased() {
	for {
		s.mu.Lock()
		renewAt := s.expiresAt.Add(-s.cfg.renewBefore())
		s.mu.Unlock()
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
			s.cfg.logf("relay lease not renewed aid=%s session=%s: %v", s.AID, s.ID, err)
			s.Close()
			return
		}
	}
}

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
	if err := json.NewDecoder(bufio.NewReader(st)).Decode(&a); err != nil {
		return fmt.Errorf("read the renewal: %w", err)
	}
	if a.Statement.AID != s.AID {
		return fmt.Errorf("the renewal is for %s, not %s", a.Statement.AID, s.AID)
	}
	v, err := s.cfg.Verifier.Verify(a, ch, s.exporter, s.cfg.now())
	if err != nil {
		json.NewEncoder(st).Encode(Admitted{Error: err.Error()})
		return err
	}
	s.mu.Lock()
	s.key, s.kel = v.Key, v.KEL
	s.expiresAt = s.cfg.now().Add(s.cfg.lease())
	exp := s.expiresAt
	s.mu.Unlock()
	s.cfg.logf("relay lease renewed aid=%s session=%s", s.AID, s.ID)
	return json.NewEncoder(st).Encode(Admitted{Session: s.ID, ExpiresAt: exp.UTC().Format(time.RFC3339)})
}

// KEL is the key event log the session was last admitted against.
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
	})
	return nil
}

// open starts a stream for one request, carrying p.
func (s *Session) open(ctx context.Context, p Preamble) (net.Conn, error) {
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("the session has ended")
	default:
		return nil, errors.New("too many requests in flight to this Identity Agent")
	}
	release := func() { <-s.slots }
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
	return &streamConn{Conn: st, preamble: p, release: release}, nil
}

// Forward carries one request to the Identity Agent on the allocation p
// names. It applies what the relay enforces itself; everything else is the
// Identity Agent's to decide.
//
//   - A private allocation passes only what [PrivateMayReach] allows, with a
//     body no larger than MaxPrivateBodyBytes. The Identity Agent enforces the
//     same and more; this is defence in depth against a relay that is wrong.
//   - A large body, or one of unknown length, is offered with
//     Expect: 100-continue, so the Identity Agent can refuse the request on its
//     headers before the body crosses the relay.
//   - Each request gets its own stream and the stream is never reused, so one
//     allocation's request can never be read as another's.
func (s *Session) Forward(w http.ResponseWriter, r *http.Request, p Preamble) {
	if p.Mode == ModePrivate {
		if !PrivateMayReach(r.Method, r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.ContentLength > MaxPrivateBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxPrivateBodyBytes)
	}
	if p.Host == "" {
		p.Host = r.Host
	}
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
			if strings.Contains(err.Error(), "too many requests") {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "the Identity Agent could not be reached", status)
		},
	}
	proxy.ServeHTTP(w, r)
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
func (g *Registry) Put(s *Session) {
	g.mu.Lock()
	old := g.sessions[s.AID]
	g.sessions[s.AID] = s
	g.mu.Unlock()
	if old != nil && old != s {
		old.Close()
	}
	go func() {
		<-s.Done()
		g.remove(s)
	}()
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
