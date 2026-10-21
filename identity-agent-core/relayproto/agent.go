package relayproto

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// AgentConfig is what an Identity Agent supplies to connect to a relay.
type AgentConfig struct {
	// URL is the relay's websocket endpoint, wss://. Its host name is the
	// relay's name: a challenge naming any other relay is refused.
	URL string
	// AID is the enrolment identifier this relay knows the Identity Agent by.
	AID string
	// KEL returns the identifier's signed key event log as a CESR stream. It is
	// asked at every admission and renewal, so a rotation reaches the relay at
	// the next one.
	KEL func() []byte
	// Signer signs with the key the log names now.
	Signer Signer
	// TLS configures the connection; nil means the system defaults with a
	// minimum of TLS 1.3.
	TLS *tls.Config
	// Now is the Identity Agent's clock; nil means time.Now.
	Now func() time.Time
}

func (c *AgentConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// AgentSession is an admitted connection to a relay, as the Identity Agent
// holds it.
type AgentSession struct {
	ID        string
	ExpiresAt time.Time

	cfg      *AgentConfig
	mux      *yamux.Session
	exporter []byte
}

// Dial connects to a relay and is admitted. It returns once admitted; call
// Serve to start answering requests.
func Dial(ctx context.Context, cfg *AgentConfig) (*AgentSession, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.TLS != nil {
		tlsCfg = cfg.TLS.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS13 {
			tlsCfg.MinVersion = tls.VersionTLS13
		}
	}
	d := websocket.Dialer{
		HandshakeTimeout: HandshakeTimeout,
		TLSClientConfig:  tlsCfg,
		Subprotocols:     []string{Subprotocol},
		Proxy:            http.ProxyFromEnvironment,
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "wss" || u.Hostname() == "" {
		return nil, fmt.Errorf("a relay is reached at a wss:// address, not %q", cfg.URL)
	}
	ws, resp, err := d.DialContext(ctx, cfg.URL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("connect to the relay: %w (HTTP %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("connect to the relay: %w", err)
	}
	fail := func(err error) (*AgentSession, error) {
		ws.Close()
		return nil, err
	}
	tc, ok := ws.UnderlyingConn().(*tls.Conn)
	if !ok {
		return fail(errors.New("the relay connection is not TLS, so it cannot be bound to"))
	}
	exporter, err := ChannelBinding(tc.ConnectionState())
	if err != nil {
		return fail(err)
	}
	// Until admitted, the relay may send a challenge and an answer, and
	// nothing larger.
	ws.SetReadLimit(MaxControlBytes)
	ws.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	var ch Challenge
	if err := ws.ReadJSON(&ch); err != nil {
		return fail(fmt.Errorf("read the relay's challenge: %w", err))
	}
	if ch.Protocol != ProtocolVersion || ch.Renewal {
		return fail(fmt.Errorf("the relay speaks %q; this Identity Agent speaks %q", ch.Protocol, ProtocolVersion))
	}
	// The statement names the relay it is for. Signing one for a name other
	// than the relay dialled would hand that relay a statement it could not
	// otherwise get.
	if !strings.EqualFold(ch.Service, u.Hostname()) {
		return fail(fmt.Errorf("the relay at %s calls itself %q", u.Hostname(), ch.Service))
	}
	a, err := Answer(ch, exporter, cfg.AID, cfg.KEL(), cfg.Signer, cfg.now())
	if err != nil {
		return fail(err)
	}
	if err := ws.WriteJSON(a); err != nil {
		return fail(err)
	}
	var ok2 Admitted
	if err := ws.ReadJSON(&ok2); err != nil {
		return fail(fmt.Errorf("read the relay's answer: %w", err))
	}
	if ok2.Error != "" || ok2.Session == "" {
		return fail(fmt.Errorf("the relay refused admission: %s", ok2.Error))
	}
	ws.SetReadDeadline(time.Time{})
	exp, _ := time.Parse(time.RFC3339, ok2.ExpiresAt)
	mux, err := yamux.Server(newWSConn(ws), muxConfig())
	if err != nil {
		return fail(err)
	}
	return &AgentSession{ID: ok2.Session, ExpiresAt: exp, cfg: cfg, mux: mux, exporter: exporter}, nil
}

// Close ends the session.
func (a *AgentSession) Close() error { return a.mux.Close() }

// Done is closed when the session ends.
func (a *AgentSession) Done() <-chan struct{} { return a.mux.CloseChan() }

// ViaRelayHeader is set on every request an Identity Agent receives through a
// relay, overwriting anything a caller sent under that name. The Identity
// Agent's gate treats a request carrying it as remote, whatever the relay did
// or did not add.
const ViaRelayHeader = "X-IA-Via-Ingress"

// Serve answers the relay's streams with handler until the session ends. Each
// stream carries exactly one request.
//
// The handler reads [PreambleFrom] to learn which allocation a request arrived
// on. It must look that allocation up in its own records to learn what it may
// reach, and must not trust the preamble's mode: the preamble says what the
// relay claims, and a relay is not trusted to decide what reaches the
// Identity Agent.
func (a *AgentSession) Serve(handler http.Handler) error {
	ln := &streamListener{
		session: a, conns: make(chan net.Conn), done: make(chan struct{}),
		slots: make(chan struct{}, MaxStreamsPerSession),
	}
	go ln.acceptLoop()
	marked := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(ViaRelayHeader, "relay")
		handler.ServeHTTP(w, r)
	})
	srv := &http.Server{
		Handler:           marked,
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if sc, ok := c.(*streamConn); ok {
				return context.WithValue(ctx, preambleKey{}, sc.preamble)
			}
			return ctx
		},
	}
	// One request per stream, whatever the relay sends. A second request on
	// the same stream would be attributed to the first one's allocation.
	srv.SetKeepAlivesEnabled(false)
	go func() {
		<-a.mux.CloseChan()
		srv.Close()
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return errors.New("the relay session ended")
	}
	return err
}

// renew answers the relay's renewal challenge on a control stream.
func (a *AgentSession) renew(st net.Conn) {
	defer st.Close()
	st.SetDeadline(time.Now().Add(HandshakeTimeout))
	r := bufio.NewReader(io.LimitReader(st, MaxControlBytes))
	var ch Challenge
	if err := json.NewDecoder(r).Decode(&ch); err != nil || !ch.Renewal {
		return
	}
	ans, err := Answer(ch, a.exporter, a.cfg.AID, a.cfg.KEL(), a.cfg.Signer, a.cfg.now())
	if err != nil {
		return
	}
	if err := json.NewEncoder(st).Encode(ans); err != nil {
		return
	}
	var res Admitted
	json.NewDecoder(r).Decode(&res)
}

type streamListener struct {
	session *AgentSession
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
	slots   chan struct{}
}

func (l *streamListener) acceptLoop() {
	defer l.Close()
	for {
		st, err := l.session.mux.Accept()
		if err != nil {
			return
		}
		// Every stream the relay holds open counts, including ones half
		// closed, plus one for the renewal's control stream: over that is
		// over the limit the relay should have kept to.
		if l.session.mux.NumStreams() > MaxStreamsPerSession+1 {
			st.Close()
			continue
		}
		go l.admitStream(st)
	}
}

func (l *streamListener) admitStream(st net.Conn) {
	st.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	p, err := readPreamble(st)
	if err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	// A renewal is not a request and takes no request slot. If it did, a
	// relay with every slot busy could not renew, and the lease would end
	// under a working session.
	if p.Mode == modeRenew {
		l.session.renew(st)
		return
	}
	select {
	case l.slots <- struct{}{}:
	default:
		st.Close()
		return
	}
	release := func() { <-l.slots }
	sc := newStreamConn(st, p, release)
	select {
	case l.conns <- sc:
	case <-l.done:
		sc.Close()
	}
}

func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *streamListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *streamListener) Addr() net.Addr { return l.session.mux.Addr() }
