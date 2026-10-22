package relayproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	keri "github.com/grapeid/keri-go"
)

// identity is an enrolment identifier with a signed key event log, made and
// signed with keri-go the way an Identity Agent makes its own.
type identity struct {
	t        *testing.T
	aid      string
	current  *keri.SoftwareSigner
	next     *keri.SoftwareSigner
	lastSAID string
	sn       int
	messages [][]byte
	mu       sync.Mutex
}

func newIdentity(t *testing.T) *identity {
	t.Helper()
	cur, _ := keri.GenerateSigner(true)
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd},
		Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	return &identity{t: t, aid: parsed.Identifier, current: cur, next: nxt,
		lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}
}

func (id *identity) kel() []byte {
	id.mu.Lock()
	defer id.mu.Unlock()
	out, err := keri.ExportKEL(id.messages)
	if err != nil {
		id.t.Fatal(err)
	}
	return out
}

func (id *identity) Sign(data []byte) ([]byte, error) {
	id.mu.Lock()
	s := id.current
	id.mu.Unlock()
	return s.Sign(data)
}

// rotate moves the identifier to its pre-committed next key.
func (id *identity) rotate() {
	id.mu.Lock()
	defer id.mu.Unlock()
	newNext, _ := keri.GenerateSigner(true)
	pub, _ := id.next.PublicKey()
	npub, _ := newNext.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: id.aid, Keys: []string{pub},
		PriorSAID: id.lastSAID, SN: id.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		id.t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, id.next)
	if err != nil {
		id.t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	id.sn++
	id.lastSAID = parsed.SAID
	id.current, id.next = id.next, newNext
	id.messages = append(id.messages, signed.Message)
}

// relay is a test relay: a TLS 1.3 endpoint agents connect to, and a front
// door that routes by Host the way a relay routes by allocation.
type relay struct {
	t        *testing.T
	registry *Registry
	cfg      *ServiceConfig
	tunnel   *httptest.Server
	front    *httptest.Server
	held     sync.Map // aid -> []byte
	logs     chan string
	routes   map[string]Preamble
	aidFor   map[string]string
	accepted chan error
}

func newRelay(t *testing.T, cfg *ServiceConfig) *relay {
	t.Helper()
	r := &relay{t: t, registry: NewRegistry(), logs: make(chan string, 100),
		routes: map[string]Preamble{}, aidFor: map[string]string{}, accepted: make(chan error, 1000)}
	if cfg == nil {
		cfg = &ServiceConfig{}
	}
	cfg.Registry = r.registry
	enrolled := func(aid string) ([]byte, bool) {
		v, ok := r.held.Load(aid)
		if !ok {
			return nil, false
		}
		return v.([]byte), true
	}
	if cfg.Verifier != nil && cfg.Verifier.Enrolled != nil {
		enrolled = cfg.Verifier.Enrolled
	}
	cfg.Verifier = &Verifier{Enrolled: enrolled}
	store := func(v *Verified) error { r.held.Store(v.AID, v.KEL); return nil }
	if cfg.OnAdmit == nil {
		cfg.OnAdmit = store
	}
	if cfg.OnRenew == nil {
		cfg.OnRenew = store
	}
	cfg.Logf = func(f string, a ...any) {
		select {
		case r.logs <- fmt.Sprintf(f, a...):
		default:
		}
	}
	r.cfg = cfg
	r.tunnel = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, err := Accept(w, req, r.cfg)
		r.accepted <- err
	}))
	r.tunnel.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	r.tunnel.StartTLS()
	// A relay's name is the host Identity Agents dial it at.
	if cfg.Verifier.Service == "" {
		cfg.Verifier.Service = "127.0.0.1"
	}
	r.front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, ok := r.routes[req.Host]
		if !ok {
			http.NotFound(w, req)
			return
		}
		s, ok := r.registry.Get(r.aidFor[req.Host])
		if !ok {
			http.Error(w, "offline", http.StatusBadGateway)
			return
		}
		s.Forward(w, req, p)
	}))
	t.Cleanup(func() { r.front.Close(); r.tunnel.Close() })
	return r
}

func (r *relay) route(host, aid string, p Preamble) {
	r.routes[host] = p
	r.aidFor[host] = aid
}

func (r *relay) agentConfig(id *identity) *AgentConfig {
	return &AgentConfig{
		URL:    "wss" + strings.TrimPrefix(r.tunnel.URL, "https"),
		AID:    id.aid,
		KEL:    id.kel,
		Signer: id,
		TLS:    r.tunnel.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

// connect dials, serves handler, and waits until the relay holds the session.
func (r *relay) connect(id *identity, handler http.Handler) *AgentSession {
	r.t.Helper()
	a, err := Dial(context.Background(), r.agentConfig(id))
	if err != nil {
		r.t.Fatalf("dial: %v", err)
	}
	go a.Serve(handler)
	r.t.Cleanup(func() { a.Close() })
	r.waitFor(func() bool { s, ok := r.registry.Get(id.aid); return ok && s.ID == a.ID })
	return a
}

func (r *relay) waitFor(cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			r.t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *relay) do(host string, req *http.Request) *http.Response {
	r.t.Helper()
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp
}

// echo reports what the Identity Agent saw of a request.
func echo(w http.ResponseWriter, r *http.Request) {
	p, ok := PreambleFrom(r.Context())
	body, _ := io.ReadAll(r.Body)
	json.NewEncoder(w).Encode(map[string]any{
		"method": r.Method, "path": r.URL.Path, "query": r.URL.RawQuery,
		"headers": r.Header, "body": string(body), "relayed": ok,
		"allocation": p.Allocation, "mode": p.Mode, "host": r.Host,
	})
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestARequestCrossesTheRelayAsHTTP(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(echo))

	req, _ := http.NewRequest("POST", r.front.URL+"/api/things?a=1&b=two&a=3", strings.NewReader("hello"))
	req.Header.Add("X-Multi", "first")
	req.Header.Add("X-Multi", "second")
	got := decode(t, r.do("acme.relay.test", req))

	if got["query"] != "a=1&b=two&a=3" {
		t.Errorf("query string arrived as %q", got["query"])
	}
	if h := got["headers"].(map[string]any)["X-Multi"]; fmt.Sprint(h) != "[first second]" {
		t.Errorf("a repeated header arrived as %v", h)
	}
	if got["body"] != "hello" || got["method"] != "POST" || got["path"] != "/api/things" {
		t.Errorf("request arrived as %v", got)
	}
	if got["relayed"] != true || got["allocation"] != "pub-1" || got["mode"] != "public" {
		t.Errorf("preamble arrived as %v", got)
	}
	if fwd := got["headers"].(map[string]any)["X-Forwarded-For"]; fwd == nil {
		t.Error("a relayed request must carry a forwarding header, so the Identity Agent treats it as remote")
	}
}

// The allocation a request is attributed to comes from the relay's preamble.
// Nothing a caller sends can change it, and requests on different allocations
// sharing one session are never confused, because each has its own stream.
func TestTheAllocationCannotBeClaimedByTheCaller(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("pub.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "pub.relay.test"})
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-7", Mode: ModePrivate, Host: "a1b2.relay.test"})
	r.connect(id, http.HandlerFunc(echo))

	var wg sync.WaitGroup
	var wrong atomic.Int32
	gate := make(chan struct{}, PrivateInFlightPerAllocation) // within one address's in-flight limit
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			host, want, path := "pub.relay.test", "pub-1", "/api/x"
			if i%2 == 1 {
				host, want, path = "a1b2.relay.test", "priv-7", "/oobi/"+id.aid
			}
			req, _ := http.NewRequest("GET", r.front.URL+path, nil)
			// A caller trying every way it has to name another allocation.
			req.Header.Set("X-Relay-Allocation", "priv-7")
			req.Header.Set("X-IA-Allocation", "priv-7")
			got := decode(t, r.do(host, req))
			if got["allocation"] != want {
				wrong.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n := wrong.Load(); n > 0 {
		t.Fatalf("%d requests were attributed to the wrong allocation", n)
	}
}

func TestAPrivateAllocationPassesOnlyArtifactsAndMessages(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-7", Mode: ModePrivate, Host: "a1b2.relay.test"})
	var reached atomic.Int32
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		reached.Add(1)
		echo(w, q)
	}))

	for _, c := range []struct {
		method, path string
		pass         bool
	}{
		{"GET", "/oobi/" + id.aid, true},
		{"GET", "/" + id.aid + "/did.json", true},
		{"POST", "/didcomm", true},
		{"GET", "/api/identity", false},
		{"POST", "/api/sealed", false},
		{"DELETE", "/didcomm", false},
	} {
		before := reached.Load()
		req, _ := http.NewRequest(c.method, r.front.URL+c.path, strings.NewReader("{}"))
		resp := r.do("a1b2.relay.test", req)
		resp.Body.Close()
		got := reached.Load() > before
		if got != c.pass {
			t.Errorf("%s %s reached the Identity Agent: %v, want %v (status %d)", c.method, c.path, got, c.pass, resp.StatusCode)
		}
	}
}

func TestAResponseStreamsAsItIsWritten(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	release := make(chan struct{})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second\n")
	}))
	req, _ := http.NewRequest("GET", r.front.URL+"/events", nil)
	resp := r.do("acme.relay.test", req)
	defer resp.Body.Close()
	lines := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() { l, _ := lines.ReadString('\n'); first <- l }()
	select {
	case l := <-first:
		if l != "first\n" {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("the first part of the response did not arrive until the whole response was written")
	}
	close(release)
	if l, _ := lines.ReadString('\n'); l != "second\n" {
		t.Fatalf("second line %q", l)
	}
}

// A websocket opens through a public address, where an identity's own front
// ends keep one, and never through a private one.
func TestAWebsocketOpensOnlyThroughAPublicAddress(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-1", Mode: ModePrivate, Host: "a1b2.relay.test"})
	up := websocket.Upgrader{}
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		c, err := up.Upgrade(w, q, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			kind, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			c.WriteMessage(kind, append([]byte("echo:"), msg...))
		}
	}))
	dial := func(host string) (*websocket.Conn, error) {
		d := websocket.Dialer{}
		c, _, err := d.Dial("ws"+strings.TrimPrefix(r.front.URL, "http")+"/oobi/"+id.aid, http.Header{"Host": {host}})
		return c, err
	}
	c, err := dial("acme.relay.test")
	if err != nil {
		t.Fatalf("the websocket did not open through the public address: %v", err)
	}
	defer c.Close()
	for _, m := range []string{"one", "two"} {
		c.WriteMessage(websocket.TextMessage, []byte(m))
		_, got, err := c.ReadMessage()
		if err != nil || string(got) != "echo:"+m {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	if c, err := dial("a1b2.relay.test"); err == nil {
		c.Close()
		t.Error("a websocket opened through a private address")
	}
}

func TestManyRequestsAreInFlightAtOnce(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	var inFlight, peak atomic.Int32
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		inFlight.Add(-1)
		io.WriteString(w, "ok")
	}))
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", r.front.URL+"/slow", nil)
			resp := r.do("acme.relay.test", req)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if peak.Load() < 10 {
		t.Errorf("at most %d requests were in flight together", peak.Load())
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("50 requests of 200ms took %v", d)
	}
}

func TestALargeBodyWaitsForTheIdentityAgentToAcceptIt(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	var expect atomic.Value
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		expect.Store(q.Header.Get("Expect"))
		http.Error(w, "not you", http.StatusForbidden)
	}))
	req, _ := http.NewRequest("POST", r.front.URL+"/api/backup/receive", bytes.NewReader(make([]byte, 2*LargeBodyBytes)))
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if expect.Load() != "100-continue" {
		t.Fatalf("a large body was sent without asking first (Expect=%q)", expect.Load())
	}
}

// A reconnecting Identity Agent replaces its session in one step: requests go
// to the new one, the old one ends, and the old one ending does not take the
// new one with it.
func TestAReconnectReplacesTheSession(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	first := r.connect(id, http.HandlerFunc(echo))
	oldSession, _ := r.registry.Get(id.aid)
	second := r.connect(id, http.HandlerFunc(echo))
	if first.ID == second.ID {
		t.Fatal("two admissions got one session id")
	}
	select {
	case <-oldSession.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the replaced session was left open")
	}
	time.Sleep(100 * time.Millisecond) // let the old session's cleanup run
	s, ok := r.registry.Get(id.aid)
	if !ok || s.ID != second.ID {
		t.Fatal("the old session ending removed the new one")
	}
	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	if resp := r.do("acme.relay.test", req); resp.StatusCode != 200 {
		t.Fatalf("status %d after reconnect", resp.StatusCode)
	}
}

func TestRevokingAnIdentifierEndsItsSession(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	a := r.connect(id, http.HandlerFunc(echo))
	r.registry.Revoke(id.aid)
	select {
	case <-a.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the agent's session survived revocation")
	}
}

// A statement answers one challenge, on one connection, at one relay, for a
// short time. A captured one is worth nothing anywhere else.
func TestACapturedStatementIsUselessElsewhere(t *testing.T) {
	id := newIdentity(t)
	v := &Verifier{Service: "relay.test", Enrolled: func(string) ([]byte, bool) { return nil, false }}
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	exporter := bytes.Repeat([]byte{1}, ExporterLength)
	a, err := Answer(ch, exporter, id.aid, id.kel(), id, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(a, ch, exporter, now); err != nil {
		t.Fatalf("the genuine statement was refused: %v", err)
	}

	other := bytes.Repeat([]byte{2}, ExporterLength)
	if _, err := v.Verify(a, ch, other, now); err == nil {
		t.Error("a statement made for one connection was accepted on another")
	}
	if _, err := v.Verify(a, NewChallenge("relay.test", now), exporter, now); err == nil {
		t.Error("a statement answering one challenge was accepted for another")
	}
	if _, err := v.Verify(a, ch, exporter, now.Add(ClockSkew+time.Second)); err == nil {
		t.Error("a stale statement was accepted")
	}
	if _, err := (&Verifier{Service: "elsewhere.test", Enrolled: v.Enrolled}).Verify(a, ch, exporter, now); err == nil {
		t.Error("a statement made for one relay was accepted by another")
	}
	forged := a
	forged.Statement.AID = newIdentity(t).aid
	if _, err := v.Verify(forged, ch, exporter, now); err == nil {
		t.Error("a statement relabelled with another identifier was accepted")
	}
	impostor := newIdentity(t)
	stolen, _ := Answer(ch, exporter, id.aid, id.kel(), impostor, now)
	if _, err := v.Verify(stolen, ch, exporter, now); err == nil {
		t.Error("a statement signed by a key the log does not name was accepted")
	}
}

// The real channel binding differs per TLS connection, so the property above
// holds on the wire and not only in a unit test.
func TestEachConnectionHasItsOwnChannelBinding(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		cb, err := ChannelBinding(*q.TLS)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(cb)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	get := func() []byte {
		c := srv.Client()
		c.Transport.(*http.Transport).DisableKeepAlives = true
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	a, b := get(), get()
	if len(a) != ExporterLength || bytes.Equal(a, b) {
		t.Fatalf("channel bindings %x and %x", a, b)
	}
}

func TestAKeyLogMayOnlyBeExtended(t *testing.T) {
	id := newIdentity(t)
	held := id.kel()
	v := &Verifier{Service: "relay.test", Enrolled: func(string) ([]byte, bool) { return held, true }}
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	ex := bytes.Repeat([]byte{3}, ExporterLength)

	id.rotate()
	a, _ := Answer(ch, ex, id.aid, id.kel(), id, now)
	got, err := v.Verify(a, ch, ex, now)
	if err != nil {
		t.Fatalf("a rotated log that extends the held one was refused: %v", err)
	}
	if pub, _ := id.current.PublicKey(); got.Key != pub {
		t.Fatal("the admission was checked against the old key")
	}

	// The same identifier presenting a different history.
	other := newIdentity(t)
	rewritten, _ := Answer(ch, ex, id.aid, other.kel(), id, now)
	if _, err := v.Verify(rewritten, ch, ex, now); err == nil {
		t.Fatal("a log that does not extend the held one was accepted")
	}
	big := Admission{Statement: a.Statement, Signature: a.Signature, KEL: strings.Repeat("A", b64.EncodedLen(MaxKELBytes)+4)}
	if _, err := v.Verify(big, ch, ex, now); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("an oversized log was not refused for its size: %v", err)
	}
}

// A lease is renewed in place before it ends: the session, and any request or
// websocket on it, carries on.
func TestALeaseIsRenewedWithoutDroppingTheSession(t *testing.T) {
	r := newRelay(t, &ServiceConfig{Lease: 1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond})
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	a := r.connect(id, http.HandlerFunc(echo))
	s, _ := r.registry.Get(id.aid)
	firstExpiry := s.ExpiresAt()

	time.Sleep(2500 * time.Millisecond)
	select {
	case <-a.Done():
		t.Fatal("the session ended at its first lease")
	default:
	}
	if !s.ExpiresAt().After(firstExpiry) {
		t.Fatal("the lease was not renewed")
	}
	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	if resp := r.do("acme.relay.test", req); resp.StatusCode != 200 {
		t.Fatalf("status %d after renewal", resp.StatusCode)
	}
}

// An Identity Agent that can no longer sign for its identifier — its key was
// rotated away from under it, or it is an impostor holding a stolen session —
// loses the session at the next renewal.
func TestALeaseThatCannotBeRenewedEnds(t *testing.T) {
	r := newRelay(t, &ServiceConfig{Lease: 1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond})
	id := newIdentity(t)
	a := r.connect(id, http.HandlerFunc(echo))
	id.mu.Lock()
	id.current, _ = keri.GenerateSigner(true) // no longer the key the log names
	id.mu.Unlock()
	select {
	case <-a.Done():
	case <-time.After(4 * time.Second):
		t.Fatal("a session that could not renew outlived its lease")
	}
	if _, ok := r.registry.Get(id.aid); ok {
		t.Fatal("the relay still routes to a session whose lease ended")
	}
}

func TestPrivateMayReach(t *testing.T) {
	aid := "E" + strings.Repeat("a", 43)
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/" + aid + "/did.json", true},
		{"HEAD", "/" + aid + "/keri.cesr", true},
		{"GET", "/oobi/" + aid, true},
		{"GET", "/public/" + aid + "/did.json", true},
		{"POST", "/_register", true},
		{"POST", "/public/_register", true},
		{"GET", "/.well-known/did-configuration.json", false},
		{"POST", "/didcomm", true},
		{"POST", "/didcomm/", false},
		{"GET", "/oobi/" + aid + "/", false},
		{"GET", "//oobi/" + aid, false},
		{"GET", "/didcomm", false},
		{"POST", "/" + aid + "/did.json", false},
		{"GET", "/api/identity", false},
		{"GET", "/" + aid + "/did.json/../../api", false},
		{"GET", "/short/did.json", false},
	} {
		if got := PrivateMayReach(c.method, c.path); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestAllocationTokensAreRandomDNSLabels(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := NewAllocationToken()
		if len(tok) != 26 || strings.ToLower(tok) != tok || seen[tok] {
			t.Fatalf("token %q", tok)
		}
		seen[tok] = true
	}
}

func TestAnAllocationIsRateLimited(t *testing.T) {
	now := time.Now()
	l := NewAllocationLimiter(3)
	l.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatal("refused within the limit")
		}
	}
	if l.Allow("a") {
		t.Fatal("allowed past the limit")
	}
	if !l.Allow("b") {
		t.Fatal("one allocation's traffic counted against another")
	}
	now = now.Add(time.Minute)
	if !l.Allow("a") {
		t.Fatal("the window did not reset")
	}
}

func TestPreambleRoundTripAndLimits(t *testing.T) {
	var buf bytes.Buffer
	p := Preamble{Allocation: "x", Mode: ModePrivate, Host: "h"}
	if err := writePreamble(&buf, p); err != nil {
		t.Fatal(err)
	}
	got, err := readPreamble(&buf)
	if err != nil || got != p {
		t.Fatalf("%v %v", got, err)
	}
	if err := writePreamble(&buf, Preamble{Mode: ModePublic}); err == nil {
		t.Fatal("a request stream with no allocation was written")
	}
	if _, err := readPreamble(bytes.NewReader([]byte{0xff, 0xff})); err == nil {
		t.Fatal("an oversized preamble was read")
	}
}

// The relay holds at most MaxStreamsPerSession requests open to one Identity
// Agent, refuses the next, and gives each place back when its request ends.
func TestTheStreamLimitHoldsAndFreesUp(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("www.acme.relay.test", id.aid, Preamble{Allocation: "pub-2", Mode: ModePublic, Host: "www.acme.relay.test"})
	hold := make(chan struct{})
	var held atomic.Int32
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path == "/hold" {
			held.Add(1)
			<-hold
		}
		io.WriteString(w, "ok")
	}))
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 0, MaxIdleConnsPerHost: 512}}
	get := func(host, path string) int {
		req, _ := http.NewRequest("GET", r.front.URL+path, nil)
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return 0
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	var wg sync.WaitGroup
	// Spread over two addresses, each within its own in-flight limit.
	for i := 0; i < MaxStreamsPerSession; i++ {
		wg.Add(1)
		host := "acme.relay.test"
		if i%2 == 1 {
			host = "www.acme.relay.test"
		}
		go func() { defer wg.Done(); get(host, "/hold") }()
	}
	r.waitFor(func() bool { return held.Load() == MaxStreamsPerSession })
	if code := get("acme.relay.test", "/x"); code != http.StatusServiceUnavailable {
		t.Errorf("request %d past the limit got %d", MaxStreamsPerSession+1, code)
	}
	close(hold)
	wg.Wait()
	for i := 0; i < MaxStreamsPerSession+10; i++ {
		if code := get("acme.relay.test", "/x"); code != 200 {
			t.Fatalf("request %d after the held ones finished got %d", i, code)
		}
	}
}

// The bytes a statement is signed over are pinned, so another implementation
// of the protocol can produce them with an ordinary JSON writer.
func TestTheSignedBytesArePinned(t *testing.T) {
	got, err := Statement{Purpose: "relay-admission", Protocol: "iarelay/2", Service: "r&d.relay.test",
		Nonce: "n", Exporter: "x", AID: "Eabc", Time: "2026-10-21T00:00:00Z"}.canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"aid":"Eabc","exporter":"x","nonce":"n","protocol":"iarelay/2","purpose":"relay-admission","service":"r&d.relay.test","t":"2026-10-21T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("signed bytes\n got %s\nwant %s", got, want)
	}
}
