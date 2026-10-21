package relayproto

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	keri "github.com/grapeid/keri-go"
	"github.com/hashicorp/yamux"
)

// --- a key rotated away cannot be used to take the identifier's session ---

// The relay's stored record may lag the live session: the record was written
// at admission, the session has since renewed with a rotated log. Somebody
// holding the old key and the old log must still be refused.
func TestAKeyRotatedAwayCannotDisplaceTheOwner(t *testing.T) {
	id := newIdentity(t)
	oldKEL := id.kel()
	oldKey := id.current
	stale := func(string) ([]byte, bool) { return oldKEL, true }
	r := newRelay(t, &ServiceConfig{
		Verifier: &Verifier{Enrolled: stale},
		OnRenew:  func(*Verified) error { return nil }, // the record is never updated
		Lease:    1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond,
	})
	owner := r.connect(id, http.HandlerFunc(echo))
	id.rotate()
	r.waitFor(func() bool {
		s, ok := r.registry.Get(id.aid)
		return ok && bytes.Equal(s.KEL(), id.kel())
	})

	thief := &AgentConfig{URL: r.agentConfig(id).URL, AID: id.aid, TLS: r.agentConfig(id).TLS,
		KEL: func() []byte { return oldKEL }, Signer: oldKey}
	if a, err := Dial(context.Background(), thief); err == nil {
		a.Close()
		t.Fatal("a key rotated away was admitted")
	}
	if s, ok := r.registry.Get(id.aid); !ok || s.ID != owner.ID {
		t.Fatal("the owner's session was displaced")
	}
}

func TestTheNewestLogTheRelayHasSeenIsTheOneToExtend(t *testing.T) {
	id := newIdentity(t)
	oldKEL, oldKey := id.kel(), id.current
	id.rotate()
	v := &Verifier{Service: "relay.test", Enrolled: func(string) ([]byte, bool) { return oldKEL, true }}
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	ex := bytes.Repeat([]byte{4}, ExporterLength)
	a, _ := Answer(ch, ex, id.aid, oldKEL, oldKey, now)
	if _, err := v.verify(a, ch, ex, now, id.kel()); err == nil {
		t.Fatal("the old log was accepted although the live session holds a newer one")
	}
}

func TestARegistryRefusesASessionWithAnOlderLog(t *testing.T) {
	id := newIdentity(t)
	oldKEL := id.kel()
	id.rotate()
	g := NewRegistry()
	cfg := &ServiceConfig{Logf: func(string, ...any) {}}
	cur := &Session{AID: id.aid, kel: id.kel(), closed: make(chan struct{}), cfg: cfg}
	if err := g.Put(cur); err != nil {
		t.Fatal(err)
	}
	older := &Session{AID: id.aid, kel: oldKEL, closed: make(chan struct{}), cfg: cfg}
	if err := g.Put(older); err == nil {
		t.Fatal("a session holding an older log replaced one holding a newer")
	}
	if s, _ := g.Get(id.aid); s != cur {
		t.Fatal("the current session was replaced")
	}
}

func TestARelayWithNoRecordsAdmitsNobody(t *testing.T) {
	id := newIdentity(t)
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	ex := bytes.Repeat([]byte{5}, ExporterLength)
	a, _ := Answer(ch, ex, id.aid, id.kel(), id, now)
	if _, err := (&Verifier{Service: "relay.test"}).Verify(a, ch, ex, now); err == nil {
		t.Fatal("a relay that keeps no record of key event logs admitted somebody")
	}
}

func TestTheRelayIsToldEveryLogItVerifies(t *testing.T) {
	r := newRelay(t, &ServiceConfig{Lease: 1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond})
	id := newIdentity(t)
	r.connect(id, http.HandlerFunc(echo))
	id.rotate()
	r.waitFor(func() bool {
		v, ok := r.held.Load(id.aid)
		return ok && bytes.Equal(v.([]byte), id.kel())
	})
}

// A renewal must extend the log of the session it renews, even when the
// relay's stored record has been lost.
func TestARenewalCannotGoBackToAnOlderLog(t *testing.T) {
	id := newIdentity(t)
	oldKEL, oldKey := id.kel(), id.current
	id.rotate()
	forget := func(string) ([]byte, bool) { return nil, false }
	r := newRelay(t, &ServiceConfig{Verifier: &Verifier{Enrolled: forget},
		OnAdmit: func(*Verified) error { return nil }, OnRenew: func(*Verified) error { return nil },
		Lease: 1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond})
	cfg := r.agentConfig(id)
	var goBack atomic.Bool
	cfg.KEL = func() []byte {
		if goBack.Load() {
			return oldKEL
		}
		return id.kel()
	}
	cfg.Signer = signerFunc(func(b []byte) ([]byte, error) {
		if goBack.Load() {
			return oldKey.Sign(b)
		}
		return id.Sign(b)
	})
	a, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	go a.Serve(http.HandlerFunc(echo))
	goBack.Store(true)
	select {
	case <-a.Done():
	case <-time.After(4 * time.Second):
		t.Fatal("a renewal presenting an older log kept the session")
	}
}

type signerFunc func([]byte) ([]byte, error)

func (f signerFunc) Sign(b []byte) ([]byte, error) { return f(b) }

// --- nothing unbounded is read before admission ---

func TestAnOversizedAdmissionIsNotRead(t *testing.T) {
	r := newRelay(t, nil)
	d := websocket.Dialer{TLSClientConfig: r.agentConfig(newIdentity(t)).TLS, Subprotocols: []string{Subprotocol}}
	ws, _, err := d.Dial(r.agentConfig(newIdentity(t)).URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var ch Challenge
	ws.ReadJSON(&ch)
	ws.WriteMessage(websocket.TextMessage, append([]byte(`{"kel":"`), bytes.Repeat([]byte("A"), 2*MaxAdmissionBytes)...))
	select {
	case err := <-r.accepted:
		if err == nil || !strings.Contains(err.Error(), "read limit") {
			t.Fatalf("an oversized admission was read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
}

// fakeRelay accepts a websocket over TLS 1.3 and hands it to serve.
func fakeRelay(t *testing.T, serve func(ws *websocket.Conn, exporter []byte)) (string, *tls.Config) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ex, _ := ChannelBinding(*r.TLS)
		up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serve(ws, ex)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return "wss" + strings.TrimPrefix(srv.URL, "https"), srv.Client().Transport.(*http.Transport).TLSClientConfig
}

func TestAnIdentityAgentReadsNoOversizedChallenge(t *testing.T) {
	u, tc := fakeRelay(t, func(ws *websocket.Conn, _ []byte) {
		ch := NewChallenge("127.0.0.1", time.Now())
		ch.Service = "127.0.0.1" + strings.Repeat(" ", 2*MaxControlBytes)
		ws.WriteJSON(ch)
		time.Sleep(time.Second)
	})
	id := newIdentity(t)
	_, err := Dial(context.Background(), &AgentConfig{URL: u, TLS: tc, AID: id.aid, KEL: id.kel, Signer: id})
	if err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("an oversized challenge was read: %v", err)
	}
}

func TestAnIdentityAgentSignsOnlyForTheRelayItDialled(t *testing.T) {
	u, tc := fakeRelay(t, func(ws *websocket.Conn, _ []byte) {
		ws.WriteJSON(NewChallenge("another-relay.test", time.Now()))
		var a Admission
		ws.ReadJSON(&a)
		ws.WriteJSON(Admitted{Session: "s", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
		time.Sleep(time.Second)
	})
	id := newIdentity(t)
	a, err := Dial(context.Background(), &AgentConfig{URL: u, TLS: tc, AID: id.aid, KEL: id.kel, Signer: id})
	if err == nil {
		a.Close()
		t.Fatal("signed a statement for a relay other than the one dialled")
	}
}

// admittedSession performs admission from the relay's side by hand and
// returns the relay's end of the session, for tests that need to misbehave.
func admittedSession(ws *websocket.Conn, ex []byte, t *testing.T) *yamux.Session {
	ws.WriteJSON(NewChallenge("127.0.0.1", time.Now()))
	var a Admission
	if err := ws.ReadJSON(&a); err != nil {
		t.Error(err)
		return nil
	}
	ws.WriteJSON(Admitted{Session: "s", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	mux, err := yamux.Client(newWSConn(ws), muxConfig())
	if err != nil {
		t.Error(err)
	}
	return mux
}

func TestARenewalChallengeIsBounded(t *testing.T) {
	answered := make(chan bool, 1)
	u, tc := fakeRelay(t, func(ws *websocket.Conn, ex []byte) {
		mux := admittedSession(ws, ex, t)
		if mux == nil {
			return
		}
		defer mux.Close()
		st, _ := mux.OpenStream()
		writePreamble(st, Preamble{Mode: modeRenew})
		ch := NewChallenge("127.0.0.1", time.Now())
		ch.Renewal = true
		body, _ := json.Marshal(map[string]any{"protocol": ch.Protocol, "service": ch.Service,
			"nonce": ch.Nonce, "t": ch.Time, "renewal": true, "pad": strings.Repeat("x", 2*MaxControlBytes)})
		st.Write(append(body, '\n'))
		st.SetReadDeadline(time.Now().Add(3 * time.Second))
		var a Admission
		answered <- json.NewDecoder(st).Decode(&a) == nil
	})
	id := newIdentity(t)
	a, err := Dial(context.Background(), &AgentConfig{URL: u, TLS: tc, AID: id.aid, KEL: id.kel, Signer: id})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	go a.Serve(http.HandlerFunc(echo))
	if <-answered {
		t.Fatal("an oversized renewal challenge was read and answered")
	}
}

// --- streams: half-closed ones count, idle ones end, one address cannot starve the rest ---

// A request whose response is complete but whose stream the Identity Agent
// never closes still holds a place until the stream is gone.
func TestAHalfClosedStreamStillCounts(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("www.acme.relay.test", id.aid, Preamble{Allocation: "pub-2", Mode: ModePublic, Host: "www.acme.relay.test"})
	var mu sync.Mutex
	var kept []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range kept {
			c.Close()
		}
	})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		buf.Flush()
		mu.Lock()
		kept = append(kept, c) // answered, never closed
		mu.Unlock()
	}))
	get := func(host string) int {
		req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < MaxStreamsPerSession; i++ {
		host := "acme.relay.test"
		if i%2 == 1 {
			host = "www.acme.relay.test"
		}
		if code := get(host); code != 200 {
			t.Fatalf("request %d got %d", i, code)
		}
	}
	if code := get("acme.relay.test"); code != http.StatusServiceUnavailable {
		t.Fatalf("with %d streams left open, another request got %d", MaxStreamsPerSession, code)
	}
}

func TestAStreamOnWhichNothingMovesEnds(t *testing.T) {
	defer streamIdleNanos.Store(streamIdleNanos.Load())
	streamIdleNanos.Store(int64(300 * time.Millisecond))
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		io.WriteString(w, "late")
	}))
	start := time.Now()
	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode == 200 || time.Since(start) > time.Second {
		t.Fatalf("an idle stream was held %v and answered %d", time.Since(start), resp.StatusCode)
	}
}

func TestOneAddressCannotTakeEveryStream(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-1", Mode: ModePrivate, Host: "a1b2.relay.test"})
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	hold := make(chan struct{})
	var held atomic.Int32
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path == "/didcomm" {
			held.Add(1)
			<-hold
		}
		io.WriteString(w, "ok")
	}))
	var wg sync.WaitGroup
	for i := 0; i < PrivateInFlightPerAllocation; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", r.front.URL+"/didcomm", strings.NewReader("{}"))
			resp := r.do("a1b2.relay.test", req)
			resp.Body.Close()
		}()
	}
	r.waitFor(func() bool { return held.Load() == PrivateInFlightPerAllocation })
	req, _ := http.NewRequest("POST", r.front.URL+"/didcomm", strings.NewReader("{}"))
	resp := r.do("a1b2.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("one more request on a full address got %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", r.front.URL+"/x", nil)
	resp = r.do("acme.relay.test", req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("another address was starved: %d", resp.StatusCode)
	}
	close(hold)
	wg.Wait()
}

func TestTheRelayLimitsRequestsPerAddress(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-1", Mode: ModePrivate, Host: "a1b2.relay.test"})
	r.connect(id, http.HandlerFunc(echo))
	last := 0
	for i := 0; i <= PrivateRequestsPerMinute; i++ {
		req, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
		resp := r.do("a1b2.relay.test", req)
		resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request %d in a minute got %d", PrivateRequestsPerMinute+1, last)
	}
}

func TestARelayHoldsNoMoreSessionsThanItAllows(t *testing.T) {
	r := newRelay(t, &ServiceConfig{MaxSessions: 1})
	r.connect(newIdentity(t), http.HandlerFunc(echo))
	other := newIdentity(t)
	if a, err := Dial(context.Background(), r.agentConfig(other)); err == nil {
		a.Close()
		t.Fatal("a full relay admitted another Identity Agent")
	}
}

// --- what crosses, and what a private address refuses ---

func TestTheRelayKnowsWhereARequestGoes(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic})
	var reached atomic.Bool
	r.connect(id, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	resp := r.do("acme.relay.test", req)
	resp.Body.Close()
	if reached.Load() || resp.StatusCode == 200 {
		t.Fatal("a request was forwarded under the caller's Host, not one the relay recorded")
	}
}

func TestAPrivateAddressRefusesOtherSpellingsAndUpgrades(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("a1b2.relay.test", id.aid, Preamble{Allocation: "priv-7", Mode: ModePrivate, Host: "a1b2.relay.test"})
	var reached atomic.Int32
	r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { reached.Add(1) }))

	encoded, _ := http.NewRequest("GET", r.front.URL+"/oobi/%45"+id.aid[1:], nil)
	resp := r.do("a1b2.relay.test", encoded)
	resp.Body.Close()
	if reached.Load() != 0 {
		t.Error("a percent-encoded path reached the Identity Agent on a private address")
	}
	up, _ := http.NewRequest("GET", r.front.URL+"/oobi/"+id.aid, nil)
	up.Header.Set("Connection", "Upgrade")
	up.Header.Set("Upgrade", "websocket")
	resp = r.do("a1b2.relay.test", up)
	resp.Body.Close()
	if reached.Load() != 0 {
		t.Error("an upgrade reached the Identity Agent on a private address")
	}
}

func TestEveryRelayedRequestIsMarkedByTheIdentityAgent(t *testing.T) {
	r := newRelay(t, nil)
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.connect(id, http.HandlerFunc(echo))
	req, _ := http.NewRequest("GET", r.front.URL+"/x", nil)
	req.Header.Set(ViaRelayHeader, "not-relayed")
	got := decode(t, r.do("acme.relay.test", req))
	if h := got["headers"].(map[string]any)[http.CanonicalHeaderKey(ViaRelayHeader)]; fmt.Sprint(h) != "[relay]" {
		t.Fatalf("relay marker arrived as %v", h)
	}
}

// --- renewal does not depend on a free request slot ---

func TestALeaseRenewsWhileEveryRequestSlotIsBusy(t *testing.T) {
	r := newRelay(t, &ServiceConfig{Lease: 1500 * time.Millisecond, RenewBefore: 1000 * time.Millisecond})
	id := newIdentity(t)
	r.route("acme.relay.test", id.aid, Preamble{Allocation: "pub-1", Mode: ModePublic, Host: "acme.relay.test"})
	r.route("www.acme.relay.test", id.aid, Preamble{Allocation: "pub-2", Mode: ModePublic, Host: "www.acme.relay.test"})
	hold := make(chan struct{})
	var held atomic.Int32
	a := r.connect(id, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		held.Add(1)
		<-hold
	}))
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 512}}
	var wg sync.WaitGroup
	for i := 0; i < MaxStreamsPerSession; i++ {
		wg.Add(1)
		host := "acme.relay.test"
		if i%2 == 1 {
			host = "www.acme.relay.test"
		}
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", r.front.URL+"/hold", nil)
			req.Host = host
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
	}
	r.waitFor(func() bool { return held.Load() == MaxStreamsPerSession })
	time.Sleep(2500 * time.Millisecond)
	select {
	case <-a.Done():
		t.Fatal("the session ended because its renewal found no free slot")
	default:
	}
	close(hold)
	wg.Wait()
}

// --- the bytes signed have one spelling ---

func TestAStatementMustBePrintableASCII(t *testing.T) {
	id := newIdentity(t)
	v := &Verifier{Service: "relay.test", Enrolled: func(string) ([]byte, bool) { return nil, false }}
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	ex := bytes.Repeat([]byte{6}, ExporterLength)
	a, _ := Answer(ch, ex, id.aid, id.kel(), id, now)
	a.Statement.AID = id.aid + "\nrelay admission accepted aid=Eforged"
	if _, err := v.Verify(a, ch, ex, now); err == nil || !strings.Contains(err.Error(), "printable") {
		t.Fatalf("a statement with a control character was not refused for it: %v", err)
	}
	if _, err := Answer(ch, ex, "Eé", nil, id, now); err == nil {
		t.Fatal("signed a statement that is not printable ASCII")
	}
}

// --- second review ---

// The same history can travel with more attachments than before, as when a
// witness receipt is added to an event. That is not a rewrite, and a relay
// that holds the shorter form must still admit it.
func TestALogThatGainsAReceiptStillExtendsTheOneHeld(t *testing.T) {
	id := newIdentity(t)
	id.rotate() // two events, so the receipt lands in the middle of the log
	held := id.kel()
	msgs, err := keri.ParseKELStream(held)
	if err != nil {
		t.Fatal(err)
	}
	witness, _ := keri.GenerateSigner(false)
	wpub, _ := witness.PublicKey()
	ev, _ := keri.ParseEvent(msgs[0])
	sig, _ := witness.Sign([]byte(ev.SAID))
	cigar, _ := keri.MatterQB64("0B", sig)
	receipt, err := keri.AttachReceiptCouples([]keri.ReceiptCouple{{Witness: wpub, CigarQB64: cigar}})
	if err != nil {
		t.Fatal(err)
	}
	grown, err := keri.ExportKEL([][]byte{append(append([]byte{}, msgs[0]...), receipt...), msgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(grown, held) {
		t.Fatal("the test log still begins with the held bytes, so it proves nothing")
	}
	if !logExtends(grown, held) {
		t.Fatal("a log whose event gained a receipt was read as a rewrite")
	}
	v := &Verifier{Service: "relay.test", Enrolled: func(string) ([]byte, bool) { return held, true }}
	now := time.Now()
	ch := NewChallenge("relay.test", now)
	ex := bytes.Repeat([]byte{7}, ExporterLength)
	a, _ := Answer(ch, ex, id.aid, grown, id, now)
	if _, err := v.Verify(a, ch, ex, now); err != nil {
		t.Fatalf("the owner was refused for a receipt on an event: %v", err)
	}
}

func TestAFullRelayStillLetsAnOwnerReconnect(t *testing.T) {
	r := newRelay(t, &ServiceConfig{MaxSessions: 1})
	id := newIdentity(t)
	r.connect(id, http.HandlerFunc(echo))
	a, err := Dial(context.Background(), r.agentConfig(id))
	if err != nil {
		t.Fatalf("a full relay refused the owner's reconnect: %v", err)
	}
	a.Close()
}

func TestARenewalIsHeldToTheRelayAndProtocolDialled(t *testing.T) {
	id := newIdentity(t)
	for _, c := range []struct{ service, protocol string }{
		{"evil.example", ProtocolVersion},
		{"relay.test", "iarelay/1"},
	} {
		a := &AgentSession{cfg: &AgentConfig{AID: id.aid, KEL: id.kel, Signer: id},
			exporter: make([]byte, ExporterLength), relay: "relay.test"}
		c1, c2 := net.Pipe()
		go a.renew(c2)
		ch := NewChallenge(c.service, time.Now())
		ch.Protocol = c.protocol
		ch.Renewal = true
		go json.NewEncoder(c1).Encode(ch)
		c1.SetDeadline(time.Now().Add(2 * time.Second))
		var ans Admission
		if err := json.NewDecoder(c1).Decode(&ans); err == nil {
			t.Errorf("signed a renewal for %q speaking %q", c.service, c.protocol)
		}
		c1.Close()
	}
}

// The relay is told of a log only once its session is the identifier's own,
// so a newcomer the registry refuses never reaches the record.
func TestTheRelayRecordsALogOnlyForTheSessionItKeeps(t *testing.T) {
	var r *relay
	var early atomic.Bool
	r = newRelay(t, &ServiceConfig{OnAdmit: func(v *Verified) error {
		s, ok := r.registry.Get(v.AID)
		if !ok || !bytes.Equal(s.KEL(), v.KEL) {
			early.Store(true)
		}
		r.held.Store(v.AID, v.KEL)
		return nil
	}})
	r.connect(newIdentity(t), http.HandlerFunc(echo))
	if early.Load() {
		t.Fatal("the relay was told of a log before the session was in place")
	}
}
