package relay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay"
	"identity-agent-core/relay/relaytest"
)

// enrolment is a pairwise enrolment identifier with its key log, as the core
// mints one for a relay.
type enrolment struct {
	aid  string
	kel  []byte
	seed []byte
	keri *keri.SoftwareSigner
}

func newEnrolment(t *testing.T) *enrolment {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	cur, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, _ := keri.NextDigest(npub)
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
	kel, _ := keri.ExportKEL([][]byte{signed.Message})
	return &enrolment{aid: parsed.Identifier, kel: kel, seed: seed, keri: cur}
}

func (e *enrolment) SignCanonical(_ string, body map[string]interface{}) (string, error) {
	canon, err := relay.CanonicalBody(body)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(e.seed), canon)), nil
}

// identityAgent stands in for the core's router: an artifact, the message
// endpoint, and an owner route.
func identityAgent() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oobi/{aid}", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("oobi of " + r.PathValue("aid")))
	})
	mux.HandleFunc("POST /didcomm", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("received " + string(b)))
	})
	mux.HandleFunc("GET /api/contacts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("the owner's contacts"))
	})
	return mux
}

// relationshipRoutes is what a private address may reach in these tests.
func relationshipRoutes(r *http.Request) bool {
	return (r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/oobi/")) ||
		(r.Method == http.MethodPost && r.URL.Path == "/didcomm")
}

func managerFor(t *testing.T, rl *relaytest.Relay, e *enrolment, mode relayproto.Mode) *relay.Manager {
	t.Helper()
	name := ""
	if mode == relayproto.ModePublic {
		name = "acme"
	}
	return relay.NewManager(relay.Config{
		BaseURL: rl.URL(), Mode: mode, EnrollmentAID: e.aid,
		KEL: func() []byte { return e.kel }, Session: e.keri, Requests: e,
		RAID: e.aid, Name: name, Handler: identityAgent(),
		PrivateMayReach: relationshipRoutes, TLS: rl.TLS(), HTTPClient: rl.Client(),
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func get(t *testing.T, c *http.Client, method, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A counterparty reaches a private address for exactly what a relationship
// needs: the identity's artifacts and its message endpoint.
func TestAPrivateAddressCarriesArtifactsAndMessages(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })

	if code, body := get(t, rl.Caller(), "GET", m.URL()+"/oobi/"+e.aid, ""); code != 200 || body != "oobi of "+e.aid {
		t.Fatalf("artifact: %d %q", code, body)
	}
	if code, body := get(t, rl.Caller(), "POST", m.URL()+"/didcomm", "hello"); code != 200 || body != "received hello" {
		t.Fatalf("message: %d %q", code, body)
	}
}

// A private address reaches nothing else, even when the relay forwards it:
// the Identity Agent applies its own rule, because a relay is not trusted to.
func TestAPrivateAddressReachesNothingElse(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })

	// The relay's own rule refuses this path too, so ask the Identity Agent's
	// rule directly with a request the relay would pass if it were lax: the
	// same path, which this Identity Agent's rule does not allow.
	if code, body := get(t, rl.Caller(), "GET", m.URL()+"/api/contacts", ""); code == 200 {
		t.Fatalf("an owner route answered through a private address: %q", body)
	}
}

// A relay that claims a private address is public does not make it so: the
// Identity Agent believes its own record of what it asked for.
func TestThePreambleModeIsNotBelieved(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	rl.ClaimMode = relayproto.ModePublic // forwards every path, and says the address is public
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	if code, body := get(t, rl.Caller(), "GET", m.URL()+"/api/contacts", ""); code == 200 {
		t.Fatalf("the relay's word that an address is public was believed: %q", body)
	}
	if code, _ := get(t, rl.Caller(), "GET", m.URL()+"/oobi/"+e.aid, ""); code != 200 {
		t.Fatalf("what a private address may reach was refused too: %d", code)
	}
}

// A public address passes everything to the Identity Agent's own gate.
func TestAPublicAddressPassesToTheGate(t *testing.T) {
	rl := relaytest.New(relayproto.ModePublic)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePublic)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	if code, _ := get(t, rl.Caller(), "GET", m.URL()+"/api/contacts", ""); code != 200 {
		t.Fatalf("a public address should reach the Identity Agent's own gate, got %d", code)
	}
}

// A request on a label this Identity Agent does not hold is refused, whatever
// the relay sends down its session.
func TestAnAddressThisIdentityAgentDoesNotHoldIsRefused(t *testing.T) {
	rl := relaytest.New(relayproto.ModePublic)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePublic)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	// A second label routed to this session by a relay that mixed them up.
	rl.Alias("someoneelse", m.Allocation().Label)
	if code, body := get(t, rl.Caller(), "GET", strings.Replace(m.URL(), "//acme.", "//someoneelse.", 1)+"/api/contacts", ""); code != 404 {
		t.Fatalf("a request on a label this Identity Agent never asked for was served: %d %q", code, body)
	}
}

// A dropped session comes back at the same address, and the address is not
// offered while it is down.
func TestAReconnectKeepsTheAddress(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	var mu sync.Mutex
	var events []bool
	m.OnChange(func(_ string, active bool) { mu.Lock(); events = append(events, active); mu.Unlock() })
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	first := m.URL()

	rl.Drop(e.aid)
	waitFor(t, "the drop to be noticed", func() bool { mu.Lock(); defer mu.Unlock(); return len(events) >= 2 })
	waitFor(t, "the reconnect", func() bool { return m.URL() != "" })
	if m.URL() != first {
		t.Fatalf("the address moved on reconnect: %s then %s", first, m.URL())
	}
	if code, _ := get(t, rl.Caller(), "GET", m.URL()+"/oobi/"+e.aid, ""); code != 200 {
		t.Fatalf("not reachable after reconnect: %d", code)
	}
}

// A restarted Identity Agent holds the address it already had again, from a
// relay that also restarted and kept only the commitment to its secret.
func TestARestartKeepsTheAddress(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	var mu sync.Mutex
	var held []relay.Allocation
	m.OnAllocated(func(a []relay.Allocation) { mu.Lock(); held = a; mu.Unlock() })
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	first := m.URL()
	m.Stop()
	rl.Restart()

	again := managerFor(t, rl, e, relayproto.ModePrivate)
	mu.Lock()
	again.Remember(held)
	mu.Unlock()
	if err := again.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer again.Stop()
	waitFor(t, "the relay address", func() bool { return again.URL() != "" })
	if again.URL() != first {
		t.Fatalf("the address moved across a restart: %s then %s", first, again.URL())
	}
	if code, _ := get(t, rl.Caller(), "GET", again.URL()+"/oobi/"+e.aid, ""); code != 200 {
		t.Fatalf("the address was held again but does not reach the Identity Agent: %d", code)
	}
}

// The secret is what holds a private address: a record without it cannot
// take the address back.
func TestAPrivateAddressIsHeldByItsSecret(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	stolen := m.Allocations()
	m.Stop()
	rl.Restart()

	other := newEnrolment(t)
	stolen[0].Secret = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	thief := managerFor(t, rl, other, relayproto.ModePrivate)
	thief.Remember(stolen)
	if err := thief.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer thief.Stop()
	// It is refused the address, and given a new one of its own.
	waitFor(t, "an address of its own", func() bool { return thief.URL() != "" })
	if thief.URL() == stolen[0].URL {
		t.Fatal("an address was taken without its secret")
	}
}

// A record cannot make a private address public: what it may reach is this
// manager's mode, whatever the record says.
func TestARecordCannotMakeAPrivateAddressPublic(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	rl.ClaimMode = relayproto.ModePublic
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	held := m.Allocations()
	m.Stop()
	held[0].Mode = relayproto.ModePublic

	again := managerFor(t, rl, e, relayproto.ModePrivate)
	again.Remember(held)
	if err := again.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer again.Stop()
	waitFor(t, "the relay address", func() bool { return again.URL() != "" })
	if code, body := get(t, rl.Caller(), "GET", again.URL()+"/api/contacts", ""); code == 200 {
		t.Fatalf("a record saying public opened a private address: %q", body)
	}
}

// Stopping does not give the address back: it was handed to counterparties.
func TestStoppingKeepsTheAddressAtTheRelay(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	label := m.Allocation().Label
	m.Stop()
	if !rl.Holds(label) {
		t.Fatal("stopping released the address")
	}
	if m.URL() != "" {
		t.Fatal("a stopped relay still offers its address")
	}
}

// A relay serving the other mode is refused rather than used.
func TestARelayOfTheOtherModeIsRefused(t *testing.T) {
	rl := relaytest.New(relayproto.ModePublic)
	defer rl.Close()
	e := newEnrolment(t)
	if err := managerFor(t, rl, e, relayproto.ModePrivate).Start(context.Background()); err == nil {
		t.Fatal("a private Identity Agent accepted a public relay")
	}
}

// The operator is identified by host so somebody can see which operators they
// rely on.
func TestTheProviderIsTheOperatorHost(t *testing.T) {
	m := relay.NewManager(relay.Config{BaseURL: "https://relay-b.example.com/api"})
	if got := m.GetStatus().Provider; got != "relay-b.example.com" {
		t.Fatalf("provider %q", got)
	}
}

// An Identity Agent is admitted, and signs its requests, only at the relay's
// connect host: never through the caller-facing door, which may sit behind a
// proxy that terminates TLS and could not carry an admission bound to it.
func TestTheSessionAndControlRequestsGoToTheConnectHost(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	e := newEnrolment(t)
	m := managerFor(t, rl, e, relayproto.ModePrivate)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	if n := rl.MisdirectedCount(); n != 0 {
		t.Fatalf("%d sessions or control requests went to the caller-facing door", n)
	}
	if !strings.HasPrefix(m.URL(), rl.URL()) {
		t.Fatalf("the address published is %s, not at the caller-facing %s", m.URL(), rl.URL())
	}
}

// A descriptor that names a connect host outside the relay's own name, as one
// rewritten by a proxy in front of callers would, is refused.
func TestAConnectHostOutsideTheRelaysNameIsRefused(t *testing.T) {
	rl := relaytest.New(relayproto.ModePrivate)
	defer rl.Close()
	rl.ConnectHostOverride = "connect.elsewhere.example:443"
	e := newEnrolment(t)
	err := managerFor(t, rl, e, relayproto.ModePrivate).Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not under its own name") {
		t.Fatalf("a connect host outside the relay's name was accepted: %v", err)
	}
}

// Every endpoint must be at the connect host the descriptor names.
func TestAnEndpointAwayFromTheConnectHostIsRefused(t *testing.T) {
	c := relay.NewClient("https://relay.example", nil)
	srv := relaytest.New(relayproto.ModePrivate)
	defer srv.Close()
	c.BaseURL = srv.URL()
	c.HTTPClient = srv.Client()
	d, err := c.FetchDescriptor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bad := *d
	bad.Endpoints = map[string]string{relay.OpBind: srv.URL() + "/bind"} // the caller-facing door
	if err := relay.CheckConnectHost(c.BaseURL, &bad); err == nil {
		t.Fatal("a control endpoint away from the connect host was accepted")
	}
	bad = *d
	bad.TunnelEndpoint = "wss://" + strings.TrimPrefix(srv.URL(), "https://") + "/tunnel"
	if err := relay.CheckConnectHost(c.BaseURL, &bad); err == nil {
		t.Fatal("a session endpoint away from the connect host was accepted")
	}
}
