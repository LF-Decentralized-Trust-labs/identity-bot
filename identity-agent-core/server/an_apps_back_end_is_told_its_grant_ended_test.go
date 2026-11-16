package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/asset"
	"identity-agent-core/login"
	"identity-agent-core/relay"
	"identity-agent-core/relay/relaytest"
)

// ADR-072 Amendment 10: when an installed app's grant ends, the core tells the
// app's back end through the relay, signed with the app's asset key, and the back
// end ends that person's sessions at once. These tests run the real relay
// (relaytest) and a back end that dials into it and claims a public name, as a
// utility app's does; the core is the real core.

// aBackEnd is an app's back end behind a relay: it keeps sessions (key -> person)
// and takes the notice at the path packages/login-go serves it at, checking it as
// login-go's VerifyGrantEnded does (the vectors tie the two together).
type aBackEnd struct {
	mu       sync.Mutex
	sessions map[string]string
	siteAID  string
	siteKey  ed25519.PublicKey
	got      atomic.Int32
	refused  atomic.Int32
	// unavailable is how many notices the back end answers 503 before it takes one: a back end mid-restart.
	unavailable atomic.Int32
	// refuse answers every notice 403, as a back end that will not take it does.
	refuse atomic.Bool
	m      *relay.Manager
	// bodies is every notice posted, in order.
	bodies []string
}

func (b *aBackEnd) sessionFor(key string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.sessions[key]
	return p, ok
}

func (b *aBackEnd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/identity-agent/grant-ended" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	b.got.Add(1)
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
	b.mu.Lock()
	b.bodies = append(b.bodies, string(raw))
	b.mu.Unlock()
	if b.unavailable.Add(-1) >= 0 {
		http.Error(w, "restarting", http.StatusServiceUnavailable)
		return
	}
	if b.refuse.Load() {
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}
	var n grantEndedNotice
	if json.Unmarshal(raw, &n) != nil {
		b.refused.Add(1)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(n.Signature)
	at, terr := time.Parse("2006-01-02T15:04:05Z", n.Issued)
	if n.V != 1 || n.Asset != b.siteAID || terr != nil || time.Since(at) > 5*time.Minute ||
		!ed25519.Verify(b.siteKey, grantEndedStatement(n.Asset, n.Key, n.Person, n.Issued), sig) {
		b.refused.Add(1)
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}
	b.mu.Lock()
	if b.sessions[n.Key] == n.Person {
		delete(b.sessions, n.Key)
	}
	b.mu.Unlock()
	w.Write([]byte(`{"ended":1}`))
}

// aRelayEnrolment is a relay enrolment identifier with its key log, as the
// relay package's own tests make one.
type aRelayEnrolment struct {
	aid  string
	kel  []byte
	seed []byte
	keri *keri.SoftwareSigner
}

func newARelayEnrolment(t *testing.T) *aRelayEnrolment {
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
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := keri.ExportKEL([][]byte{signed.Message})
	return &aRelayEnrolment{aid: parsed.Identifier, kel: kel, seed: seed, keri: cur}
}

func (e *aRelayEnrolment) SignCanonical(_ string, body map[string]interface{}) (string, error) {
	canon, err := relayproto.CanonicalBody(body)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(e.seed), canon)), nil
}

// startBackEnd dials the back end into rl and waits for its public address.
func startBackEnd(t *testing.T, rl *relaytest.Relay, b *aBackEnd) string {
	t.Helper()
	e := newARelayEnrolment(t)
	b.m = relay.NewManager(relay.Config{BaseURL: rl.URL(), Mode: relayproto.ModePublic, EnrollmentAID: e.aid,
		KEL: func() []byte { return e.kel }, Session: e.keri, Requests: e, RAID: e.aid, Name: "theapp",
		Handler: b, TLS: rl.TLS(), HTTPClient: rl.Client()})
	if err := b.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.m.Stop)
	deadline := time.Now().Add(10 * time.Second)
	for b.m.URL() == "" {
		if time.Now().After(deadline) {
			t.Fatal("the back end never got its relay address")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return strings.TrimSuffix(b.m.URL(), "/")
}

type aPushWorld struct {
	*anInstalledAppWorld
	rl *relaytest.Relay
	be *aBackEnd
}

func aPushedWorld(t *testing.T) *aPushWorld {
	t.Helper()
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	rl := relaytest.New(relayproto.ModePublic)
	t.Cleanup(rl.Close)
	iw.org.grantPushClient = rl.Caller()
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	pub, _, err := asset.DeriveAssetKeypair(iw.org.DataDir, a.SigningIndex)
	if err != nil {
		t.Fatal(err)
	}
	return &aPushWorld{iw, rl, &aBackEnd{sessions: map[string]string{}, siteAID: a.PairwiseAID, siteKey: pub}}
}

// signIn signs the installed key in at the back end's own address and gives the
// back end its session for it, as a host does when the sign-in confirms.
func (w *aPushWorld) signIn(t *testing.T, address string) string {
	t.Helper()
	in, err := w.org.startFrontEndKeySignIn(anAppsRequest("the-website", nil), "", "the-website", address, w.key, "installed_app", w.srv.URL, w.proof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: w.srv.URL}); err != nil {
		t.Fatalf("an approved sign-in was refused: %v", err)
	}
	person, ok := w.org.browserKeys().Whose("the-website", w.key, time.Now())
	if !ok {
		t.Fatal("the key does not speak after its sign-in")
	}
	w.be.mu.Lock()
	w.be.sessions[w.key] = person
	w.be.mu.Unlock()
	return person
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAGrantTheOwnerEndsEndsTheBackEndsSessionThroughTheRelay(t *testing.T) {
	w := aPushedWorld(t)
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	if _, ok := w.be.sessionFor(w.key); !ok {
		t.Fatal("the back end holds no session to end")
	}
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the back end to end the session", func() bool { _, ok := w.be.sessionFor(w.key); return !ok })
	if w.be.refused.Load() != 0 {
		t.Fatal("the back end refused the core's notice")
	}
}

func TestEveryRoadThatEndsAGrantTellsTheBackEnd(t *testing.T) {
	roads := map[string]func(w *aPushWorld) error{
		"the owner switches the front end off": func(w *aPushWorld) error {
			_, err := w.org.browserKeys().EndKind("the-website", login.FrontEndInstalledApp)
			return err
		},
		"a member is removed": func(w *aPushWorld) error {
			p, _ := w.org.browserKeys().Whose("the-website", w.key, time.Now())
			_, err := w.org.browserKeys().End("the-website", "", p)
			return err
		},
	}
	for name, road := range roads {
		t.Run(name, func(t *testing.T) {
			w := aPushedWorld(t)
			addr := startBackEnd(t, w.rl, w.be)
			w.signIn(t, addr)
			if err := road(w); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, "the back end to end the session", func() bool { _, ok := w.be.sessionFor(w.key); return !ok })
		})
	}
}

func TestOnlyTheEndedKeysSessionEnds(t *testing.T) {
	w := aPushedWorld(t)
	addr := startBackEnd(t, w.rl, w.be)
	person := w.signIn(t, addr)
	w.be.mu.Lock()
	w.be.sessions["another-key"] = person
	w.be.mu.Unlock()
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the notice", func() bool { _, ok := w.be.sessionFor(w.key); return !ok })
	if _, ok := w.be.sessionFor("another-key"); !ok {
		t.Fatal("a session of another key ended with it")
	}
}

func TestABackEndThatCannotTakeTheNoticeYetIsToldAgain(t *testing.T) {
	w := aPushedWorld(t)
	w.org.grantBackoff = []time.Duration{0, 50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond}
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	w.be.unavailable.Store(2) // the first two attempts meet a back end that is restarting
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the retried notice", func() bool { _, ok := w.be.sessionFor(w.key); return !ok })
	if w.be.got.Load() < 3 {
		t.Fatalf("the notice was sent %d times, want at least 3", w.be.got.Load())
	}
}

func TestAGrantWithNoAddressAndAFrontEndThatIsNotInstalledSendNothing(t *testing.T) {
	w := aPushedWorld(t)
	startBackEnd(t, w.rl, w.be)
	bk := w.org.browserKeys()
	// An installed grant recorded without an address, as one made before this existed.
	if err := bk.RecordAppKey("the-website", "Eperson", w.key, time.Now(), nil, installedAppFact{}); err != nil {
		t.Fatal(err)
	}
	// A browser's record that somehow carries an address: only an installed app's grant is pushed.
	if err := bk.recordWith("the-website", "Eperson", aBrowserKey, login.FrontEndBrowser, time.Now().Add(time.Hour), time.Now(), nil, nil, w.be.m.URL()); err != nil {
		t.Fatal(err)
	}
	bk.End("the-website", w.key, "")
	bk.End("the-website", aBrowserKey, "")
	time.Sleep(300 * time.Millisecond)
	if w.be.got.Load() != 0 {
		t.Fatalf("%d notices were sent for grants that are not an installed app's with an address", w.be.got.Load())
	}
}

func TestARetryDoesNotEndAGrantThePersonHasSinceSignedInAgain(t *testing.T) {
	w := aPushedWorld(t)
	w.org.grantBackoff = []time.Duration{0, 400 * time.Millisecond}
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	w.be.unavailable.Store(1) // the first attempt fails, so a retry is waiting
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the first attempt", func() bool { return w.be.got.Load() >= 1 })
	w.signIn(t, addr) // the same key signs in again and the back end has a new session
	time.Sleep(900 * time.Millisecond)
	if w.be.got.Load() != 1 {
		t.Fatalf("the retry was sent after the key spoke again (%d attempts)", w.be.got.Load())
	}
	if _, ok := w.be.sessionFor(w.key); !ok {
		t.Fatal("a late retry ended the new session")
	}
}

func TestANoticeTheBackEndRefusesIsNotRepeated(t *testing.T) {
	w := aPushedWorld(t)
	w.org.grantBackoff = []time.Duration{0, 50 * time.Millisecond, 50 * time.Millisecond}
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	w.be.refuse.Store(true)
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the notice", func() bool { return w.be.got.Load() >= 1 })
	time.Sleep(400 * time.Millisecond)
	if w.be.got.Load() != 1 {
		t.Fatalf("a 403 was answered with %d attempts", w.be.got.Load())
	}
}

// The client the core uses unless a test gives one: it will not dial a machine
// of this host's, and it does not follow a redirect to one.
func TestTheCoreOwnClientDoesNotReachThisMachineOrFollowARedirect(t *testing.T) {
	var hit atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Add(1) }))
	defer srv.Close()
	s := &CoreServer{}
	c := s.grantPushHTTP()
	if _, err := c.Post(srv.URL+"/identity-agent/grant-ended", "application/json", strings.NewReader("{}")); err == nil {
		t.Fatal("the core dialled a loopback address")
	}
	if hit.Load() != 0 {
		t.Fatal("a request reached a loopback server")
	}
	if err := c.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("a redirect would be followed: %v", err)
	}
}

func TestANoticeIsSignedWithTheAppsKeyAndNoOneElsesIsTaken(t *testing.T) {
	w := aPushedWorld(t)
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	// A forger's notice, signed by another key, is refused by the back end and ends nothing.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	n := signGrantEnded(other.Seed(), w.be.siteAID, w.key, "any", time.Now())
	body, _ := json.Marshal(n)
	req, _ := http.NewRequest("POST", addr+"/identity-agent/grant-ended", strings.NewReader(string(body)))
	resp, err := w.rl.Caller().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a forged notice was answered %d", resp.StatusCode)
	}
	if _, ok := w.be.sessionFor(w.key); !ok {
		t.Fatal("a forged notice ended a session")
	}
}

// The core's signature is the one login-go checks: the same vector file both run.
func TestTheNoticeTheCoreSignsIsTheVectorsBytes(t *testing.T) {
	raw, err := os.ReadFile("../../packages/login-web/test-vectors/grant-ended.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		SeedHex   string `json:"seed_hex"`
		Statement string `json:"statement"`
		Notice    grantEndedNotice
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if got := string(grantEndedStatement(v.Notice.Asset, v.Notice.Key, v.Notice.Person, v.Notice.Issued)); got != v.Statement {
		t.Fatalf("statement\n got %q\nwant %q", got, v.Statement)
	}
	seed, _ := hex.DecodeString(v.SeedHex)
	at, _ := time.Parse(time.RFC3339, v.Notice.Issued)
	if got := signGrantEnded(seed, v.Notice.Asset, v.Notice.Key, v.Notice.Person, at); got != v.Notice {
		t.Fatalf("notice\n got %+v\nwant %+v", got, v.Notice)
	}
}

func TestTheCoreCallsOnlyAPublicHttpsOrigin(t *testing.T) {
	for _, bad := range []string{"http://app.example", "https://app.example/path", "https://u@app.example", "https://app.example?x=1",
		"ftp://app.example", "", "app.example", "https://app.example#f"} {
		if _, err := pushOrigin(bad); err == nil {
			t.Errorf("%q was accepted as an address to call", bad)
		}
	}
	if o, err := pushOrigin("https://app.example:8443/"); err != nil || o != "https://app.example:8443" {
		t.Errorf("a good origin: %q %v", o, err)
	}
	for _, bad := range []string{"127.0.0.1:443", "10.0.0.5:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443", "0.0.0.0:80", "[fe80::1]:443",
		"100.64.0.1:443", "198.18.0.1:443", "240.0.0.1:443", "[64:ff9b::a00:5]:443", "[2002:a00:5::]:443", "[::ffff:10.0.0.5]:443", "example.com:443"} {
		if refusePrivate("tcp", bad, nil) == nil {
			t.Errorf("a dial to %s was allowed", bad)
		}
	}
	if err := refusePrivate("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
}

// Every attempt carries the same notice, dated when the grant ended: a retry sent
// later is not re-dated, so it cannot reach a session begun after the grant ended.
func TestARetryCarriesTheNoticeDatedWhenTheGrantEnded(t *testing.T) {
	w := aPushedWorld(t)
	w.org.grantBackoff = []time.Duration{0, 1100 * time.Millisecond}
	addr := startBackEnd(t, w.rl, w.be)
	w.signIn(t, addr)
	w.be.unavailable.Store(1)
	if _, err := w.org.browserKeys().End("the-website", w.key, ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the retried notice", func() bool { _, ok := w.be.sessionFor(w.key); return !ok })
	w.be.mu.Lock()
	defer w.be.mu.Unlock()
	if len(w.be.bodies) != 2 || w.be.bodies[0] != w.be.bodies[1] {
		t.Fatalf("the retry is not the first notice again: %q", w.be.bodies)
	}
}
