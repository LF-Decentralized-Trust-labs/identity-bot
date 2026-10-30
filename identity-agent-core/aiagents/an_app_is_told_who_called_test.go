package aiagents

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/appcall"
	"identity-agent-core/internal/addontest"
	"identity-agent-core/sandbox"
	"identity-agent-core/server"
	"identity-agent-core/store"
)

// notesApp is an app providing two capabilities, running as one would: its
// capability API refuses anything the Identity Agent did not stamp, and its
// display serves everything else and records what it was sent.
type notesApp struct {
	mu    sync.Mutex
	calls []appcall.Caller
	// reached counts every request that arrived at the capability API at
	// all, stamped or not, so a test can tell the proxy refusing from the
	// app refusing.
	reached   int
	displayed []http.Header
}

func (a *notesApp) lastCall() (appcall.Caller, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.calls) == 0 {
		return appcall.Caller{}, 0
	}
	return a.calls[len(a.calls)-1], len(a.calls)
}

// withNotesApp gives s a sandbox with the notes app installed and running.
func withNotesApp(t *testing.T, s *server.CoreServer) *notesApp {
	t.Helper()
	manifests := t.TempDir()
	b, _ := json.Marshal(map[string]any{
		"id": "notes", "name": "Notes", "execution_type": "compiled", "binary": map[string]string{"path": "/bin/true"},
		"display_method": "webview", "network_mode": "local_only", "network": map[string]string{"tls_mode": "mitm"},
		"log_level": "none", "resources": map[string]int{"memory_mb": 64},
		"provides": []map[string]string{{"id": "notes.write"}, {"id": "notes.read"}},
	})
	if err := os.WriteFile(filepath.Join(manifests, "notes.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := sandbox.NewManager(sandbox.ManagerConfig{Log: fixtures.LogForTest(s, t, s.DataDir), Vault: fixtures.VaultForTest(s, s.DataDir), DataDir: s.DataDir, ManifestsDir: manifests})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	if err := m.LoadManifests(); err != nil {
		t.Fatal(err)
	}
	addontest.UseSandboxManager(s, m)

	key, err := m.AppCallKey("notes")
	if err != nil {
		t.Fatal(err)
	}
	v, err := appcall.NewVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	app := &notesApp{}
	mux := http.NewServeMux()
	verified := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := appcall.FromContext(r.Context())
		app.mu.Lock()
		app.calls = append(app.calls, c)
		app.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	mux.HandleFunc("/v1/capability/", func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		app.reached++
		app.mu.Unlock()
		verified.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		app.displayed = append(app.displayed, r.Header.Clone())
		app.mu.Unlock()
		w.Write([]byte("<html></html>"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	port := ln.Addr().(*net.TCPAddr).Port
	if err := m.Store().SaveInstance(sandbox.Instance{ID: "notes-1", AppID: "notes", Status: "running",
		DisplayPort: &port, TLSMode: "mitm", LogLevel: "none"}); err != nil {
		t.Fatal(err)
	}
	return app
}

// anAIAgentHolding is a token for an AI agent granted exactly caps.
func anAIAgentHolding(t *testing.T, s *server.CoreServer, caps ...string) string {
	t.Helper()
	const plaintext = "an-ai-agents-token"
	seedAgentToken(t, s, plaintext, mcpToken{Name: "assistant", Scopes: caps,
		AgentAID: "EAgentAID", DelegatorAID: "EOrgAID", CreatedAt: time.Now()})
	return plaintext
}

func invoke(capability, body, token string) *http.Request {
	r := fixtures.Remote("POST", "/api/capabilities/"+capability+"/invoke", body)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// The app hears who the Identity Agent admitted, and nothing the caller said
// about itself. A caller setting the call headers itself gets them replaced.
func TestAnAppIsToldWhichAIAgentCalled(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)
	tok := anAIAgentHolding(t, s, "notes.write")

	req := invoke("notes.write", `{"task":"n-1"}`, tok)
	req.Header.Set(appcall.HeaderKind, appcall.KindOwner)
	req.Header.Set(appcall.HeaderIdentifier, "EThePersonInCharge")
	req.Header.Set("X-IA-Session", "run-7")
	w := httptest.NewRecorder()
	hostOf(s).BuildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the invocation failed: %d %s", w.Code, w.Body.String())
	}
	got, n := app.lastCall()
	if n != 1 {
		t.Fatalf("the app received %d calls, not one", n)
	}
	if got.Kind != appcall.KindAIAgent || got.Identifier != "EAgentAID" || got.Session != "run-7" {
		t.Fatalf("the app was told %+v, not the AI agent the Identity Agent admitted", got)
	}
}

// An owner proving it remotely with the identity's key reaches a capability.
// The gate spends the owner's signature, so the handler must be told the
// caller is the owner rather than find a remote caller with no scopes.
func TestARemoteOwnerCanInvokeACapability(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)
	seed, ownerAID := fixtures.SealTestOwner(t, s)

	req := fixtures.Signed(t, "POST", "/api/capabilities/notes.write/invoke", `{"task":"n-1"}`, seed, time.Now())
	w := httptest.NewRecorder()
	hostOf(s).BuildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("a remote owner was refused a capability: %d %s", w.Code, w.Body.String())
	}
	got, _ := app.lastCall()
	if got.Kind != appcall.KindOwner || got.Identifier != ownerAID || got.AuthLevel != helpers.OwnerSigned() {
		t.Fatalf("the app was told %+v, not the owner", got)
	}
}

// The display proxy never forwards a capability call, however it is spelled,
// so an AI agent granted one capability cannot call another through it.
func TestTheDisplayProxyNeverForwardsACapabilityCall(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)
	tok := anAIAgentHolding(t, s, "notes.read")
	r := hostOf(s).BuildRouter("")

	for _, path := range []string{
		"/apps/notes/v1/capability/notes.write",
		"/apps/notes/V1/Capability/notes.write",
		"/apps/notes//v1/capability/notes.write",
		"/apps/notes/x/../v1/capability/notes.write",
		"/apps/notes/v1/capability/",
		"/apps/notes/v1%2Fcapability%2Fnotes.write",
	} {
		req := fixtures.Remote("POST", path, `{"task":"n-1"}`)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		app.mu.Lock()
		reached := app.reached
		app.mu.Unlock()
		// Reaching the app at all is the failure, even though the app's own
		// check would then refuse it: an app that checks nothing is still the
		// one the proxy must not forward to.
		if reached != 0 {
			t.Fatalf("%s was forwarded to the app's capability API: %d %s", path, w.Code, w.Body.String())
		}
		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Errorf("%s was answered %d", path, w.Code)
		}
	}
}

// What proves the caller to the Identity Agent never reaches the app through
// the display proxy, and neither does a caller the app would believe.
func TestTheDisplayProxyStripsWhatOnlyTheIdentityAgentReads(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)
	tok := anAIAgentHolding(t, s, "notes.read")

	req := fixtures.Remote("GET", "/apps/notes/page", "")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(appcall.HeaderKind, appcall.KindOwner)
	req.Header.Set(appcall.HeaderMAC, "forged")
	req.Header.Set("X-IA-Owner-Sig", "0Bsomething")
	req.Header.Set(server.LocalOwnerSecretHeader, "guess")
	req.Header.Set("X-Requested-With", "the app's own header")
	w := httptest.NewRecorder()
	hostOf(s).BuildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the display was not served: %d %s", w.Code, w.Body.String())
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(app.displayed) != 1 {
		t.Fatalf("the display received %d requests", len(app.displayed))
	}
	h := app.displayed[0]
	for name := range h {
		if strings.HasPrefix(name, "X-Ia-") || name == http.CanonicalHeaderKey(server.LocalOwnerSecretHeader) {
			t.Errorf("the app was sent %s", name)
		}
	}
	if h.Get("Authorization") != "" {
		t.Error("the app was sent the AI agent's Identity Agent token")
	}
	if h.Get("X-Requested-With") == "" {
		t.Error("the app's own header was stripped too")
	}
}

// An Authorization header that is the app's own login is left for the app.
func TestTheDisplayProxyLeavesTheAppsOwnLogin(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)

	req := fixtures.Local("GET", "/apps/notes/page", "")
	req.Header.Set("Authorization", "Bearer the-apps-own-session")
	w := httptest.NewRecorder()
	hostOf(s).BuildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the display was not served: %d %s", w.Code, w.Body.String())
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if got := app.displayed[0].Get("Authorization"); got != "Bearer the-apps-own-session" {
		t.Fatalf("the app's own login was not passed on: %q", got)
	}
	if app.displayed[0].Get(server.LocalOwnerSecretHeader) != "" {
		t.Fatal("the local owner's secret was passed on")
	}
}

// A browser session written as the Identity Agent itself accepts it, in any
// case and with extra spaces, is still stripped.
func TestTheDisplayProxyStripsASessionHoweverItIsWritten(t *testing.T) {
	s := newGrantTestServer(t)
	app := withNotesApp(t, s)
	tok := fixtures.SignInABrowser(t, s, "the browser's secret")

	req := fixtures.Local("GET", "/apps/notes/page", "")
	req.Header.Set("Authorization", "bearer   "+tok)
	req.Header.Set("X_IA_Call_Kind", "owner")
	w := httptest.NewRecorder()
	hostOf(s).BuildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the display was not served: %d %s", w.Code, w.Body.String())
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	h := app.displayed[0]
	if h.Get("Authorization") != "" {
		t.Error("a browser session reached the app")
	}
	if len(h.Values("X_IA_Call_Kind")) != 0 {
		t.Error("a call header spelled with underscores reached the app")
	}
}

// The owner's AI conversations, served through the display proxy, are read
// only by the owner or a machine acting for them — never by a caller admitted
// for holding some unrelated scope.
func TestOnlyTheOwnerReadsConversationsThroughTheDisplayProxy(t *testing.T) {
	s := newGrantTestServer(t)
	withNotesApp(t, s)
	mem, err := store.NewAIMemoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.AIMemory = mem
	if err := mem.SaveConversation(store.Conversation{ID: "c1", Title: "private"}); err != nil {
		t.Fatal(err)
	}
	tok := anAIAgentHolding(t, s, "notes.read")
	r := hostOf(s).BuildRouter("")

	for _, path := range []string{"/apps/notes/api/v1/chats", "/apps/notes/api/v1/chats/c1", "/apps/notes/api/v1//chats"} {
		req := fixtures.Remote("GET", path, "")
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("an AI agent holding an unrelated scope read %s: %d %s", path, w.Code, w.Body.String())
		}
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, fixtures.Local("GET", "/apps/notes/api/v1/chats", ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "private") {
		t.Fatalf("the owner could not read their conversations: %d %s", w.Code, w.Body.String())
	}
	machine, mseed := fixtures.AnAuthorisedMachine(t, s, server.GradeEnrolled)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, fixtures.AsThatMachine(t, machine, "GET", "/apps/notes/api/v1/chats", "", mseed, "", time.Time{}))
	if w.Code != http.StatusOK {
		t.Fatalf("a machine acting for the owner could not read their conversations: %d %s", w.Code, w.Body.String())
	}
	// The owner sealed while authorising the machine.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, fixtures.Signed(t, "GET", "/apps/notes/api/v1/chats/c1", "", fixtures.TestOwnerSeed(), time.Now()))
	if w.Code != http.StatusOK {
		t.Fatalf("the owner, signing remotely, could not read a conversation: %d %s", w.Code, w.Body.String())
	}
}
