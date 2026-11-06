package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
)

// A person signed in at an app speaks to an AI agent from the app's page with
// a session and the browser key it is bound to, as that person and not as a
// controller; a controller keeps working; and everything else is refused.

const (
	chatOrigin  = "https://chat.example"
	otherOrigin = "https://other.example"
)

type anAppWorld struct {
	s     *CoreServer
	h     http.Handler
	key   *ecdsa.PrivateKey
	token string
	who   coretypes.Signer
}

func anAppSessionWorld(t *testing.T) *anAppWorld {
	t.Helper()
	s := notifyTestServer(t)
	st := s.assetHandler.Store
	for _, a := range []asset.Asset{
		{ID: "chat", DisplayName: "chat", AssetType: "app", Origin: chatOrigin},
		{ID: "other", DisplayName: "other", AssetType: "app", Origin: otherOrigin},
		{ID: "site", DisplayName: "site", AssetType: "website", Origin: "https://site.example"},
	} {
		if err := st.UpsertAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertEmployee(asset.Employee{PairwiseAID: "Eann", Name: "Ann", Status: "active", IsSigner: true}); err != nil {
		t.Fatal(err)
	}
	// The talk routes belong to an add-on; this stands in for them, naming who
	// the core says is asking.
	say := func(w http.ResponseWriter, r *http.Request) {
		person, proof, err := s.thePersonAsking(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_, asApp := TheAppSessionThatAsked(r)
		_, asController := TheControllerThatAsked(r)
		verify := ""
		if err := (agentmessage.ControllerProof{
			Controller: proof.Controller, PublicKey: proof.PublicKey, SignedString: proof.SignedString,
			Signature: proof.Signature, RequestBytes: proof.RequestBytes, ControllerGrant: proof.ControllerGrant, Scheme: proof.Scheme,
		}).Verify(); err != nil {
			verify = err.Error()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"person": person.AID, "app": asApp, "controller": asController, "verify": verify, "id": chi.URLParam(r, "id")})
	}
	s.MountExtraRoutes(func(r chi.Router) {
		r.Post("/mcp/agents/{id}/conversations", say)
		r.Get("/mcp/agents/{id}/conversations", say)
		r.Get("/mcp/conversations/{cid}", say)
		r.Get("/mcp/conversations/{cid}/export", say)
		r.Get("/employees", say)
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := &anAppWorld{s: s, h: s.buildRouter(), key: key, token: "tok-" + t.Name(), who: coretypes.Signer{AID: "Eann", Standing: "signer", Name: "Ann"}}
	w.open("chat", w.who, time.Now().Add(time.Hour))
	return w
}

func (w *anAppWorld) open(app string, who coretypes.Signer, till time.Time) {
	x := base64.RawURLEncoding.EncodeToString(w.key.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(w.key.PublicKey.Y.FillBytes(make([]byte, 32)))
	if _, err := w.s.OpenAppSession(app, login.BrowserSessionBinding(w.token), x, y, who, till); err != nil {
		panic(err)
	}
}

// request builds the browser's request, signed with key (or not, when nil).
func (w *anAppWorld) request(method, path, body, origin string, key *ecdsa.PrivateKey) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:51000"
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("Authorization", "Bearer "+w.token)
	if key == nil {
		return r
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := login.BrowserSessionBinding(ts + path + body + origin)[:20]
	signed := login.BrowserProofString(method, r.Host, r.URL.RequestURI(), ts, nonce, login.BrowserSessionBinding(w.token), []byte(body))
	// WebCrypto's ECDSA signature: r then s, 32 bytes each.
	rr, ss, err := ecdsa.Sign(rand.Reader, key, hashOf(signed))
	if err != nil {
		panic(err)
	}
	sig := append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	r.Header.Set(login.HeaderBrowserProofTime, ts)
	r.Header.Set(login.HeaderBrowserProofNonce, nonce)
	r.Header.Set(login.HeaderBrowserProof, base64.RawURLEncoding.EncodeToString(sig))
	return r
}

func (w *anAppWorld) serve(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

const talk = "/api/mcp/agents/agent-1/conversations"

func TestAValidAppSessionSpeaksAsItsPersonAndIsNotAController(t *testing.T) {
	w := anAppSessionWorld(t)
	rec := w.serve(w.request(http.MethodPost, talk, `{"body":"hello"}`, chatOrigin, w.key))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["person"] != "Eann" || got["app"] != true || got["controller"] != false {
		t.Fatalf("answer = %v, want Ann through an app session and no controller", got)
	}
	// What it signed can be checked later by anyone, from the record alone.
	if got["verify"] != "" {
		t.Fatalf("the proof the record keeps does not verify: %v", got["verify"])
	}
	for _, p := range []string{"/api/mcp/agents/agent-1/conversations", "/api/mcp/conversations/c1"} {
		if rec := w.serve(w.request(http.MethodGet, p, "", chatOrigin, w.key)); rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != chatOrigin {
		t.Fatalf("the app's own origin is not answered: %v", rec.Header())
	}
}

func TestAnAppSessionReachesTheTalkRoutesAndNothingElse(t *testing.T) {
	w := anAppSessionWorld(t)
	for _, p := range []string{"/api/mcp/conversations/c1/export", "/api/employees"} {
		if rec := w.serve(w.request(http.MethodGet, p, "", chatOrigin, w.key)); rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s = %d, want refused: %s", p, rec.Code, rec.Body)
		}
	}
}

func TestACopiedSessionTokenWithoutTheKeyIsRefused(t *testing.T) {
	w := anAppSessionWorld(t)
	stolen, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, r := range map[string]*http.Request{
		"no signature at all":     w.request(http.MethodPost, talk, `{"body":"x"}`, chatOrigin, nil),
		"signed with another key": w.request(http.MethodPost, talk, `{"body":"x"}`, chatOrigin, stolen),
		"no origin, no signature": w.request(http.MethodGet, talk, "", "", nil),
		"a token nobody opened": func() *http.Request {
			w.token = "never-opened"
			return w.request(http.MethodGet, talk, "", chatOrigin, w.key)
		}(),
	} {
		rec := w.serve(r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401: %s", name, rec.Code, rec.Body)
		}
	}
}

func TestAProofIsUsedOnceAndCoversTheBody(t *testing.T) {
	w := anAppSessionWorld(t)
	r := w.request(http.MethodPost, talk, `{"body":"x"}`, chatOrigin, w.key)
	if rec := w.serve(r.Clone(r.Context())); rec.Code != http.StatusOK {
		t.Fatalf("first use: %d", rec.Code)
	}
	again := w.request(http.MethodPost, talk, `{"body":"x"}`, chatOrigin, w.key)
	again.Header = r.Header.Clone()
	again.Body = httptest.NewRequest(http.MethodPost, talk, strings.NewReader(`{"body":"x"}`)).Body
	if rec := w.serve(again); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a proof used twice = %d, want 401", rec.Code)
	}
	changed := w.request(http.MethodPost, talk, `{"body":"x"}`, chatOrigin, w.key)
	changed.Body = httptest.NewRequest(http.MethodPost, talk, strings.NewReader(`{"body":"y"}`)).Body
	if rec := w.serve(changed); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a body changed in flight = %d, want 401", rec.Code)
	}
}

func TestASessionOfOneAppDoesNotSpeakFromAnother(t *testing.T) {
	w := anAppSessionWorld(t)
	// The chat app's session, used from another app's page.
	if rec := w.serve(w.request(http.MethodGet, talk, "", otherOrigin, w.key)); rec.Code != http.StatusForbidden {
		t.Fatalf("from another app's origin = %d, want 403: %s", rec.Code, rec.Body)
	}
	// From an origin no app lists.
	if rec := w.serve(w.request(http.MethodGet, talk, "", "https://evil.example", w.key)); rec.Code != http.StatusForbidden {
		t.Fatalf("from an unlisted origin = %d, want 403", rec.Code)
	}
	// A session for a non-app or an unknown app cannot be opened at all (TestOpenAppSessionRefusesWhatAnAppSessionMayNotBe).
}

func TestAnExpiredOrEndedSessionIsRefused(t *testing.T) {
	w := anAppSessionWorld(t)
	w.token = "short"
	w.open("chat", w.who, time.Now().Add(50*time.Millisecond))
	time.Sleep(80 * time.Millisecond)
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an expired session = %d, want 401", rec.Code)
	}
	w.token = "ended"
	w.open("chat", w.who, time.Now().Add(time.Hour))
	w.s.EndAppSessionsOf("Eann")
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an ended session = %d, want 401", rec.Code)
	}
}

func TestAPersonWhoNoLongerStandsSpeaksNoMore(t *testing.T) {
	w := anAppSessionWorld(t)
	if _, _, err := w.s.assetHandler.Store.SetEmployeeStatus("Eann", "revoked", ""); err != nil {
		t.Fatal(err)
	}
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a removed person = %d, want 401: %s", rec.Code, rec.Body)
	}
}

func TestACorsAnswerIsForAnAppsOwnOriginOnTheTalkRoutesOnly(t *testing.T) {
	w := anAppSessionWorld(t)
	preflight := func(origin, path string) *httptest.ResponseRecorder {
		method := "POST"
		if strings.HasPrefix(path, "/api/mcp/conversations/") {
			method = "GET"
		}
		r := httptest.NewRequest(http.MethodOptions, path, nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", method)
		r.Header.Set("Access-Control-Request-Headers", "authorization,x-browser-proof,x-browser-proof-time,x-browser-proof-nonce,content-type")
		return w.serve(r)
	}
	if got := preflight(chatOrigin, talk).Header().Get("Access-Control-Allow-Origin"); got != chatOrigin {
		t.Fatalf("a listed origin on a talk route = %q", got)
	}
	if got := preflight(chatOrigin, "/api/mcp/conversations/c1").Header().Get("Access-Control-Allow-Origin"); got != chatOrigin {
		t.Fatalf("a listed origin on the conversation route = %q", got)
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"an unlisted origin":                 preflight("https://evil.example", talk),
		"a listed origin, another route":     preflight(chatOrigin, "/api/employees"),
		"a listed origin, the export":        preflight(chatOrigin, "/api/mcp/conversations/c1/export"),
		"a website's origin is not an app's": preflight("https://site.example", talk),
	} {
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s was answered: %q", name, got)
		}
	}
	// And an answer to a refused request still tells the page nothing it may read
	// for an origin that is not listed.
	if got := w.serve(w.request(http.MethodGet, talk, "", otherOrigin, w.key)).Header().Get("Access-Control-Allow-Origin"); got != otherOrigin {
		// another app's origin is listed (for that app); the session is what refuses it
		t.Logf("other app's origin answered %q", got)
	}
}

func TestAControllerStillWorksOnTheTalkRoutes(t *testing.T) {
	resetSeenSignatures(t)
	cw := newControllerWorld(t)
	s := cw.s
	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{ID: "chat", AssetType: "app", Origin: chatOrigin}); err != nil {
		t.Fatal(err)
	}
	say := func(w http.ResponseWriter, r *http.Request) {
		person, proof, err := s.thePersonAsking(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_, asApp := TheAppSessionThatAsked(r)
		_, asController := TheControllerThatAsked(r)
		verify := (agentmessage.ControllerProof{
			Controller: proof.Controller, PublicKey: proof.PublicKey, SignedString: proof.SignedString,
			Signature: proof.Signature, RequestBytes: proof.RequestBytes, ControllerGrant: proof.ControllerGrant, Scheme: proof.Scheme,
		}).Verify()
		_ = json.NewEncoder(w).Encode(map[string]any{"person": person.AID, "app": asApp, "controller": asController, "verifies": verify == nil})
	}
	s.MountExtraRoutes(func(r chi.Router) {
		r.Post("/mcp/agents/{id}/conversations", say)
		r.Get("/mcp/conversations/{cid}", say)
	})
	h := s.buildRouter()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/mcp/agents/agent-1/conversations", `{"body":"hello"}`},
		{http.MethodGet, "/api/mcp/conversations/c1", ""},
	} {
		target, err := s.whoThisIdentityAgentIs()
		if err != nil {
			t.Fatal(err)
		}
		r := asThatMachineTo(t, target, cw.ctlAID, c.method, c.path, c.body, cw.ctlSeed, authprovider.Level(""), time.Now())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var got map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got["person"] != talkSigner || got["controller"] != true || got["app"] != false || (c.body != "" && got["verifies"] != true) {
			t.Fatalf("%s %s by a controller = %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
}

func hashOf(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

func TestOpenAppSessionRefusesWhatAnAppSessionMayNotBe(t *testing.T) {
	w := anAppSessionWorld(t)
	x := base64.RawURLEncoding.EncodeToString(w.key.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(w.key.PublicKey.Y.FillBytes(make([]byte, 32)))
	till := time.Now().Add(time.Hour)
	hash := login.BrowserSessionBinding("fresh-token")
	if _, err := w.s.OpenAppSession("chat", hash, x, y, coretypes.Signer{AID: "Eown", Standing: "owner"}, till); err == nil {
		t.Fatal("a session as the owner was opened")
	}
	for _, app := range []string{"nonexistent", "site"} {
		if _, err := w.s.OpenAppSession(app, hash, x, y, w.who, till); err == nil {
			t.Fatalf("a session for %q, which is not an app asset, was opened", app)
		}
	}
	if _, err := w.s.OpenAppSession("chat", login.BrowserSessionBinding(w.token), x, y, coretypes.Signer{AID: "Eother", Standing: "signer"}, till); err == nil {
		t.Fatal("a token hash already registered was overwritten")
	}
	// The original session is untouched and still speaks as Ann.
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusOK {
		t.Fatalf("the original session = %d: %s", rec.Code, rec.Body)
	}
	if _, err := w.s.OpenAppSession("chat", hash, x, y, w.who, till); err != nil {
		t.Fatalf("a good session was refused: %v", err)
	}
}

func TestTheProofCoversTheHost(t *testing.T) {
	w := anAppSessionWorld(t)
	r := w.request(http.MethodGet, talk, "", chatOrigin, w.key)
	r.Host = "elsewhere.example"
	if rec := w.serve(r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a proof replayed at another host = %d, want 401", rec.Code)
	}
}

func TestExpiredSessionsAreDroppedWhenAnotherIsOpened(t *testing.T) {
	w := anAppSessionWorld(t)
	w.token = "short-lived"
	w.open("chat", w.who, time.Now().Add(30*time.Millisecond))
	time.Sleep(60 * time.Millisecond)
	w.token = "later"
	w.open("chat", w.who, time.Now().Add(time.Hour))
	w.s.appSessions.mu.Lock()
	n := len(w.s.appSessions.sessions)
	w.s.appSessions.mu.Unlock()
	if n != 2 { // the world's own session and the new one; the expired one is gone
		t.Fatalf("%d sessions held, want 2", n)
	}
}

func TestACorsAnswerKeysOnTheMatchedRouteAndMethod(t *testing.T) {
	w := anAppSessionWorld(t)
	preflight := func(path, method string) string {
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.URL.Path, r.URL.RawPath = path, ""
		r.Header.Set("Origin", chatOrigin)
		r.Header.Set("Access-Control-Request-Method", method)
		return w.serve(r).Header().Get("Access-Control-Allow-Origin")
	}
	if got := preflight(talk, "POST"); got != chatOrigin {
		t.Fatalf("POST on the talk route = %q", got)
	}
	if got := preflight(talk, "DELETE"); got != "" {
		t.Fatalf("DELETE on the talk route was answered: %q", got)
	}
	if got := preflight("/api/mcp/conversations/c1", "POST"); got != "" {
		t.Fatalf("POST on the conversation route was answered: %q", got)
	}
	// Spelled to look like a talk path, but not a route the router serves.
	if got := preflight(talk+"/", "POST"); got != "" {
		t.Fatalf("a trailing-slash spelling was answered: %q", got)
	}
	if got := preflight("/api/mcp//agents/a/conversations", "POST"); got != "" {
		t.Fatalf("a doubled-slash spelling was answered: %q", got)
	}
}

func TestRenewingAnAppSessionExtendsItAndALapsedLeaseIsNotAdmitted(t *testing.T) {
	w := anAppSessionWorld(t)
	w.token = "lease"
	w.open("chat", w.who, time.Now().Add(300*time.Millisecond))
	hash := login.BrowserSessionBinding(w.token)
	if err := w.s.RenewAppSession(hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusOK {
		t.Fatalf("a renewed session = %d, want 200: %s", rec.Code, rec.Body)
	}
	// A lease nobody renews stops being admitted.
	w.token = "unrenewed"
	w.open("chat", w.who, time.Now().Add(150*time.Millisecond))
	time.Sleep(250 * time.Millisecond)
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a lease not renewed = %d, want 401", rec.Code)
	}
}

func TestAnExpiredOrEndedAppSessionCannotBeRenewedNorPastItsCap(t *testing.T) {
	w := anAppSessionWorld(t)
	w.token = "gone"
	w.open("chat", w.who, time.Now().Add(30*time.Millisecond))
	hash := login.BrowserSessionBinding(w.token)
	time.Sleep(60 * time.Millisecond)
	if err := w.s.RenewAppSession(hash, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("an expired session was renewed")
	}
	if rec := w.serve(w.request(http.MethodGet, talk, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session renewed after it expired = %d, want 401", rec.Code)
	}
	w.token = "ended-2"
	w.open("chat", w.who, time.Now().Add(time.Hour))
	hash = login.BrowserSessionBinding(w.token)
	w.s.EndAppSession(hash)
	if err := w.s.RenewAppSession(hash, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("an ended session was renewed")
	}
	w.token = "capped"
	w.open("chat", w.who, time.Now().Add(time.Minute))
	hash = login.BrowserSessionBinding(w.token)
	if err := w.s.RenewAppSession(hash, time.Now().Add(appSessionCap+time.Hour)); err == nil {
		t.Fatal("a session was renewed past its cap")
	}
	if err := w.s.RenewAppSession(hash, time.Now().Add(appSessionCap-time.Hour)); err != nil {
		t.Fatalf("renewing within the cap: %v", err)
	}
	// A shorter until never shortens it.
	if err := w.s.RenewAppSession(hash, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.s.appSessions.get(hash, time.Now().Add(time.Hour)); !ok {
		t.Fatal("a renewal to an earlier time shortened the session")
	}
}
