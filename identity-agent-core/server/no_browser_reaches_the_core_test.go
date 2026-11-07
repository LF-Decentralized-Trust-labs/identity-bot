package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
)

// No browser reaches the core (ADR-006): a browser talks to an app and the app
// talks to the core. The core answers no browser origin and admits no browser
// credential. An app's back end speaks for a person only with that person's own
// signed statement, and only for the person it serves.

const (
	appPage   = "https://chat.example"
	talkPath  = "/api/mcp/agents/agent-1/conversations"
	talkWords = `{"to":"agent-1","body":"hello","nonce":"n-%d"}`
)

type ed25519Key struct{ priv ed25519.PrivateKey }

func (k ed25519Key) PublicKey() ([]byte, error)    { return k.priv.Public().(ed25519.PublicKey), nil }
func (k ed25519Key) Sign(d []byte) ([]byte, error) { return ed25519.Sign(k.priv, d), nil }

func aPersonsKey(b byte) ed25519Key {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return ed25519Key{ed25519.NewKeyFromSeed(seed)}
}

type anAppWorld struct {
	cw     *controllerWorld
	h      http.Handler
	target string
	served *int
	calls  int
}

func newAnAppWorld(t *testing.T) *anAppWorld {
	t.Helper()
	resetSeenSignatures(t)
	cw := newControllerWorld(t)
	s := cw.s
	st := s.assetHandler.Store
	if err := st.UpsertAsset(asset.Asset{ID: "chat", DisplayName: "chat", AssetType: "app", Origin: appPage}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEmployee(asset.Employee{PairwiseAID: "Ebob", Name: "Bob", Role: "Staff", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	served := 0
	say := func(w http.ResponseWriter, r *http.Request) {
		person, proof, err := s.thePersonAsking(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		served++
		_, has := ThePersonStatementThatSpoke(proof)
		_ = json.NewEncoder(w).Encode(map[string]any{"person": person.AID, "statement": has})
	}
	s.MountExtraRoutes(func(r chi.Router) {
		r.Post("/mcp/agents/{id}/conversations", say)
		r.Get("/mcp/agents/{id}/conversations", say)
		r.Get("/mcp/conversations/{cid}", say)
	})
	target, err := s.whoThisIdentityAgentIs()
	if err != nil {
		t.Fatal(err)
	}
	return &anAppWorld{cw: cw, h: s.buildRouter(), target: target, served: &served}
}

// fromTheApp is the app's back end asking, signed as an enrolled machine does.
func (w *anAppWorld) fromTheApp(t *testing.T, speakingFor, statement string) *httptest.ResponseRecorder {
	t.Helper()
	// A machine's signature works once, so each request carries its own nonce.
	w.calls++
	r := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, fmt.Sprintf(talkWords, w.calls), w.cw.ctlSeed, authprovider.Level(""), time.Now())
	if speakingFor != "" {
		r.Header.Set(headerSpeakingFor, speakingFor)
	}
	if statement != "" {
		r.Header.Set(headerPersonStatement, statement)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

// theyStatement is what the person's own device signs over the words.
func (w *anAppWorld) theyStatement(t *testing.T, from string, key ed25519Key, mutate func(*agentmessage.PersonStatement)) string {
	t.Helper()
	salt, err := agentmessage.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := agentmessage.Fingerprint(salt, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := agentbody.Identity(key)
	if err != nil {
		t.Fatal(err)
	}
	st := agentmessage.PersonStatement{
		Agent: w.cw.s.thisIdentityAgentsIdentifier(), Conversation: "c1", MessageID: "m1" + id[:6] + fp[:6],
		Kind: agentmessage.PersonKindMessage, From: from, Signer: id, To: "agent-1",
		Nonce: "nonce-0123456789abcdef" + fp[:6], Time: time.Now().UTC().Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
	}
	if mutate != nil {
		mutate(&st)
	}
	sig, err := agentbody.Sign(key, st.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_, vk, _ := agentbody.Identity(key)
	js, err := json.Marshal(agentmessage.PersonProof{Statement: st, Verkey: vk, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(js)
}

func TestNoBrowserOriginIsAnsweredOnAnyRoute(t *testing.T) {
	w := newAnAppWorld(t)
	for _, origin := range []string{appPage, "https://evil.example", "null"} {
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/api/mcp/conversations/c1"},
			{http.MethodPost, talkPath},
			{http.MethodGet, talkPath},
			{http.MethodGet, "/api/mcp/conversations/c1/export"},
			{http.MethodGet, "/api/employees"},
		} {
			r := httptest.NewRequest(c.method, c.path, nil)
			r.RemoteAddr = "203.0.113.9:51000"
			r.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			w.h.ServeHTTP(rec, r)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s %s from %s was answered for that origin: %q", c.method, c.path, origin, got)
			}
			// And the preflight a browser sends first.
			p := httptest.NewRequest(http.MethodOptions, c.path, nil)
			p.RemoteAddr = "203.0.113.9:51000"
			p.Header.Set("Origin", origin)
			p.Header.Set("Access-Control-Request-Method", c.method)
			p.Header.Set("Access-Control-Request-Headers", "authorization")
			prec := httptest.NewRecorder()
			w.h.ServeHTTP(prec, p)
			for h := range prec.Header() {
				if strings.HasPrefix(strings.ToLower(h), "access-control-") {
					t.Errorf("a preflight for %s %s from %s was answered with %s", c.method, c.path, origin, h)
				}
			}
		}
	}
}

func TestNoBrowserCredentialIsAdmittedOnTheTalkRoutes(t *testing.T) {
	w := newAnAppWorld(t)
	// What a browser holds: a session token, a key-bound proof, the person's
	// own statement. None of them is a credential here without the app's body.
	statement := w.theyStatement(t, talkSigner, aPersonsKey(1), nil)
	for name, set := range map[string]func(*http.Request){
		"a bearer session token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer session-token-from-a-browser") },
		"a browser key proof": func(r *http.Request) {
			r.Header.Set("X-IA-Browser-Proof", "c2ln")
			r.Header.Set("X-IA-Browser-Proof-Time", time.Now().UTC().Format(time.RFC3339))
			r.Header.Set("X-IA-Browser-Proof-Nonce", "bm9uY2Utbm9uY2U")
		},
		"the person's statement alone": func(r *http.Request) {
			r.Header.Set(headerSpeakingFor, talkSigner)
			r.Header.Set(headerPersonStatement, statement)
		},
	} {
		r := httptest.NewRequest(http.MethodPost, talkPath, strings.NewReader(fmt.Sprintf(talkWords, 0)))
		r.RemoteAddr = "203.0.113.9:51000"
		r.Header.Set("Origin", appPage)
		set(r)
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK || *w.served != 0 {
			t.Fatalf("%s was admitted: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestAnAppSpeaksForAPersonWhoSignedItsWords(t *testing.T) {
	w := newAnAppWorld(t)
	rec := w.fromTheApp(t, talkSigner, w.theyStatement(t, talkSigner, aPersonsKey(1), nil))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["person"] != talkSigner || got["statement"] != true {
		t.Fatalf("the app speaking for the person it serves, with their statement = %d %s", rec.Code, rec.Body)
	}
}

func TestAnAppCannotSpeakForAPersonWhoDidNotSign(t *testing.T) {
	w := newAnAppWorld(t)
	good := w.theyStatement(t, talkSigner, aPersonsKey(1), nil)
	for name, c := range map[string]struct{ who, statement string }{
		"no statement":                                     {talkSigner, ""},
		"a statement and no one named":                     {"", good},
		"a person the app does not serve":                  {"Ebob", w.theyStatement(t, "Ebob", aPersonsKey(9), nil)},
		"a statement from someone else than the one named": {talkSigner, w.theyStatement(t, "Ebob", aPersonsKey(9), nil)},
		"a person nobody knows":                            {"Estranger", w.theyStatement(t, "Estranger", aPersonsKey(9), nil)},
		"a statement for another Identity Agent": {talkSigner, w.theyStatement(t, talkSigner, aPersonsKey(1),
			func(s *agentmessage.PersonStatement) { s.Agent = "EOTHERAGENT" })},
		"a stale statement": {talkSigner, w.theyStatement(t, talkSigner, aPersonsKey(1),
			func(s *agentmessage.PersonStatement) { s.Time = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) })},
		"an unsalted statement": {talkSigner, w.theyStatement(t, talkSigner, aPersonsKey(1),
			func(s *agentmessage.PersonStatement) { s.FingerprintVersion = agentmessage.FingerprintV0 })},
		"a statement that is not base64url": {talkSigner, "!!not-a-statement"},
	} {
		if rec := w.fromTheApp(t, c.who, c.statement); rec.Code == http.StatusOK {
			t.Errorf("%s was admitted: %s", name, rec.Body)
		} else if testing.Verbose() {
			t.Logf("%s: %d %s", name, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	// A statement whose signature was altered after signing.
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	var p agentmessage.PersonProof
	_ = json.Unmarshal(raw, &p)
	p.Statement.To = "agent-2"
	js, _ := json.Marshal(p)
	if rec := w.fromTheApp(t, talkSigner, base64.RawURLEncoding.EncodeToString(js)); rec.Code == http.StatusOK {
		t.Errorf("a statement changed after it was signed was admitted")
	}
	if *w.served != 0 {
		t.Fatalf("%d refused requests were served", *w.served)
	}
}

func TestAPersonsStatementIsUsedOnce(t *testing.T) {
	w := newAnAppWorld(t)
	st := w.theyStatement(t, talkSigner, aPersonsKey(1), nil)
	if rec := w.fromTheApp(t, talkSigner, st); rec.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", rec.Code, rec.Body)
	}
	if rec := w.fromTheApp(t, talkSigner, st); rec.Code == http.StatusOK {
		t.Fatal("the same statement was admitted twice")
	}
}

func TestAMachineStillSpeaksAsItsSignerWithNoStatementNamed(t *testing.T) {
	w := newAnAppWorld(t)
	rec := w.fromTheApp(t, "", "")
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["person"] != talkSigner || got["statement"] != false {
		t.Fatalf("a machine speaking as the signer it belongs to = %d %s", rec.Code, rec.Body)
	}
}
