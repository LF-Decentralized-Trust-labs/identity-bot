package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/trail"
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
	proof  *coretypes.ControllerProof
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
	// The asset admits Ann and Bob, who are not the machine's signer: an app
	// speaks for whoever its asset admits, not for one person.
	for _, m := range []string{"Eann", "Ebob"} {
		if err := st.AddMember(asset.AssetMember{AssetID: "chat", PairwiseAID: m, JoinedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.controllers().BindAppAsset(cw.ctlAID, "chat"); err != nil {
		t.Fatal(err)
	}
	served := 0
	aw := &anAppWorld{}
	say := func(w http.ResponseWriter, r *http.Request) {
		person, proof, err := s.thePersonAsking(r)
		aw.proof = proof
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		served++
		_, _, has := ThePersonStatementThatSpoke(proof)
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
	aw.cw, aw.h, aw.target, aw.served = cw, s.buildRouter(), target, &served
	return aw
}

// aBrowsersKey is a P-256 key a browser holds, signing as a machine key does
// everywhere in the core (low-s, raw r||s).
type aBrowsersKey struct{ priv *ecdsa.PrivateKey }

func newBrowsersKey(t *testing.T) aBrowsersKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return aBrowsersKey{k}
}
func (k aBrowsersKey) PublicKey() ([]byte, error) {
	return elliptic.MarshalCompressed(elliptic.P256(), k.priv.X, k.priv.Y), nil
}
func (k aBrowsersKey) Sign(d []byte) ([]byte, error) {
	sum := sha256.Sum256(d)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// signedIn is the person's sign-in at the chat asset naming this key, as the
// callback keeps it.
func (w *anAppWorld) signedIn(t *testing.T, person string, key agentbody.Signer, until time.Duration) {
	t.Helper()
	_, vk, err := agentbody.Identity(key)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := login.BrowserKeyThumbprintOfMachineKey(vk)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.cw.s.browserKeys().Record("chat", person, tp, time.Now().Add(until), time.Now()); err != nil {
		t.Fatal(err)
	}
}

// aSpokenRequest is one thing a person says through the app, and the ways a
// test may bend it.
type aSpokenRequest struct {
	who     string
	key     agentbody.Signer
	words   string // what the person signed a fingerprint of
	sent    string // what the app put in the body, when different
	mutate  func(*agentmessage.PersonStatement)
	noSalt  bool
	noState bool
	noWho   bool
	// conversation is what the body names, when it names one.
	conversation string
}

// say sends it as the app's back end does, and reports the answer.
func (w *anAppWorld) say(t *testing.T, q aSpokenRequest) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, w.request(t, q))
	return rec
}

// request is what the app's back end would send, not yet sent.
func (w *anAppWorld) request(t *testing.T, q aSpokenRequest) *http.Request {
	t.Helper()
	// A machine's signature works once, so each request carries its own nonce.
	w.calls++
	nonce := fmt.Sprintf("n-%d", w.calls)
	sent := q.sent
	if sent == "" {
		sent = q.words
	}
	body := fmt.Sprintf(`{"to":"agent-1","body":%q,"nonce":%q}`, sent, nonce)
	if q.conversation != "" {
		body = fmt.Sprintf(`{"conversation":%q,"to":"agent-1","body":%q,"nonce":%q}`, q.conversation, sent, nonce)
	}
	r := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, body, w.cw.ctlSeed, authprovider.Level(""), time.Now())
	salt, _ := agentmessage.NewSalt()
	fp, _ := agentmessage.Fingerprint(salt, []byte(q.words))
	id, vk, _ := agentbody.Identity(q.key)
	st := agentmessage.PersonStatement{
		Agent: w.cw.s.thisIdentityAgentsIdentifier(), Conversation: "c1", MessageID: nonce,
		Kind: agentmessage.PersonKindMessage, From: q.who, Signer: id, To: "agent-1",
		Nonce: "nonce-0123456789abcdef" + nonce, Time: time.Now().UTC().Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
	}
	if q.mutate != nil {
		q.mutate(&st)
	}
	sig, err := agentbody.Sign(q.key, st.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(agentmessage.PersonProof{Statement: st, Verkey: vk, Signature: sig})
	if !q.noWho {
		r.Header.Set(headerSpeakingFor, q.who)
	}
	if !q.noState {
		r.Header.Set(headerPersonStatement, base64.RawURLEncoding.EncodeToString(js))
	}
	if !q.noSalt {
		r.Header.Set(headerPersonSalt, base64.RawURLEncoding.EncodeToString(salt))
	}
	return r
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
	statement := "e30"
	for name, set := range map[string]func(*http.Request){
		"a bearer session token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer session-token-from-a-browser") },
		"a browser key proof": func(r *http.Request) {
			r.Header.Set("X-IA-Browser-Proof", "c2ln")
			r.Header.Set("X-IA-Browser-Proof-Time", time.Now().UTC().Format(time.RFC3339))
			r.Header.Set("X-IA-Browser-Proof-Nonce", "bm9uY2Utbm9uY2U")
		},
		"the person's statement alone": func(r *http.Request) {
			r.Header.Set(headerSpeakingFor, "Eann")
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

func (w *anAppWorld) mustBeRefused(t *testing.T, name string, q aSpokenRequest) {
	t.Helper()
	if rec := w.say(t, q); rec.Code == http.StatusOK {
		t.Errorf("%s was admitted: %s", name, rec.Body)
	} else if testing.Verbose() {
		t.Logf("%s: %d %s", name, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

func TestAValidStatementIsAdmittedAndLandsInTheTrail(t *testing.T) {
	w := newAnAppWorld(t)
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)
	// A second person, with their own key, is served by the same app: the
	// grant is the app's, not one person's.
	bobs := newBrowsersKey(t)
	w.signedIn(t, "Ebob", bobs, time.Hour)

	for _, c := range []struct {
		who string
		key agentbody.Signer
	}{{"Eann", key}, {"Ebob", bobs}} {
		rec := w.say(t, aSpokenRequest{who: c.who, key: c.key, words: "hello"})
		var got map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got["person"] != c.who || got["statement"] != true {
			t.Fatalf("%s speaking through the app = %d %s", c.who, rec.Code, rec.Body)
		}
	}

	// What the request carries is what trail.Write takes, and it keeps it.
	if rec := w.say(t, aSpokenRequest{who: "Eann", key: key, words: "again", conversation: "c1"}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	proof := w.proof
	pp, gotSalt, ok := ThePersonStatementThatSpoke(proof)
	if !ok {
		t.Fatal("the statement did not reach the proof")
	}
	keys, err := didcomm.GenerateKeySet(w.cw.s.thisIdentityAgentsIdentifier())
	if err != nil {
		t.Fatal(err)
	}
	// The trail asks the core's own record whose the key is.
	tr := trail.New(permissiveRoster{keysSpeakingAt{s: w.cw.s, asset: "chat"}}, &keepingApp{}, trail.Options{
		Agent:       w.cw.s.thisIdentityAgentsIdentifier(),
		Countersign: func(r agentmessage.Record) (*didcomm.Envelope, error) { return agentmessage.Countersign(keys, r) },
	})
	if err := tr.Open("c1", "Eann", false); err != nil {
		t.Fatal(err)
	}
	res, err := tr.Write(context.Background(), trail.Write{
		Statement: pp.Statement, Verkey: pp.Verkey, Signature: pp.Signature, Salt: gotSalt, Words: []byte("again"),
	})
	if err != nil || res.State != trail.Committed {
		t.Fatalf("the trail did not keep what the app carried: %+v %v", res, err)
	}
}

// permissiveRoster says every rule but whose a key is allows: this test is
// about the key, which is the core's own record.
type permissiveRoster struct{ trail.KeyRoster }

func (permissiveRoster) IsAIAgent(string) bool             { return true }
func (permissiveRoster) MayUseAgent(_, _ string) bool      { return true }
func (permissiveRoster) AgentGrantAllows(_, _ string) bool { return true }
func (permissiveRoster) ActiveEmployee(string) bool        { return true }
func (permissiveRoster) IsSigner(string) bool              { return false }

// keepingApp keeps the words and confirms their fingerprint.
type keepingApp struct{}

func (keepingApp) Reachable(context.Context) error { return nil }
func (keepingApp) Keep(_ context.Context, f trail.Forward) (trail.Receipt, error) {
	fp, err := agentmessage.Fingerprint(f.Salt, f.Words)
	return trail.Receipt{Fingerprint: fp}, err
}
func (keepingApp) Discard(context.Context, string, string) error { return nil }

func TestAnAppCannotSpeakForAPersonWhoDidNotSign(t *testing.T) {
	w := newAnAppWorld(t)
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)
	good := aSpokenRequest{who: "Eann", key: key, words: "hello"}

	with := func(f func(*aSpokenRequest)) aSpokenRequest { q := good; f(&q); return q }
	for name, q := range map[string]aSpokenRequest{
		"no statement":                       with(func(q *aSpokenRequest) { q.noState = true }),
		"no one named":                       with(func(q *aSpokenRequest) { q.noWho = true }),
		"no salt":                            with(func(q *aSpokenRequest) { q.noSalt = true }),
		"an invented key":                    {who: "Eann", key: newBrowsersKey(t), words: "hello"},
		"words that are not the ones signed": with(func(q *aSpokenRequest) { q.sent = "something else" }),
		"another conversation than the body names": with(func(q *aSpokenRequest) {
			q.conversation = "c1"
			q.mutate = func(s *agentmessage.PersonStatement) { s.Conversation = "other" }
		}),
		"another kind": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindClose; s.To = "" }
		}),
		"another recipient": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.To = "agent-2" }
		}),
		"another message id": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.MessageID = "m-other" }
		}),
		"a statement from someone else than the one named": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.From = "Ebob" }
		}),
		"a statement for another Identity Agent": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.Agent = "EOTHERAGENT" }
		}),
		"a statement signed six minutes ago": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) {
				s.Time = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339)
			}
		}),
		"an unsalted statement": with(func(q *aSpokenRequest) {
			q.mutate = func(s *agentmessage.PersonStatement) { s.FingerprintVersion = agentmessage.FingerprintV0 }
		}),
	} {
		w.mustBeRefused(t, name, q)
	}
	// A person the asset does not admit, with a key they signed in with.
	other := newBrowsersKey(t)
	w.signedIn(t, "Estranger", other, time.Hour)
	w.mustBeRefused(t, "a person the asset does not admit", aSpokenRequest{who: "Estranger", key: other, words: "hello"})
	// A person removed from the asset since they signed in.
	gone := newBrowsersKey(t)
	w.signedIn(t, "Egone", gone, time.Hour)
	if err := w.cw.s.assetHandler.Store.AddMember(asset.AssetMember{AssetID: "chat", PairwiseAID: "Egone", JoinedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if rec := w.say(t, aSpokenRequest{who: "Egone", key: gone, words: "hello"}); rec.Code != http.StatusOK {
		t.Fatalf("a member was refused: %d %s", rec.Code, rec.Body)
	}
	if err := w.cw.s.assetHandler.Store.RemoveMember("chat", "Egone"); err != nil {
		t.Fatal(err)
	}
	w.mustBeRefused(t, "a person removed from the asset since they signed in", aSpokenRequest{who: "Egone", key: gone, words: "hello"})
	// A key whose sign-in has lapsed.
	old := newBrowsersKey(t)
	w.signedIn(t, "Eann", old, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	w.mustBeRefused(t, "a key whose sign-in has lapsed", aSpokenRequest{who: "Eann", key: old, words: "hello"})
	// A key that signed in as Ann cannot speak for Bob.
	w.mustBeRefused(t, "a key that signed in as someone else", aSpokenRequest{who: "Ebob", key: key, words: "hello"})
	// An Ed25519 key is not a browser key, whatever it signs.
	ed := aPersonsKey(1)
	if _, vk, _ := agentbody.Identity(ed); true {
		if _, err := login.BrowserKeyThumbprintOfMachineKey(vk); err == nil {
			t.Fatal("an Ed25519 key was given a browser key thumbprint")
		}
	}
	w.mustBeRefused(t, "a key that is not a browser's", aSpokenRequest{who: "Eann", key: ed, words: "hello"})
	// The one request served is the removed person's, while still a member.
	if *w.served != 1 {
		t.Fatalf("%d requests were served, and only one was admitted", *w.served)
	}
}

func TestAPersonsStatementIsUsedOnce(t *testing.T) {
	w := newAnAppWorld(t)
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)
	r := w.request(t, aSpokenRequest{who: "Eann", key: key, words: "hello"})
	grant, _, err := w.cw.s.controllers().Get(w.cw.ctlAID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readSignedBody(r)
	if _, _, _, _, err := w.cw.s.thePersonAnAppSpeaksFor(r, grant, body); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, _, _, _, err := w.cw.s.thePersonAnAppSpeaksFor(r, grant, body); err == nil {
		t.Fatal("the same statement was admitted twice")
	}
}

func TestAMachineBoundToAnAppSpeaksForNoOneWithoutAStatement(t *testing.T) {
	w := newAnAppWorld(t)
	w.calls++
	r := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, fmt.Sprintf(talkWords, w.calls), w.cw.ctlSeed, authprovider.Level(""), time.Now())
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK || *w.served != 0 {
		t.Fatalf("an app machine with no statement was served: %d %s", rec.Code, rec.Body)
	}
}

func TestAMachineBoundToNoAppStillSpeaksAsItsSigner(t *testing.T) {
	w := newAnAppWorld(t)
	c := w.cw.s.controllers()
	grantsLock.Lock()
	all, err := c.load()
	if err == nil {
		g := all[w.cw.ctlAID]
		g.AppAsset = ""
		all[w.cw.ctlAID] = g
		err = c.save(all)
	}
	grantsLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w.calls++
	r := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, fmt.Sprintf(talkWords, w.calls), w.cw.ctlSeed, authprovider.Level(""), time.Now())
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got["person"] != talkSigner || got["statement"] != false {
		t.Fatalf("a machine speaking as the signer it belongs to = %d %s", rec.Code, rec.Body)
	}
	// And it does not speak for anyone else by naming them.
	w.calls++
	r = asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, fmt.Sprintf(talkWords, w.calls), w.cw.ctlSeed, authprovider.Level(""), time.Now())
	r.Header.Set(headerSpeakingFor, "Eann")
	rec = httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK {
		t.Fatal("a machine bound to no app spoke for a named person")
	}
}
