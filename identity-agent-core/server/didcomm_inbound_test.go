package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/store"
)

// Reaching this agent from another one.
//
// POST /didcomm was registered as the public inbound endpoint and never added to
// the allow-list, so the router refused every peer with 403 before the handler
// ran. Agent-to-agent messaging did not work at all, and nothing said so — the
// handler it never reached is full of careful verification.
//
// Making it reachable puts the handler's own checks on the front line, so these
// tests pin them: what an unknown sender gets, what a sender may declare about
// itself, and that neither answer depends on anybody being logged in.

func didcommPost(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := s.buildRouter("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("POST", "/didcomm", body))
	return w
}

// The gap this closes: the route was unreachable, so no peer could ever deliver
// anything.
func TestAPeerCanReachTheInboundRoute(t *testing.T) {
	s := newAuthTestServer(t)
	w := didcommPost(t, s, `{"protected":{"skid":""}}`)

	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "authoriz") {
		t.Fatalf("the router refused a peer before the handler ran: %d %s", w.Code, w.Body.String())
	}
	// It reached the handler, which rejects this envelope on its own terms.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected the handler's own 400 for a missing skid, got %d %s", w.Code, w.Body.String())
	}
}

// Public means public. If this ever starts depending on being the owner, every
// peer silently stops being able to deliver again — which is the failure this
// whole change is undoing.
func TestTheInboundRouteDoesNotRequireBeingTheOwner(t *testing.T) {
	if _, ok := publicRoutes["POST /didcomm"]; !ok {
		t.Fatal("POST /didcomm is not in the public allow-list, so no peer can reach it")
	}
}

// A stranger is refused before anything expensive happens, and the refusal does
// not echo what they sent.
//
// It used to fall through to auto-registration for any AID belonging to a local
// provisioned agent. Those AIDs are published in OOBI URLs, so an anonymous POST
// naming one made this agent mint a post-quantum keyset and write two files
// before a single byte was authenticated.
func TestAnUnregisteredSenderIsRefusedWithoutMintingAnything(t *testing.T) {
	s := newAuthTestServer(t)
	before := dataDirSnapshot(t, s.DataDir)

	w := didcommPost(t, s, `{"protected":{"skid":"ESTRANGER-AID"},"recipients":[{"header":{"kid":"EUS"}}]}`)

	if w.Code != http.StatusForbidden {
		t.Fatalf("an unregistered sender was not refused: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ESTRANGER-AID") {
		t.Errorf("the refusal echoed the sender's own string back: %s", w.Body.String())
	}
	if after := dataDirSnapshot(t, s.DataDir); after != before {
		t.Errorf("an unauthenticated request changed stored state:\nbefore %q\nafter  %q", before, after)
	}
}

// The sender does not get to decide how long we remember it for. An envelope
// valid until 2099 has to be held in the replay cache until then, so a peer
// could fill it with entries that never evict — and because that cache is
// per-process, the same envelope becomes replayable after any restart for as
// long as the sender chose.
func TestAnEnvelopeCannotDeclareItselfValidForever(t *testing.T) {
	if maxEnvelopeLifetime <= 0 {
		t.Fatal("there is no ceiling on how long an envelope may declare itself valid")
	}
	if maxEnvelopeLifetime > 24*time.Hour {
		t.Errorf("the ceiling is %s, long enough for the replay cache to be filled at will", maxEnvelopeLifetime)
	}
}

// The sweep walks every entry on every call, so an unbounded map is not just
// memory: cost per message grows with what a peer has planted.
func TestTheReplayCacheIsBounded(t *testing.T) {
	if maxSeenEntries <= 0 {
		t.Fatal("the replay cache has no size cap")
	}

	// Full, with entries that are live so the sweep cannot reclaim them.
	future := time.Now().Add(30 * time.Minute)
	didcommSeen.Lock()
	didcommSeen.m = map[string]time.Time{}
	for i := 0; i < maxSeenEntries; i++ {
		didcommSeen.m[string(rune(i))+"-planted"] = future
	}
	didcommSeen.Unlock()

	if seenBefore("a-genuinely-new-id", future) {
		t.Error("a new message was reported as a replay because the cache was full")
	}

	didcommSeen.Lock()
	grew := len(didcommSeen.m) > maxSeenEntries
	didcommSeen.m = map[string]time.Time{}
	didcommSeen.Unlock()
	if grew {
		t.Error("the cache grew past its cap")
	}
}

// A half-written file is not a smaller file — every reader here discards the
// unmarshal error and carries on with an empty map. So an interrupted write
// silently emptied the peers list, the inbox, or this agent's DIDComm private
// keys.
func TestStateFilesAreReplacedInOneStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte(`{"original":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte(`{"replacement":true}`), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]bool
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("the file did not parse after replacement: %v", err)
	}
	if !parsed["replacement"] {
		t.Error("the replacement did not land")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
}

// The listeners were started with a zero-value http.Server: no deadlines at all.
// A connection that sent one byte a minute held a descriptor and a goroutine for
// as long as it liked.
func TestTheServerHasReadDeadlines(t *testing.T) {
	s := newAuthTestServer(t)
	srv := s.httpServer()

	if srv.ReadHeaderTimeout == 0 {
		t.Error("no ReadHeaderTimeout: a connection can hold a slot having sent nothing")
	}
	if srv.ReadTimeout == 0 {
		t.Error("no ReadTimeout")
	}
	if srv.IdleTimeout == 0 {
		t.Error("no IdleTimeout: kept-alive connections are never given up")
	}
}

// dataDirSnapshot lists the data directory and the size of each file, so a test
// can assert that an unauthenticated request changed nothing.
func dataDirSnapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "<unreadable>"
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		b.WriteString(e.Name())
		b.WriteString(":")
		b.WriteString(time.Duration(info.Size()).String())
		b.WriteString(" ")
	}
	return b.String()
}

// The first message anybody sends to a fresh agent.
//
// A DIDComm keyset is minted lazily, so an agent that has never SENT anything
// has none — and the endpoint that publishes it refused to mint for a
// non-owner, which is right in general and wrong for exactly one case. Every
// new customer is in that state, and they are precisely the people who need to
// be reachable: somebody who just bought hosting and has never written to
// anyone is who a payment warning is for.
func TestAFreshAgentCanStillBeWrittenToFirst(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")

	r := s.buildRouter("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/didcomm/did?aid=EOURS", ""))

	if w.Code != http.StatusOK {
		t.Fatalf("a stranger could not read our own published keys: %d %s", w.Code, w.Body.String())
	}
}

// The bound on that exception. A stranger naming any other identifier must not
// make this agent generate a keyset — that is unbounded work on demand, which
// is the same hole that was closed on the inbound route.
func TestAStrangerStillCannotMakeUsGenerateKeysForAnythingElse(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")

	r := s.buildRouter("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/didcomm/did?aid=ESOMETHING-ELSE", ""))

	if w.Code == http.StatusOK {
		t.Fatal("a stranger made this agent mint a keyset for an identifier of their choosing")
	}
}

// serverWithIdentity is an agent that knows who it is, which newAuthTestServer
// does not build — it exists to test the authorisation gate and needs no store.
func serverWithIdentity(t *testing.T, aid string) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ds.SaveIdentity(store.IdentityState{
		AID: aid, PublicKey: "DPUB", Created: "2026-07-31T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds}
}
