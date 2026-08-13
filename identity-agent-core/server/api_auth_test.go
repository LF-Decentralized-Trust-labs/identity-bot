package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

func newAuthTestServer(t *testing.T) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: t.TempDir()}
}

// remote builds a request that did not originate on this machine — the shape a
// tunnelled or forwarded caller has.
func remote(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:51000"
	return r
}

// local builds a request from the machine the agent runs on.
func local(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:51000"
	return r
}

// The whole point: a route nobody classified is private. This is the property
// that has to hold for routes that do not exist yet.
func TestUnclassifiedRoutesAreOwnerOnly(t *testing.T) {
	for _, tc := range []struct{ method, pattern string }{
		{"POST", "/api/some/route/invented/tomorrow"},
		{"GET", "/api/identity"},
		{"POST", "/api/reset"},
		{"POST", "/api/keystore/root-seed"},
		{"POST", "/api/mcp/tokens"},
		{"GET", "/api/profile"},
		{"POST", "/api/scan/execute"},
		{"GET", "/api/vault/credentials"},
	} {
		if got := classify(tc.method, tc.pattern); got != accessOwner {
			t.Errorf("%s %s classified %q — the default must be owner-only", tc.method, tc.pattern, got)
		}
	}
}

// Every route that is deliberately open should be open for the reason recorded
// next to it — an entry with no reason is an entry nobody reviewed.
func TestEveryPublicRouteStatesWhy(t *testing.T) {
	for key, why := range publicRoutes {
		if strings.TrimSpace(why) == "" {
			t.Errorf("public route %q has no stated reason", key)
		}
		if !strings.HasPrefix(key, "GET ") && !strings.HasPrefix(key, "POST ") &&
			!strings.HasPrefix(key, "OPTIONS ") && !strings.HasPrefix(key, "PUT ") &&
			!strings.HasPrefix(key, "DELETE ") {
			t.Errorf("public route %q is not keyed METHOD /pattern", key)
		}
	}
	for key, why := range scopedRoutes {
		if strings.TrimSpace(why) == "" {
			t.Errorf("scoped route %q has no stated reason", key)
		}
	}
}

// Named routes that must never drift into the public list. If someone adds one
// of these to publicRoutes, this fails rather than shipping.
func TestSensitiveRoutesAreNeverPublic(t *testing.T) {
	for _, tc := range []struct{ method, pattern string }{
		{"POST", "/api/reset"},
		{"POST", "/api/keystore/root-seed"},
		{"GET", "/api/keystore/root-seed"},
		{"POST", "/api/mcp/tokens"},
		{"GET", "/api/mcp/tokens"},
		{"POST", "/api/rotation"},
		{"POST", "/api/sign"},
		{"GET", "/api/vault/credentials"},
		{"POST", "/api/recovery/start"},
		{"GET", "/api/contacts"},
		{"GET", "/api/profile"},
		{"PUT", "/api/profile"},
	} {
		if got := classify(tc.method, tc.pattern); got == accessPublic {
			t.Errorf("%s %s is public — it must not be", tc.method, tc.pattern)
		}
	}
}

// The routes a counterparty genuinely needs stay reachable, or the product
// breaks: a stranger must be able to verify us before any relationship exists.
func TestCounterpartyRoutesStayPublic(t *testing.T) {
	for _, tc := range []struct{ method, pattern string }{
		{"GET", "/public/oobi/{aid}"},
		{"GET", "/oobi/{aid}"},
		{"GET", "/{aid}/did.json"},
		{"GET", "/i/{token}"},
		// The counterparty route a stranger uses is now the envelope itself,
		// which is where an introduction arrives with its own proof.
		{"POST", "/didcomm"},
		{"POST", "/api/login/callback"},
		{"GET", "/api/health"},
		{"GET", "/*"},
	} {
		if got := classify(tc.method, tc.pattern); got != accessPublic {
			t.Errorf("%s %s classified %q — a counterparty cannot reach it", tc.method, tc.pattern, got)
		}
	}
}

// End to end through the real router: a remote caller is refused an owner
// route, and the same route works from the machine the agent runs on.
func TestRouterRefusesRemoteCallerOnOwnerRoute(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/profile", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("remote caller on an owner route: got %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not_authorized") {
		t.Errorf("expected a not_authorized body, got %q", w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, local("GET", "/api/profile", ""))
	if w.Code == http.StatusForbidden {
		t.Error("the local owner was refused its own agent")
	}
}

// A forwarded request presents as loopback because the tunnel daemon connects
// locally. It must not be mistaken for the owner.
func TestForwardedRequestIsNotTheOwner(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")
	req := local("GET", "/api/profile", "")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("a forwarded request was treated as local: got %d, want 403", w.Code)
	}
}

func TestPublicRouteReachableFromAnywhere(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/health", ""))
	if w.Code == http.StatusForbidden {
		t.Error("the health probe must not require authorisation")
	}
}

// A CORS preflight carries no credentials and must survive the gate, or every
// browser client breaks.
func TestPreflightIsNotGated(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")
	w := httptest.NewRecorder()
	req := remote("OPTIONS", "/api/profile", "")
	req.Header.Set("Origin", "https://example.org")
	req.Header.Set("Access-Control-Request-Method", "GET")
	r.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Error("CORS preflight was refused by the authorisation gate")
	}
}

// --- the signed path: how a remote owner proves it ---

// The replay cache is process-wide, which is right in production and awkward
// across tests: two tests signing the same request at the same second produce
// the same signature, and the second would look like a replay. Each signed test
// starts from a clean cache.
func resetSeenSignatures(t *testing.T) {
	t.Helper()
	seenSignaturesMu.Lock()
	defer seenSignaturesMu.Unlock()
	seenSignatures = map[string]time.Time{}
}

func sealTestOwner(t *testing.T, s *CoreServer) (seed []byte, aid string) {
	t.Helper()
	resetSeenSignatures(t)
	seed = make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid = "EOWNERTESTAID"
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       aid,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("seal owner authority: %v", err)
	}
	return seed, aid
}

func signed(t *testing.T, method, path, body string, seed []byte, at time.Time) *http.Request {
	t.Helper()
	req := remote(method, path, body)
	stamp := at.UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest(method, path, stamp, []byte(body), seed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	return req
}

// The bootstrap fix: the owner is remote, and still gets in.
func TestSignedRemoteOwnerIsAdmitted(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, signed(t, "GET", "/api/profile", "", seed, time.Now()))
	if w.Code == http.StatusForbidden {
		t.Fatalf("a correctly signed remote owner was refused: %s", w.Body.String())
	}
}

func TestSignatureFromAnotherKeyIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	sealTestOwner(t, s)
	imposter := make([]byte, ed25519.SeedSize)
	for i := range imposter {
		imposter[i] = byte(200 - i)
	}
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, signed(t, "GET", "/api/profile", "", imposter, time.Now()))
	if w.Code != http.StatusForbidden {
		t.Errorf("a signature from a non-owner key was accepted: %d", w.Code)
	}
}

// A signature is bound to one method, path and body, so a captured one cannot
// be pointed at something more dangerous.
func TestSignatureIsBoundToTheRequest(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)

	stamp := time.Now().UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest("GET", "/api/profile", stamp, nil, seed)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for _, tc := range []struct{ name, method, path, body string }{
		{"different path", "GET", "/api/reset", ""},
		{"different method", "POST", "/api/profile", ""},
		{"different body", "GET", "/api/profile", `{"malicious":true}`},
	} {
		req := remote(tc.method, tc.path, tc.body)
		req.Header.Set(headerOwnerSig, sig)
		req.Header.Set(headerOwnerTimestamp, stamp)
		if err := s.verifyOwnerSignature(req); err == nil {
			t.Errorf("%s: a signature for another request was accepted", tc.name)
		}
	}
}

func TestSignedRequestExpires(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	req := signed(t, "GET", "/api/profile", "", seed, time.Now().Add(-10*time.Minute))
	if err := s.verifyOwnerSignature(req); err == nil {
		t.Error("a stale signed request was accepted")
	}
}

// Capturing a valid request off the wire buys one use at most — and it is
// already spent by the owner who sent it.
func TestSignedRequestCannotBeReplayed(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	now := time.Now()

	first := signed(t, "GET", "/api/profile", "", seed, now)
	if err := s.verifyOwnerSignature(first); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	replay := signed(t, "GET", "/api/profile", "", seed, now)
	if err := s.verifyOwnerSignature(replay); err == nil {
		t.Error("a replayed signed request was accepted")
	}
}

// The handler still needs the body the signature was computed over.
func TestSignedRequestBodySurvivesVerification(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)
	body := `{"alias":"Ada"}`
	req := signed(t, "PUT", "/api/profile", body, seed, time.Now())
	if err := s.verifyOwnerSignature(req); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got := make([]byte, len(body))
	if _, err := req.Body.Read(got); err != nil && err.Error() != "EOF" {
		t.Fatalf("read body after verification: %v", err)
	}
	if string(got) != body {
		t.Errorf("handler would see %q, not the signed body %q", got, body)
	}
}

// With nothing sealed — an agent on its owner's own machine — the agent's own
// identity is the authority, so signing works there too with no extra setup.
func TestUnsealedAgentFallsBackToItsOwnIdentity(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 9)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := ds.SaveIdentity(store.IdentityState{
		AID:       "ESELFOWNED",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Skipf("cannot save identity: %v", err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("owner authority: %v", err)
	}
	if authority.AID != "ESELFOWNED" {
		t.Errorf("expected the agent's own identity as authority, got %q", authority.AID)
	}
	if err := s.verifyOwnerSignature(signed(t, "GET", "/api/profile", "", seed, time.Now())); err != nil {
		t.Errorf("self-owned agent rejected its own owner: %v", err)
	}
}

// Public keys arrive in more than one encoding depending on which path minted
// them; all of them must resolve to the same key.
func TestVerkeyDecodesEveryEncodingWeMint(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for name, encoded := range map[string]string{
		"base64url": base64.RawURLEncoding.EncodeToString(pub),
		"base64std": base64.StdEncoding.EncodeToString(pub),
	} {
		got, err := login.DecodeVerkey(encoded)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != string(pub) {
			t.Errorf("%s: decoded to a different key", name)
		}
	}
	if _, err := login.DecodeVerkey("not-a-key"); err == nil {
		t.Error("garbage decoded as a key")
	}
}

// Every route the router actually serves resolves to a class — no request can
// reach a handler without passing a decision.
func TestEveryRegisteredRouteResolvesToAClass(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")
	count := 0
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		count++
		switch classify(method, route) {
		case accessOwner, accessPublic, accessScoped:
			return nil
		default:
			t.Errorf("%s %s resolved to no access class", method, route)
			return nil
		}
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if count < 100 {
		t.Fatalf("only %d routes walked — the router did not build", count)
	}
	t.Logf("%d routes classified", count)
}

// The loopback predicate is not an ownership test on its own — it cannot ever
// be true for an owner who rents the hardware. Handlers must ask s.isOwner,
// which accepts a signed request too. This scans the package rather than the
// behaviour because the defect being prevented is a line of code someone adds
// back out of habit.
func TestNoHandlerUsesLoopbackAsTheOwnerTest(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// The predicates themselves, and the one place entitled to call them.
		if name == "api_auth.go" || name == "mcp_tokens.go" {
			continue
		}
		// The one route where being local is not standing in for being the
		// owner.
		//
		// This rule exists so an owner who is somewhere else can still prove
		// who they are by signing. That needs an owner to exist. A computer
		// with no identity yet has none, so s.isOwner(r) would refuse every
		// caller forever, including the person holding the machine.
		//
		// And what this gate protects is not an authorisation decision. Whether
		// the pairing is allowed is decided by the claim proving control of the
		// identity making it (claim_proves_control.go). This only keeps the
		// code that is meant for the machine's own screen from being handed out
		// over the network.
		//
		// Narrow, and checked rather than trusted: one gate in that file, and
		// anything else there must use s.isOwner(r).
		if name == "offer_this_computer.go" {
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if n := strings.Count(string(src), "isLocalOwnerRequest(r)"); n != 1 {
				t.Errorf("%s gates on being local %d times; it is exempt for exactly one "+
					"route, the one that runs before an owner exists and only to keep an "+
					"on-screen code off the network. Anything else must use s.isOwner(r)", name, n)
			}
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, banned := range []string{"isLocalOwnerRequest(r)", "isLocalhost(r)"} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s calls %s — use s.isOwner(r) so an owner who is not at "+
					"the keyboard can still prove it by signing the request", name, banned)
			}
		}
	}
}

// A publicRoutes entry only opens a route if its key is the exact pattern chi
// matches, because classify does a string lookup and otherwise falls through to
// owner-only. So an entry with the wrong path is worse than no entry: in review
// it reads as the route having been deliberately opened, while the route
// answers 403 to the party it exists for, logs nothing, and appears to work
// only from loopback — where the caller is treated as the owner and so never
// finds out.
//
// These are the routes whose whole purpose is to be reachable by somebody who
// is not the owner. Each is spelled here as its full mounted path.
func TestRoutesForNonOwnersAreOpenAtTheirRealPaths(t *testing.T) {
	for _, tc := range []struct{ method, pattern, who string }{
		{"POST", "/api/assets/enrol", "a machine enrolling with the key it generated"},
	} {
		if got := classify(tc.method, tc.pattern); got != accessPublic {
			t.Errorf("%s %s classified %q, so %s is refused before the handler runs",
				tc.method, tc.pattern, got, tc.who)
		}
	}
}

// And the mistake itself: the path that is NOT mounted must not be classified
// public, or the entry has simply been duplicated rather than corrected.
func TestTheUnmountedEnrolPathIsNotOpen(t *testing.T) {
	if got := classify("POST", "/api/enrol"); got == accessPublic {
		t.Error("/api/enrol is classified public, but nothing is mounted there — " +
			"the stale entry was left behind")
	}
}
