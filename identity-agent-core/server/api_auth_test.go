package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
)

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
	for key, why := range everyPublicRoute() {
		if strings.TrimSpace(why) == "" {
			t.Errorf("public route %q has no stated reason", key)
		}
		if !strings.HasPrefix(key, "GET ") && !strings.HasPrefix(key, "POST ") &&
			!strings.HasPrefix(key, "OPTIONS ") && !strings.HasPrefix(key, "PUT ") &&
			!strings.HasPrefix(key, "DELETE ") {
			t.Errorf("public route %q is not keyed METHOD /pattern", key)
		}
	}
	for key, why := range everyScopedRoute() {
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
		// A relying party in another language checks a key log here.
		{"POST", "/public/login/key"},
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
	sig, err := SignOwnerRequest("", "GET", "/api/profile", stamp, nil, seed)
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
	// A founded identity, with its inception in its log: an identity row with no
	// key event is not one whose key state can be told (where post-quantum keys
	// are read, it is refused).
	s := appHeldCore(t)
	k := appSeeds(2)
	seed := k[0]
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1",
		"n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	if code != http.StatusOK {
		t.Fatalf("prepare founding: %d %v", code, out)
	}
	icp := preparedBytes(t, out)
	if code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}}); code != http.StatusCreated {
		t.Fatalf("commit founding: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("owner authority: %v", err)
	}
	if authority.AID != own.AID {
		t.Errorf("expected the agent's own identity as authority, got %q", authority.AID)
	}
	if err := s.verifyOwnerSignature(signedFor(t, own.AID, "GET", "/api/profile", "", seed, time.Now())); err != nil {
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
//
// Add-ons serve handlers too, through the handle package addon gives them, so
// that package is scanned as well: none of the predicates is ever put on it.
func TestNoHandlerUsesLoopbackAsTheOwnerTest(t *testing.T) {
	for _, dir := range []string{"../addon", "../addon/addontest"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			for _, banned := range []string{"isLocalOwnerRequest(", "isLocalConnection(", "isLocalhost(",
				"IsLocalOwnerRequest(", "IsLocalConnection(", "IsLocalhost("} {
				if strings.Contains(string(src), banned) {
					t.Errorf("%s/%s calls %s — use IsOwner so an owner who is not at "+
						"the keyboard can still prove it by signing the request", dir, name, banned)
				}
			}
		}
	}
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
		// caller_resolver.go joined this list on 2026-08-31, when the default
		// resolver moved into the file it is named for. Its use is the legitimate
		// one: deciding whether a caller is local is what a resolver is FOR, and
		// the result is recorded as a fact about the connection rather than used
		// as an ownership test.
		if name == "api_auth.go" || name == "caller_resolver.go" || name == "the_owner_at_this_computer.go" {
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
			// Two routes, both of which run before an owner exists and both of
			// which only keep an on-screen code — and who took it — off the
			// network: issuing the code, and reading back what happened to it.
			// A third would not be covered by that reasoning, so it fails here
			// and has to be argued for rather than assumed.
			if n := strings.Count(string(src), "isLocalOwnerRequest(r)"); n != 2 {
				t.Errorf("%s gates on being local %d times, expected 2 (issuing the code, "+
					"and reading back what happened to it). Both run before an owner exists, "+
					"which is the only reason the exemption holds. Anything else in this "+
					"file must use s.isOwner(r)", name, n)
			}
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, banned := range []string{"isLocalOwnerRequest(r)", "isLocalConnection(r)", "isLocalhost(r)"} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s calls %s — use s.isOwner(r) so an owner who is not at "+
					"the keyboard can still prove it by signing the request", name, banned)
			}
		}
	}
}

// An entry in publicRoutes or scopedRoutes only opens a route if its key is the
// EXACT pattern chi matches. classify does a string lookup and otherwise falls
// through to owner-only, so an entry with the wrong path is worse than no entry:
// in review it reads as the route having been deliberately opened, while the
// route answers 403 to the party it exists for, logs nothing, and appears to
// work only from loopback — where the caller is treated as the owner and so
// never finds out.
//
// This is checked against the ROUTER rather than against classify, because
// classify agrees with whatever is written in the map. A test that asks
// classify what it thinks confirms the typo instead of catching it — which is
// how POST /api/enrol shipped owner-gated while two tests covering that exact
// entry passed. Walking the router is the only version of this test that can
// fail when the map is wrong.
func TestEveryOpenRouteIsMountedWhereItSaysItIs(t *testing.T) {
	s := newAuthTestServer(t)
	// mountAssetRoutes returns early on a nil handler, so a bare server does not
	// mount the very routes this test exists to check. The engine is nil because
	// nothing is called — the router is walked, not served.
	ah, err := asset.NewHandler(s.DataDir, nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	s.assetHandler = ah
	// The witness routes are mounted only on an agent with a witness service;
	// an empty one mounts them, and nothing here calls it.
	s.WitnessService = &witness.Service{}

	mounted := map[string]bool{}
	if err := chi.Walk(s.buildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			mounted[method+" "+route] = true
			return nil
		}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(mounted) < 100 {
		t.Fatalf("only %d routes walked — the router did not build", len(mounted))
	}

	for _, m := range []struct {
		name  string
		table map[string]string
	}{
		{"publicRoutes", everyPublicRoute()},
		{"scopedRoutes", everyScopedRoute()},
	} {
		for key, why := range m.table {
			if !mounted[key] {
				t.Errorf("%s names %q, which nothing mounts — so it opens nothing "+
					"and %q is refused 403 before its handler runs",
					m.name, key, why)
			}
		}
	}
}

// countingBody serves total bytes and records how many were actually taken.
type countingBody struct {
	total, served int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	if c.served >= c.total {
		return 0, io.EOF
	}
	n := int64(len(p))
	if rest := c.total - c.served; n > rest {
		n = rest
	}
	c.served += n
	return int(n), nil
}

func (c *countingBody) Close() error { return nil }

// A caller with a fresh timestamp and a garbage signature must not be able to
// make the agent buffer its whole body: the read happens before the signature
// is known good, so it stops at the bound and the request is refused.
func TestAnOversizedBodyWithABadSignatureIsNotFullyRead(t *testing.T) {
	s := newAuthTestServer(t)
	sealTestOwner(t, s)

	body := &countingBody{total: 4 * maxSignedBodyBytes}
	req := remote("POST", "/api/profile", "")
	req.Body = body
	req.Header.Set(headerOwnerSig, "0Bgarbage")
	req.Header.Set(headerOwnerTimestamp, time.Now().UTC().Format(time.RFC3339))

	err := s.verifyOwnerSignature(req)
	var tooLarge requestTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("an oversized body was refused with %v, want the size refusal", err)
	}
	if body.served == 0 {
		t.Fatal("none of the body was read, so this proves nothing about where reading stops")
	}
	// Whatever was read must not be handed on as if it were the whole body.
	if left, rerr := io.ReadAll(req.Body); rerr == nil || len(left) != 0 {
		t.Fatalf("a refused request's body still yields %d bytes (err %v)", len(left), rerr)
	}
	if body.served > maxSignedBodyBytes+1 {
		t.Fatalf("the agent read %d bytes of a body it should have stopped at %d",
			body.served, maxSignedBodyBytes+1)
	}
}

// A body is read up to the bound of its ROUTE. The archive routes and the photo
// routes carry far more than the default, and a remote owner can only sign
// them; the same size on any other route is refused, as a size and not as a
// bad signature.
func TestASignedBodyMayBeAsLargeAsItsRouteAllows(t *testing.T) {
	big := func(fill string, n int) string {
		return `{"` + fill + `":"` + strings.Repeat("A", n) + `"}`
	}
	for _, tc := range []struct {
		name, method, path, body string
		accepted                 bool
	}{
		{"recovery start, 20 MiB archive", "POST", "/api/recovery/start", big("archive_b64", 20<<20), true},
		{"recovery verify, 20 MiB archive", "POST", "/api/recovery/verify", big("archive_b64", 20<<20), true},
		{"profile PUT, 15 MiB", "PUT", "/api/profile", big("photo_pad", 15<<20), true},
		{"avatar stylize, 15 MiB", "POST", "/api/profile/avatar/stylize", big("image", 15<<20), true},
		{"profile PUT, over the photo bound", "PUT", "/api/profile", big("photo_pad", int(maxPhotoBody)), false},
		{"tunnel settings, 20 MiB (default bound)", "PUT", "/api/settings/tunnel", big("pad", 20<<20), false},
		{"tunnel settings, 15 MiB (default bound)", "PUT", "/api/settings/tunnel", big("pad", 15<<20), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAuthTestServer(t)
			seed, _ := sealTestOwner(t, s)
			// A probe stands where the handler would, so "the gate let it
			// through" is observed rather than inferred from the absence of a
			// refusal: a handler that crashes after the gate looks the same as
			// one that served.
			reached, admitted := false, false
			probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached, admitted = true, theGateAdmittedTheOwner(r)
			})
			router := s.buildRouter("")
			w := httptest.NewRecorder()
			req := signed(t, tc.method, tc.path, tc.body, seed, time.Now())
			// The larger bounds are for a request that declares its digest, so
			// that its signature is checked before any of the body is read.
			req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must([]byte(tc.body)))
			s.authorize(router)(probe).ServeHTTP(w, req)
			if tc.accepted {
				if !reached || !admitted {
					t.Fatalf("the gate did not admit a validly signed request (reached %v, admitted as the owner %v): %d %s",
						reached, admitted, w.Code, w.Body.String())
				}
				return
			}
			if reached {
				t.Fatal("a body over its route's bound reached the handler")
			}
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("got %d, want 413: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "too large for this route") {
				t.Fatalf("the refusal does not say the request is too large: %s", w.Body.String())
			}
		})
	}
}

// Every route that raises its bound is a route the router actually serves; a
// misspelt key would silently leave it at the default.
func TestEverySignedBodyBoundNamesAMountedRoute(t *testing.T) {
	s := newAuthTestServer(t)
	router := s.buildRouter("")
	for key := range signedBodyBounds {
		method, path, _ := strings.Cut(key, " ")
		req := httptest.NewRequest(method, path, nil)
		if matchedRoutePattern(router, req) != path {
			t.Errorf("%s is not a mounted route pattern", key)
		}
	}
}

// A body that declares it is too big is refused without reading any of it, and
// with the same 413 as one found too big by reading.
func TestADeclaredOversizeBodyIsRefusedUnread(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)

	body := &countingBody{total: 4 * maxSignedBodyBytes}
	req := signed(t, "PUT", "/api/settings/tunnel", "{}", seed, time.Now())
	req.Body = body
	req.ContentLength = body.total

	w := httptest.NewRecorder()
	s.buildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge ||
		!strings.Contains(w.Body.String(), "too large for this route") {
		t.Fatalf("got %d, want the 413: %s", w.Code, w.Body.String())
	}
	if body.served != 0 {
		t.Fatalf("the agent read %d bytes of a body that declared itself too big", body.served)
	}
}

// An owner who claims to be a different identity gets the refusal it always
// did, not a size error, however large the body.
func TestAMismatchedOwnerClaimIsNotAnSizeError(t *testing.T) {
	s := newAuthTestServer(t)
	seed, _ := sealTestOwner(t, s)

	req := signed(t, "PUT", "/api/settings/tunnel",
		`{"pad":"`+strings.Repeat("A", int(maxSignedBodyBytes)+1)+`"}`, seed, time.Now())
	req.Header.Set(headerOwnerAID, "ESOMEONEELSE")

	w := httptest.NewRecorder()
	s.buildRouter("").ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want the 403 a mismatched owner always got: %s", w.Code, w.Body.String())
	}
}

// A machine asking for a route it may not use is refused before any of its body
// is read; the same machine on a route it may use still reaches the size bound.
func TestAControllerIsCheckedAgainstTheRouteBeforeItsBodyIsRead(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	if _, closed := isOwnerOnly("POST", "/api/rotation"); !closed {
		t.Fatal("POST /api/rotation is no longer owner-only, so this proves nothing")
	}

	serve := func(method, path string) (int, *countingBody) {
		req := asThatMachine(t, aid, method, path, "", seed, "", time.Time{})
		body := &countingBody{total: 4 * maxSignedBodyBytes}
		req.Body = body
		w := httptest.NewRecorder()
		s.buildRouter("").ServeHTTP(w, req)
		return w.Code, body
	}

	if code, body := serve("POST", "/api/rotation"); code != http.StatusForbidden || body.served != 0 {
		t.Fatalf("an owner-only route: got %d after reading %d bytes, want 403 and none read", code, body.served)
	}
	if code, body := serve("GET", "/api/profile"); code != http.StatusRequestEntityTooLarge || body.served == 0 {
		t.Fatalf("a permitted route: got %d after reading %d bytes, want the size refusal", code, body.served)
	}
}
