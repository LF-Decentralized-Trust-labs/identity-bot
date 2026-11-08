package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
)

// No browser reaches an Identity Agent's core, for anything (ADR-006). It is
// reached from the installed app on a device that holds the key, and a
// person's own apps reach it as enrolled apps from their own servers. A
// browser reaches those apps, never past them to here.
//
// A browser login to the core was built once, before that was decided, and
// work kept extending it because the code was still here to read. These
// tests are what stops it coming back: each fails if any route signs a
// browser in, accepts a browser's token as the owner, or answers a browser's
// origin.

// browserOrigin is a page an app this agent hosts is served from, the origin a
// browser would most plausibly be let in for.
const browserOrigin = "https://app.example"

// aCoreHostingAnApp is a core that hosts an app served from browserOrigin, so
// nothing passes these tests merely because no browser origin is known.
func aCoreHostingAnApp(t *testing.T) (*CoreServer, chi.Router) {
	t.Helper()
	s := notifyTestServer(t)
	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{ID: "app", DisplayName: "app", AssetType: "app", Origin: browserOrigin}); err != nil {
		t.Fatal(err)
	}
	return s, s.buildRouter()
}

// eachRoute calls fn with every route the router serves and a path that
// reaches it, skipping the web UI's wildcard fallthrough.
func eachRoute(t *testing.T, router chi.Router, fn func(method, route, path string)) int {
	t.Helper()
	param := regexp.MustCompile(`\{[^}]*\}`)
	n := 0
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.Contains(route, "*") {
			return nil
		}
		n++
		fn(method, route, param.ReplaceAllString(route, "x"))
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if n == 0 {
		t.Fatal("the router serves no routes, so this proves nothing")
	}
	return n
}

func serveWithin(router http.Handler, r *http.Request) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r.WithContext(ctx))
	return w
}

// There is no way to sign a browser in to the core: no route under
// /api/session, and none named for a browser login.
func TestNoRouteSignsABrowserIn(t *testing.T) {
	_, router := aCoreHostingAnApp(t)
	eachRoute(t, router, func(method, route, _ string) {
		lower := strings.ToLower(route)
		if strings.HasPrefix(lower, "/api/session") || strings.Contains(lower, "browser-login") ||
			strings.Contains(lower, "browser-session") {
			t.Errorf("%s %s signs a browser in to the core; no browser reaches an Identity Agent (ADR-006)",
				method, route)
		}
	})
}

// A bearer token is no owner's credential. A browser holding one, from this
// agent's own app's origin, is refused at the gate on every route that is the
// owner's. This catches a gate that admits any token; a gate that admits only
// tokens it issued itself is caught by TestNothingHereKeepsABrowserSession.
func TestABrowsersTokenIsNotTheOwner(t *testing.T) {
	_, router := aCoreHostingAnApp(t)
	checked := 0
	eachRoute(t, router, func(method, route, path string) {
		if classify(method, route) != accessOwner {
			return
		}
		checked++
		r := remote(method, path, "")
		r.Header.Set("Authorization", "Bearer a-token-a-browser-holds")
		r.Header.Set("Origin", browserOrigin)
		if w := serveWithin(router, r); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s %s answered %d to a browser's token; only the owner's key reaches it",
				method, route, w.Code)
		}
	})
	if checked == 0 {
		t.Fatal("no owner routes found, so this proves nothing")
	}
}

// answeringABrowser are the routes that answer a browser's origin, each with
// why. It is exact: a route not on it must never answer, and one on it that
// stops answering must be taken off it.
var answeringABrowser = map[string]string{
	// Signing in to a website is not reaching this core. The sign-in button a
	// website embeds (packages/login-web, ADR-021) asks the Identity Agent that
	// holds the website as an asset for a challenge signed with the asset's
	// key, and collects who signed in. The browser carries no credential and
	// gains nothing over any identity; the person approves on their own
	// Identity Agent, on their own device.
	"OPTIONS /api/login/session/{asset_id}":         "the sign-in button a website embeds starts a sign-in",
	"POST /api/login/session/{asset_id}":            "the sign-in button a website embeds starts a sign-in",
	"OPTIONS /api/login/session/{asset_id}/{token}": "the sign-in button a website embeds waits for the answer",
	"GET /api/login/session/{asset_id}/{token}":     "the sign-in button a website embeds waits for the answer",
	// A website with no back end of its own checks the assertion it was handed
	// in the page. The key log is checked here, once, instead of in a second
	// implementation in the page (ADR-021). The route takes no credential and
	// answers only what the log it is sent establishes.
	"OPTIONS /public/login/key": "a page with only the login SDK checks the assertion it was handed",
	"POST /public/login/key":    "a page with only the login SDK checks the assertion it was handed",
}

// No route lets a browser read its answer: neither a preflight nor the request
// itself carries Access-Control-Allow-Origin, for a stranger's origin or for
// the origin of an app this agent hosts.
func TestTheCoreAnswersNoBrowserOrigin(t *testing.T) {
	_, router := aCoreHostingAnApp(t)
	answering := map[string]bool{}
	eachRoute(t, router, func(method, route, path string) {
		key := method + " " + route
		for _, origin := range []string{browserOrigin, "https://stranger.example"} {
			pre := remote(http.MethodOptions, path, "")
			pre.Header.Set("Origin", origin)
			pre.Header.Set("Access-Control-Request-Method", method)
			asked := []*http.Request{pre}
			// An owner's route is refused at the gate, before its handler, so
			// the preflight speaks for it. Any other route's handler runs, and
			// could set the header itself.
			if classify(method, route) != accessOwner {
				real := remote(method, path, "")
				real.Header.Set("Origin", origin)
				asked = append(asked, real)
			}
			for _, r := range asked {
				if serveWithin(router, r).Header().Get("Access-Control-Allow-Origin") != "" {
					answering[key] = true
				}
			}
		}
	})
	for key := range answering {
		if _, known := answeringABrowser[key]; !known {
			t.Errorf("%s lets a browser read its answer; no browser reaches an Identity Agent (ADR-006). "+
				"A browser reaches the person's app, and the app asks this core from its own server", key)
		}
	}
	for key := range answeringABrowser {
		if !answering[key] {
			t.Errorf("%s no longer answers a browser: take it off answeringABrowser", key)
		}
	}
}

// browserSessionWords names a browser session, a browser login or a session
// token standing in for the owner, in any spelling.
var browserSessionWords = regexp.MustCompile(`(?i)browser.?(session|login)|session.?forbidden|requires.?the.?key.?itself`)

// stillNamingABrowserSession are the files outside the tests allowed to name
// one, each with why. The list may only shrink.
var stillNamingABrowserSession = map[string]string{
	// A person's session at an app is named by the hash of its token
	// (login.BrowserSessionBinding, ADR-066). It reaches the talk routes only,
	// never as the owner or a controller, and is being reworked so that the app
	// asks from its own server.
	"an_app_session_speaks_for_its_person.go": "an app session is named by the hash of its token (ADR-066)",
}

// Nothing in the core keeps a browser session or a browser login, whatever
// the route that would reach it is called. A login brought back would admit
// tokens it issued itself, which no request a test makes up can hold, so this
// reads the code instead: an identifier or comment naming one fails it.
func TestNothingHereKeepsABrowserSession(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	named := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !browserSessionWords.Match(src) {
			continue
		}
		named[f] = true
		if _, known := stillNamingABrowserSession[f]; !known {
			t.Errorf("%s names a browser session or login (%q); no browser reaches an Identity Agent (ADR-006)",
				f, browserSessionWords.Find(src))
		}
	}
	for f := range stillNamingABrowserSession {
		if !named[f] {
			t.Errorf("%s no longer names a browser session: take it off stillNamingABrowserSession", f)
		}
	}
}
