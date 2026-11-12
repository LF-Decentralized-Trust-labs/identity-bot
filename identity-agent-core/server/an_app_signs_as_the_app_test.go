package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/authprovider"
	"identity-agent-core/limits"
)

// An app's back end reaches the core as the app, signed by its App Body key
// (ADR-072 section 4), and by no other way. These are the cases the published
// vectors cannot hold, because they are the core's own: which routes an app may
// use, and what refuses its key everywhere else.

// The add-on the route tests include: one route an app may use, with its
// limit on "to" read from the path, and one it may not.
func anAddOnWithAnAppRoute() Addon {
	ok := func(w http.ResponseWriter, r *http.Request) {
		app, isApp := TheAppThatAsked(r)
		fmt.Fprintf(w, "served app %q %v", app.Asset, isApp)
	}
	return Addon{
		ID: "app-reads", Name: "app-reads",
		Routes: func(_ *CoreServer, r chi.Router) {
			r.Get("/app-reads/{id}", ok)
			r.Get("/app-reads-none-for-apps/{id}", ok)
		},
		AppRoutes: map[string]AppRoute{
			"GET /api/app-reads/{id}": {Capability: "agent.message.read", Arguments: map[string]string{"to": "id"}},
		},
	}
}

// The routes an app's key is admitted on, exactly: the core's one, and the one
// the add-on above lists. A route added to either table, or to an add-on's
// AppRoutes, changes this set and is read here before it ships.
var theAppRoutes = []string{
	"GET /api/app-reads/{id}",
	"GET /api/conversations/{id}/head",
	"POST /api/mcp/agents/{id}/conversations",
	"POST /api/mcp/conversations/{cid}/close",
	"POST /api/mcp/conversations/{cid}/limit",
	"POST /api/mcp/conversations/{cid}/reopen",
}

// An app's key is refused on every route that is not one an app may use, by
// the gate and for that reason, never by a handler's own refusal: every
// controller route and every owner-only one, however the request is signed.
var pathParam = regexp.MustCompile(`\{[^}/]*\}`)

func TestAnAppsKeyIsRefusedOnEveryRouteButItsOwn(t *testing.T) {
	onlyAddons(t, anAddOnWithAnAppRoute())
	w := newAnAppWorld(t)
	var routes []string
	if err := chi.Walk(w.h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The set of app routes is pinned: the table says it, and so does this.
	var admitted []string
	for route := range appRoutesOf(registeredAddons()) {
		admitted = append(admitted, route)
	}
	sort.Strings(admitted)
	if !reflect.DeepEqual(admitted, theAppRoutes) {
		t.Fatalf("the routes an app may use are %v, and this test pins %v: a new one is an app route to be reviewed, then added here", admitted, theAppRoutes)
	}
	checked, ownerOnly := 0, 0
	for _, route := range routes {
		method, pattern, _ := strings.Cut(route, " ")
		if _, mayUse := appRoutesOf(registeredAddons())[route]; mayUse || classify(method, pattern) == accessPublic {
			continue
		}
		path := pathParam.ReplaceAllString(pattern, "x")
		if strings.ContainsAny(path, "{}*") {
			t.Errorf("%s has a path this test cannot fill in, so an app's key was not tried on it", route)
			continue
		}
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, w.signedAsTheApp(t, method, path, ""))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s was answered %d for an app's key", route, rec.Code)
		}
		// The gate's own words: a handler that refuses an app by itself, or a
		// route that is answered some other way, does not pass for the gate.
		if want := "is not one of them"; !strings.Contains(rec.Body.String(), want) || !strings.Contains(rec.Body.String(), strings.TrimSuffix(route, "/")) {
			t.Errorf("%s was not refused by the gate for an app's key (want %q naming the route): %s", route, want, rec.Body)
		}
		if _, owner := isOwnerOnly(method, pattern); owner {
			ownerOnly++
			if !strings.Contains(rec.Body.String(), reasonOwnerOnly) {
				t.Errorf("%s is owner-only and the app was not told so: %s", route, rec.Body)
			}
		}
		checked++
	}
	if checked < 20 || ownerOnly < 5 {
		t.Fatalf("only %d routes were tried, %d of them owner-only", checked, ownerOnly)
	}
	if *w.served != 0 {
		t.Fatalf("an app's key reached %d handlers", *w.served)
	}
}

// An add-on's route that lists AppRoutes admits an app on it, with the
// capability its grant must hold, and is held to the app's rate; an add-on's
// route that does not list it refuses the app.
func TestAnAddOnsAppRouteIsAnAppsAndNoOthers(t *testing.T) {
	onlyAddons(t, anAddOnWithAnAppRoute())
	w := newAnAppWorld(t)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, w.signedAsTheApp(t, http.MethodGet, path, ""))
		return rec
	}
	if rec := get("/api/app-reads/agent-1"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `served app "chat" true`) {
		t.Fatalf("an app was not admitted on the route its add-on lists: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/api/app-reads-none-for-apps/agent-1"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "is not one of them") {
		t.Fatalf("an app was admitted on a route its add-on does not list: %d %s", rec.Code, rec.Body)
	}
	// The capability is the add-on's entry's: without it the route is refused.
	_ = w.cw.s.DataStore.DeleteCredential("Egrant")
	w.enrolApp(t, w.cw.s, []string{"agent.message.send"})
	if rec := get("/api/app-reads/agent-1"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent.message.read") {
		t.Fatalf("an app without the capability was answered %d %s", rec.Code, rec.Body)
	}
}

// Past its rate, an app is turned away on an add-on's route as on the core's.
func TestAnAppPastItsRateIsTurnedAwayOnAnAddOnsRoute(t *testing.T) {
	onlyAddons(t, anAddOnWithAnAppRoute())
	w := newAnAppWorld(t)
	l := limits.Defaults()
	l.RateBurst, l.RatePerSecond = 2, 0.001
	w.cw.s.SetLimits(l)
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, w.signedAsTheApp(t, http.MethodGet, "/api/app-reads/agent-1", ""))
		return rec
	}
	for i := 0; i < 2; i++ {
		if rec := get(); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the rate: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := get(); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("an app past its rate on an add-on's route got %d %s", rec.Code, rec.Body)
	}
}

// A grant that limits an app to some AI agents is not a key to the others: the
// limit on "to" names an AI agent by the identifier its entries are addressed
// to (as a person's statement does), is held to the AI agent in the route, and
// a limit the route cannot be checked against refuses the request.
func TestAnAppLimitedToOneAIAgentCannotWriteToAnother(t *testing.T) {
	w := newAnAppWorld(t)
	limit := func(c map[string]map[string][]string) {
		_ = w.cw.s.DataStore.DeleteCredential("Egrant")
		w.enrolAppLimited(t, w.cw.s, []string{"agent.message.send", "agent.message.read"}, c)
	}
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)
	// The route names the AI agent by its asset id, the body and the statement by its identifier.
	to := func(agent, aid string) *httptest.ResponseRecorder {
		return w.say(t, aSpokenRequest{who: "Eann", key: key, words: "hello", to: aid, path: "/api/mcp/agents/" + agent + "/conversations"})
	}
	limit(map[string]map[string][]string{"agent.message.send": {"to": {"Eagent2"}}})
	rec := to("agent-1", "Eagent1")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "limits agent.message.send") && !strings.Contains(rec.Body.String(), "outside_the_grants_limit") && !strings.Contains(rec.Body.String(), "not one") || *w.served != 0 {
		t.Fatalf("an app limited to agent-2 spoke to agent-1: %d %s (%d served)", rec.Code, rec.Body, *w.served)
	}
	if rec := to("agent-2", "Eagent2"); rec.Code != http.StatusOK {
		t.Fatalf("an app limited to agent-2 was refused agent-2: %d %s", rec.Code, rec.Body)
	}
	// A limit that names the asset id is not a limit to that AI agent.
	limit(map[string]map[string][]string{"agent.message.send": {"to": {"agent-2"}}})
	if rec := to("agent-2", "Eagent2"); rec.Code == http.StatusOK {
		t.Fatalf("a limit naming agent-2's asset id admitted agent-2: %d %s", rec.Code, rec.Body)
	}
	limit(map[string]map[string][]string{"agent.message.send": {"to": {"Eagent2"}}})
	// Whichever way the same AI agent is written, it is not the one named.
	if rec := to("agent-2%2F", "Eagent2"); rec.Code == http.StatusOK {
		t.Fatalf("a path that is not agent-2 was read as agent-2: %d %s", rec.Code, rec.Body)
	}
	// A route that names no AI agent cannot be checked against a limit on "to".
	if rec := to("agent-none", "Eagent2"); rec.Code == http.StatusOK {
		t.Fatalf("a route naming no AI agent was admitted under a limit on it: %d %s", rec.Code, rec.Body)
	}
	// A limit on another capability is not this one's.
	limit(map[string]map[string][]string{"agent.message.read": {"to": {"Eagent2"}}})
	if rec := to("agent-1", "Eagent1"); rec.Code != http.StatusOK {
		t.Fatalf("a limit on reading limited sending: %d %s", rec.Code, rec.Body)
	}
	// A limit on an argument the route does not give cannot be checked, so it is not read as none.
	limit(map[string]map[string][]string{"agent.message.send": {"to": {"Eagent1"}, "topic": {"billing"}}})
	rec = to("agent-1", "Eagent1")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cannot be checked") {
		t.Fatalf("a limit the gate cannot enforce was ignored: %d %s", rec.Code, rec.Body)
	}
}

// A limit that is there but is not an object is not read as no limit: an app
// whose grant says it is limited, in a form that cannot be read, may use nothing.
func TestAnAppWhoseLimitsCannotBeReadIsNotUnlimited(t *testing.T) {
	for name, limits := range map[string]any{
		"resource_constraints a string":   "agent-1 only",
		"resource_constraints a list":     []string{"agent-1"},
		"resource_constraints null":       json.RawMessage("null"),
		"the capability's entry a string": map[string]any{"agent.message.send": "agent-1"},
		"the capability's entry a list":   map[string]any{"agent.message.send": []string{"agent-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newAnAppWorld(t)
			_ = w.cw.s.DataStore.DeleteCredential("Egrant")
			w.enrolAppWithConstraints(t, w.cw.s, []string{"agent.message.send"}, limits)
			rec := httptest.NewRecorder()
			w.h.ServeHTTP(rec, w.signedAsTheApp(t, http.MethodPost, talkPath, `{"to":"Eagent1","body":"hi","nonce":"n"}`))
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cannot be read") || *w.served != 0 {
				t.Fatalf("an app with an unreadable limit got %d %s (%d served)", rec.Code, rec.Body, *w.served)
			}
		})
	}
}

// A copy of a request that was already used is refused before the rate is
// charged, so replaying one cannot use up the app's rate.
func TestAReplayedRequestDoesNotSpendTheAppsRate(t *testing.T) {
	onlyAddons(t, anAddOnWithAnAppRoute())
	w := newAnAppWorld(t)
	l := limits.Defaults()
	l.RateBurst, l.RatePerSecond = 2, 0.001
	w.cw.s.SetLimits(l)
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, r)
		return rec
	}
	first := w.signedAsTheApp(t, http.MethodGet, "/api/app-reads/agent-1", "")
	if rec := serve(first); rec.Code != http.StatusOK {
		t.Fatalf("the first request: %d %s", rec.Code, rec.Body)
	}
	for i := 0; i < 5; i++ {
		if rec := serve(w.copyOf(first)); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "already used") {
			t.Fatalf("replay %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := serve(w.signedAsTheApp(t, http.MethodGet, "/api/app-reads/agent-1", "")); rec.Code != http.StatusOK {
		t.Fatalf("a fresh request after replays was refused, so the replays used the rate: %d %s", rec.Code, rec.Body)
	}
}

// What an App Body credential, an App Grant and the request must each be for an
// app's key to be admitted at all.
func TestAnAppIsAdmittedOnlyOnItsCredentials(t *testing.T) {
	refused := func(t *testing.T, w *anAppWorld, r *http.Request, want string) {
		t.Helper()
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK || *w.served != 0 || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("answered %d %s (%d served), want a refusal saying %q", rec.Code, rec.Body, *w.served, want)
		}
	}
	say := func(w *anAppWorld) *http.Request {
		return w.signedAsTheApp(t, http.MethodPost, talkPath, `{"to":"Eagent1","body":"hi","nonce":"n"}`)
	}
	t.Run("a grant that does not hold the capability", func(t *testing.T) {
		w := newAnAppWorld(t)
		_ = w.cw.s.DataStore.DeleteCredential("Egrant")
		w.enrolApp(t, w.cw.s, []string{"agent.message.read"})
		refused(t, w, say(w), "agent.message.send")
	})
	t.Run("a grant that is revoked", func(t *testing.T) {
		w := newAnAppWorld(t)
		if err := w.cw.s.DataStore.UpdateCredentialStatus("Egrant", "revoked"); err != nil {
			t.Fatal(err)
		}
		refused(t, w, say(w), "no App Grant in force")
	})
	t.Run("a body that is revoked is not an app's key", func(t *testing.T) {
		w := newAnAppWorld(t)
		if err := w.cw.s.DataStore.UpdateCredentialStatus("Ebody", "revoked"); err != nil {
			t.Fatal(err)
		}
		refused(t, w, say(w), "not_authorized")
	})
	t.Run("a signature used twice", func(t *testing.T) {
		w := newAnAppWorld(t)
		r := say(w)
		w.h.ServeHTTP(httptest.NewRecorder(), r) // refused for want of a person's statement, and spent
		refused(t, w, w.copyOf(r), "already used")
	})
	t.Run("a request that is also a controller's", func(t *testing.T) {
		w := newAnAppWorld(t)
		r := say(w)
		c := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodPost, talkPath, "{}", w.cw.ctlSeed, authprovider.Level(""), time.Now())
		for _, h := range []string{headerControllerAID, headerControllerSig, headerControllerTimestamp, headerControllerFor} {
			r.Header.Set(h, c.Header.Get(h))
		}
		refused(t, w, r, "signed by one key")
	})
	t.Run("a request that also carries a token", func(t *testing.T) {
		w := newAnAppWorld(t)
		r := say(w)
		r.Header.Set("Authorization", "Bearer some-token")
		refused(t, w, r, "signed by one key")
	})
	t.Run("a body that is not an app's is left to whoever keeps it", func(t *testing.T) {
		w := newAnAppWorld(t)
		body, _ := w.cw.s.appBodyOf("BNotAnApp")
		if body != nil {
			t.Fatal("a key no App Body names was read as an app's")
		}
	})
}
