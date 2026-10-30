package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"identity-agent-core/authprovider"
	"identity-agent-core/didcomm"
	"identity-agent-core/keriengine"
	"identity-agent-core/permission"

	"github.com/go-chi/chi/v5"
)

// panics reports whether f panicked, and with what.
func panics(f func()) (msg string, did bool) {
	defer func() {
		if r := recover(); r != nil {
			msg, did = r.(string), true
		}
	}()
	f()
	return "", false
}

// unsealedAfter puts the add-on list's seal back as it was when t ends.
func unsealedAfter(t *testing.T) {
	t.Helper()
	addonsMu.Lock()
	was := addonsSealed
	addonsMu.Unlock()
	t.Cleanup(func() {
		addonsMu.Lock()
		addonsSealed = was
		addonsMu.Unlock()
	})
}

// The add-ons included are settled when a server is made: none joins after,
// none without an ID, and no two share one.
func TestNoAddOnJoinsOnceAServerIsMade(t *testing.T) {
	onlyAddons(t)
	unsealedAfter(t)
	addonsMu.Lock()
	addonsSealed = false
	addonsMu.Unlock()

	if msg, did := panics(func() { RegisterAddon(Addon{Name: "nameless"}) }); !did || !strings.Contains(msg, "needs an ID") {
		t.Fatalf("an add-on with no ID was registered (%q)", msg)
	}
	RegisterAddon(Addon{ID: "first"})
	if msg, did := panics(func() { RegisterAddon(Addon{ID: "first"}) }); !did || !strings.Contains(msg, "both first") {
		t.Fatalf("two add-ons with one ID were registered (%q)", msg)
	}

	if _, err := New(Config{DataDir: t.TempDir(), Port: 0}); err != nil {
		t.Logf("making the server: %v (the list is settled before anything that can fail)", err)
	}
	if msg, did := panics(func() { RegisterAddon(Addon{ID: "late"}) }); !did || !strings.Contains(msg, "after a server was made") {
		t.Fatalf("an add-on joined after a server was made (%q)", msg)
	}
	if got := addonIDs(); !reflect.DeepEqual(got, []string{"first"}) {
		t.Fatalf("the add-ons included are %v, want [first]", got)
	}
}

// A credential more than one add-on claims is nobody's: which of them it is
// cannot be told, so it is refused as an unknown one is.
func TestACredentialTwoAddOnsClaimIsRefused(t *testing.T) {
	claims := func(id string) Addon {
		return Addon{ID: id,
			ResolveBearerToken: func(s *CoreServer, r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
				cc.CallerAID, cc.Scopes = "E"+id, []string{"demo.read"}
				return cc, true
			},
			SealedSender: func(s *CoreServer, kid string) (didcomm.DID, bool) {
				return didcomm.DID{AID: "E" + id}, true
			},
			ConversationParty: func(s *CoreServer, id, party string) (bool, bool, error) { return true, true, nil },
		}
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}

	onlyAddons(t, claims("one"))
	if cc := s.resolveCaller(fromThisComputerAsTheOwner("Authorization", "Bearer shared")); cc.CallerAID != "Eone" {
		t.Fatalf("one add-on's token did not resolve: %+v", cc)
	}
	if _, ok := s.sealedSenderOfAnAddon("kid"); !ok {
		t.Fatal("one add-on's sealed sender was not found")
	}
	if held, party, err := s.conversationParty("c", "p"); err != nil || !held || !party {
		t.Fatalf("one add-on's conversation: %v %v %v", held, party, err)
	}

	onlyAddons(t, claims("one"), claims("two"))
	if why := refused(s.resolveCaller(fromThisComputerAsTheOwner("Authorization", "Bearer shared"))); why != "" {
		t.Fatalf("a token two add-ons claim was not refused: %s", why)
	}
	if did, ok := s.sealedSenderOfAnAddon("kid"); ok {
		t.Fatalf("a sealed sender two add-ons claim was taken as %s", did.AID)
	}
	if _, _, err := s.conversationParty("c", "p"); err == nil {
		t.Fatal("a conversation two add-ons hold was filed under one of them")
	}
}

// An add-on closes its own routes to a controller and can raise the score
// they need, but cannot lower what the core asks.
func TestAnAddOnCanOnlyMakeAControllerActionHarder(t *testing.T) {
	const route = "POST /api/an-add-ons-own"
	onlyAddons(t, Addon{ID: "strict",
		ControllerOwnerOnly:    map[string]string{"DELETE /api/an-add-ons-own": "only the owner"},
		ControllerMinimumScore: map[string]int{route: 95, "GET /api/profile": 10},
	})
	if why, closed := isOwnerOnly("DELETE", "/api/an-add-ons-own"); !closed || why != "only the owner" {
		t.Fatalf("an add-on's owner-only route is open to a controller (%q)", why)
	}
	if got := minimumScoreFor(route); got != 95 {
		t.Fatalf("the add-on's raised minimum is %d, want 95", got)
	}
	if got := minimumScoreFor("GET /api/profile"); got != 0 {
		t.Fatalf("an add-on lowered what a core route needs, to %d", got)
	}
	ok, _ := mayThisControllerDoThis("POST", "/api/an-add-ons-own", "Eperson",
		authprovider.Result{Measured: true, Score: 90})
	if ok {
		t.Fatal("a score of 90 was let through a route an add-on set to need 95")
	}

	onlyAddons(t, Addon{ID: "mistaken", ControllerMinimumScore: map[string]int{route: -1}})
	if got := minimumScoreFor(route); got >= 0 {
		t.Fatalf("a negative minimum from an add-on became %d rather than refusing everybody", got)
	}
}

// What the handle hands an add-on are copies: changing one changes no rule.
func TestTheControllerRulesAnAddOnIsGivenAreCopies(t *testing.T) {
	onlyAddons(t)
	owner := hostWrapper{}.ControllerOwnerOnly()
	for k := range owner {
		delete(owner, k)
	}
	owner["GET /api/profile"] = "changed"
	hostWrapper{}.ControllerMinimumScore()["GET /api/profile"] = 1
	if _, closed := isOwnerOnly("GET", "/api/profile"); closed {
		t.Fatal("changing the copy closed a route")
	}
	if len(controllerOwnerOnly) == 0 {
		t.Fatal("changing the copy emptied the core's rules")
	}
	if got := minimumScoreFor("GET /api/profile"); got != 0 {
		t.Fatalf("changing the copy set a minimum of %d", got)
	}
}

// Every entry an add-on makes in the route tables or the controller rules
// names a route that add-on itself mounts, so none can open, close or rate a
// core route. This is the check; the add-ons' own tests run it on the real
// ones.
func TestAnAddOnsEntriesForACoreRouteAreFound(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {}
	own := Addon{ID: "own",
		Routes:           func(s *CoreServer, r chi.Router) { r.Get("/own", ok) },
		RootRoutes:       func(s *CoreServer, r chi.Router) { r.HandleFunc("/own-prefix/*", ok) },
		PublicRoutes:     map[string]string{"GET /api/own": "its own"},
		ScopedPrefixes:   []string{"/own-prefix/"},
		SessionForbidden: map[string]string{"GET /api/own": "its own"},
	}
	onlyAddons(t, own)
	s := &CoreServer{DataDir: t.TempDir()}
	if got := entriesForRoutesNotItsOwn(s); len(got) != 0 {
		t.Fatalf("an add-on's entries for its own routes were reported: %v", got)
	}
	grabby := own
	grabby.ID = "grabby"
	grabby.PublicRoutes = map[string]string{"GET /api/profile": "a core route"}
	grabby.ScopedRoutes = map[string]string{"POST /api/sign": "a core route"}
	grabby.ScopedPrefixes = []string{"/api/"}
	grabby.ControllerMinimumScore = map[string]int{"GET /api/contacts": 1}
	onlyAddons(t, grabby)
	got := entriesForRoutesNotItsOwn(s)
	want := []string{
		"grabby: ControllerMinimumScore: GET /api/contacts",
		"grabby: PublicRoutes: GET /api/profile",
		"grabby: ScopedPrefixes: /api/",
		"grabby: ScopedRoutes: POST /api/sign",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries for core routes found: %v\nwant %v", got, want)
	}
}

// /api/info names exactly the add-ons included.
func TestTheInfoNamesTheAddOnsIncluded(t *testing.T) {
	for _, included := range [][]Addon{nil, {{ID: "ai_agents"}}, {{ID: "sandboxed_apps"}, {ID: "ai_agents"}}} {
		onlyAddons(t, included...)
		s := agentWithDerivedIdentity(t)
		s.KeriDriver = keriengine.New()
		w := httptest.NewRecorder()
		s.handleInfo(w, httptest.NewRequest("GET", "/api/info", nil))
		var info CoreInfoResponse
		if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		want := []string{}
		for _, a := range included {
			want = append(want, a.ID)
		}
		if !reflect.DeepEqual(info.AddOns, want) {
			t.Fatalf("/api/info says %v are included, want %v", info.AddOns, want)
		}
		for _, c := range info.Capabilities {
			if c == "sandbox_plugins" {
				t.Fatal("/api/info still claims sandbox plug-ins whatever is included")
			}
		}
	}
}

// A server is not made with an add-on that opens a route it does not serve:
// one that would make a core route public, or scope a prefix over a core
// route, is refused as the server is made.
func TestAnAddOnThatOpensACoreRouteIsRefused(t *testing.T) {
	unsealedAfter(t)
	ok := func(w http.ResponseWriter, r *http.Request) {}
	for name, rogue := range map[string]Addon{
		"a core route made public": {ID: "rogue",
			Routes:       func(s *CoreServer, r chi.Router) { r.Get("/rogue", ok) },
			PublicRoutes: map[string]string{"POST /api/reset": "taken over"}},
		"a prefix over a core route": {ID: "rogue",
			Routes:         func(s *CoreServer, r chi.Router) { r.Get("/controller", ok) },
			ScopedPrefixes: []string{"/api/controller"}},
		"a core route scoped": {ID: "rogue",
			ScopedRoutes: map[string]string{"DELETE /api/controllers/{aid}": "taken over"}},
	} {
		onlyAddons(t, rogue)
		msg, refused := panics(func() { New(Config{DataDir: t.TempDir()}) })
		if !refused || !strings.Contains(msg, "opens routes it does not serve") {
			t.Errorf("a server was made with an add-on opening %s (%q)", name, msg)
		}
	}
	// The same add-ons, opening only their own routes, are made.
	onlyAddons(t, Addon{ID: "own",
		Routes:         func(s *CoreServer, r chi.Router) { r.Get("/its-own/{x}", ok) },
		PublicRoutes:   map[string]string{"GET /api/its-own/{x}": "its own"},
		ScopedPrefixes: []string{"/api/its-own"}})
	if msg, refused := panics(func() { New(Config{DataDir: t.TempDir()}) }); refused {
		t.Fatalf("an add-on opening only its own route was refused: %s", msg)
	}
}

// A scoped prefix covers routes under it on a path segment's boundary only:
// /api/controller opens /api/controller/... and never /api/controllers/...
func TestAPrefixOpensOnlyWhatIsUnderIt(t *testing.T) {
	onlyAddons(t, Addon{ID: "prefix", ScopedPrefixes: []string{"/api/controller"}})
	for pattern, want := range map[string]accessClass{
		"/api/controller":             accessScoped,
		"/api/controller/{x}":         accessScoped,
		"/api/controllers/{aid}":      accessOwner,
		"/api/controllers-and-more/x": accessOwner,
	} {
		if got := classify("DELETE", pattern); got != want {
			t.Errorf("%s classified %v, want %v", pattern, got, want)
		}
	}
}

// An overlay's routes, added after the server is made, are checked too: a
// prefix an add-on opens may not cover one of them, and the server does not
// start.
func TestAPrefixOverAnOverlaysRouteStopsTheStart(t *testing.T) {
	unsealedAfter(t)
	ok := func(w http.ResponseWriter, r *http.Request) {}
	onlyAddons(t, Addon{ID: "prefix",
		Routes:         func(s *CoreServer, r chi.Router) { r.Get("/shared/mine", ok) },
		ScopedPrefixes: []string{"/api/shared"}})
	s, err := New(Config{DataDir: t.TempDir(), Port: 0})
	if err != nil {
		t.Skipf("making the server: %v", err)
	}
	s.MountExtraRoutes(func(r chi.Router) { r.Get("/shared/the-overlays", ok) })
	if err := s.Start(); err == nil {
		s.Stop()
		t.Fatal("a server started with an add-on's prefix over an overlay's route")
	} else if !strings.Contains(err.Error(), "opens routes it does not serve") {
		t.Fatalf("the start failed for another reason: %v", err)
	}
}

// A message is filed under the conversation its sender named only where that
// is known to be right: where no add-on keeps conversations it is the
// sender's thread, as named; where an add-on fails to say, or two hold it, it
// is filed under none.
func TestAMessageIsFiledUnderNoConversationWhenItCannotBeTold(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	body := json.RawMessage(`{"conversation":"c_named"}`)
	holds := func(id string) Addon {
		return Addon{ID: id, ConversationParty: func(*CoreServer, string, string) (bool, bool, error) { return true, true, nil }}
	}

	onlyAddons(t)
	if got := s.trafficConversation("Esender", body); got != "c_named" {
		t.Fatalf("with no add-on keeping conversations, the message was filed under %q", got)
	}
	onlyAddons(t, Addon{ID: "fails", ConversationParty: func(*CoreServer, string, string) (bool, bool, error) {
		return false, false, errors.New("the store is unreadable")
	}})
	if got := s.trafficConversation("Esender", body); got != "" {
		t.Fatalf("an add-on that failed to say still had the message filed under %q", got)
	}
	onlyAddons(t, holds("one"), holds("two"))
	if got := s.trafficConversation("Esender", body); got != "" {
		t.Fatalf("a conversation two add-ons hold had the message filed under %q", got)
	}
}

// A body two add-ons claim is nobody's, and an add-on's work on a caller it
// does not claim reaches nothing: each works on a copy, and the caller takes
// only what exactly one claims.
func TestAProvenCallerTakesOnlyWhatOneAddOnClaims(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	r := httptest.NewRequest("POST", "/api/agent-host/messages", nil)
	body := func(id string) Addon {
		return Addon{ID: id, ResolveBodySignature: func(s *CoreServer, r *http.Request, cc permission.CallerContext) (permission.CallerContext, bool) {
			cc.CallerAID = "E" + id
			return cc, true
		}}
	}
	onlyAddons(t, body("one"))
	if cc, ok := s.resolveBodySignature(r, permission.CallerContext{Remote: true}); !ok || cc.CallerAID != "Eone" {
		t.Fatalf("one add-on's body was not resolved: %+v %v", cc, ok)
	}
	onlyAddons(t, body("one"), body("two"))
	if cc, ok := s.resolveBodySignature(r, permission.CallerContext{Remote: true}); ok || cc.CallerAID != "" {
		t.Fatalf("a body two add-ons claim was taken as %q", cc.CallerAID)
	}

	meddles := Addon{ID: "meddles", EnrichProvenCaller: func(s *CoreServer, c *permission.CallerContext) bool {
		c.Scopes = append(c.Scopes, "everything")
		c.DelegationChain = []string{"Esomebody"}
		return false
	}}
	claims := func(id string) Addon {
		return Addon{ID: id, EnrichProvenCaller: func(s *CoreServer, c *permission.CallerContext) bool {
			c.DelegationChain = []string{"E" + id}
			return true
		}}
	}
	proven := func() *permission.CallerContext {
		return &permission.CallerContext{EnvelopeVerified: true, CallerAID: "Eproven", Scopes: []string{"read"}}
	}
	onlyAddons(t, meddles)
	c := proven()
	s.enrichProvenCaller(c)
	if len(c.DelegationChain) != 0 || len(c.Scopes) != 1 {
		t.Fatalf("an add-on that did not claim the caller changed it: %+v", c)
	}
	onlyAddons(t, meddles, claims("one"))
	c = proven()
	s.enrichProvenCaller(c)
	if len(c.DelegationChain) != 1 || c.DelegationChain[0] != "Eone" || len(c.Scopes) != 1 {
		t.Fatalf("the one add-on that claimed the caller did not have its way alone: %+v", c)
	}
	onlyAddons(t, claims("one"), claims("two"))
	c = proven()
	s.enrichProvenCaller(c)
	if len(c.DelegationChain) != 0 {
		t.Fatalf("a caller two add-ons claim was given %v", c.DelegationChain)
	}
}

// failingChains are chains that cannot be read.
type failingChains struct{}

func (failingChains) Heads() (map[string]ChainHead, error) {
	return nil, errors.New("the store is unreadable")
}
func (failingChains) EntryHash(string, int) (string, error) {
	return "", errors.New("the store is unreadable")
}

// silentChains answer for entries without listing them among their heads.
type silentChains struct{ fixedChains }

func (silentChains) Heads() (map[string]ChainHead, error) { return map[string]ChainHead{}, nil }

// The anchoring's check reports a chain it cannot read as broken, not as
// nothing to check, and refuses a conversation entry more than one chain
// answers for, as it refuses a conversation held twice.
func TestTheAnchorCheckNeitherIgnoresNorGuessesAtChains(t *testing.T) {
	s := recordWorld(t)
	chain := fixedChains{"c1": {Seq: 2, Hash: "Ehead"}}
	keeps := func(id string, c AnchoredChains) Addon {
		return Addon{ID: id, AnchoredChains: func(*CoreServer) (AnchoredChains, error) { return c, nil }}
	}
	onlyAddons(t, keeps("one", chain))
	writeRows(t, s, 1)
	s.anchorRecord()
	if got, err := s.checkAnchors(); err != nil || got.BrokenAt != 0 {
		t.Fatalf("the anchors did not hold to begin with: %+v %v", got, err)
	}

	onlyAddons(t, keeps("one", chain), keeps("broken", failingChains{}))
	if got, _ := s.checkAnchors(); got.BrokenAt == 0 || !strings.Contains(got.Why, "cannot be read") {
		t.Fatalf("a chain that cannot be read was not reported: %+v", got)
	}
	onlyAddons(t, keeps("one", chain), keeps("two", chain))
	if got, _ := s.checkAnchors(); got.BrokenAt == 0 || !strings.Contains(got.Why, "more than one add-on") {
		t.Fatalf("a conversation two add-ons keep was not reported: %+v", got)
	}
	onlyAddons(t, keeps("one", chain), keeps("silent", silentChains{chain}))
	if got, _ := s.checkAnchors(); got.BrokenAt == 0 {
		t.Fatalf("an entry two chains answer for was checked against one of them: %+v", got)
	}
}
