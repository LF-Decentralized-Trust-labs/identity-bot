package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// onlyAddons makes as the add-ons registered, for the length of the test.
func onlyAddons(t *testing.T, as ...Addon) {
	t.Helper()
	addonsMu.Lock()
	was := addons
	addons = as
	addonsMu.Unlock()
	t.Cleanup(func() {
		addonsMu.Lock()
		addons = was
		addonsMu.Unlock()
	})
}

// An add-on's routes are served behind the same authorisation as the core's:
// one nobody classified is the owner's, under /api, and one outside /api is
// served where the add-on put it.
func TestAnAddOnsRoutesAreServedBehindTheCoresAuthorisation(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]bool{"ok": true}) }
	onlyAddons(t, Addon{
		Name:       "test",
		Routes:     func(s *CoreServer, r chi.Router) { r.Get("/an-add-on", ok) },
		RootRoutes: func(s *CoreServer, r chi.Router) { r.Get("/an-add-on-outside-the-api", ok) },
	})
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	s.router = s.buildRouter("")

	serve := func(r *http.Request) int {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, r)
		return w.Code
	}
	if code := serve(local("GET", "/api/an-add-on", "")); code != http.StatusOK {
		t.Fatalf("the owner was answered %d by an add-on's route", code)
	}
	if code := serve(remote("GET", "/api/an-add-on", "")); code == http.StatusOK {
		t.Fatal("an add-on's route answered a stranger: it is not behind the core's authorisation")
	}
	if code := serve(local("GET", "/an-add-on-outside-the-api", "")); code != http.StatusOK {
		t.Fatalf("an add-on's route outside /api was answered %d", code)
	}
}

// Without the add-on, its routes are not there: the core answers for one as
// it answers for a route that does not exist.
func TestAnAddOnLeftOutServesNothing(t *testing.T) {
	onlyAddons(t)
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	s.router = s.buildRouter("")
	serve := func(path string) (int, string) {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, local("GET", path, ""))
		return w.Code, w.Body.String()
	}
	nothingCode, nothingBody := serve("/api/a/route/nobody/serves")
	if code, body := serve("/api/mcp/agents"); code != nothingCode || body != nothingBody {
		t.Fatalf("an Identity Agent with no AI-agent add-on answered %d %q for its route, and %d %q for no route",
			code, body, nothingCode, nothingBody)
	}
}

// Withdrawing a credential tells every add-on, in the order they registered,
// with why.
func TestWithdrawingACredentialTellsEveryAddOn(t *testing.T) {
	var heard []string
	onlyAddons(t,
		Addon{Name: "first", CredentialWithdrawn: func(s *CoreServer, why string) { heard = append(heard, "first: "+why) }},
		Addon{Name: "no hook"},
		Addon{Name: "second", CredentialWithdrawn: func(s *CoreServer, why string) { heard = append(heard, "second: "+why) }},
	)
	(&CoreServer{}).credentialWithdrawn("a credential was revoked")
	want := []string{"first: a credential was revoked", "second: a credential was revoked"}
	if !reflect.DeepEqual(heard, want) {
		t.Fatalf("heard %q, want %q", heard, want)
	}
}

// The loop ticks at least as often as the add-on that needs it most often,
// and no more often than the interval where none needs it sooner.
func TestTheLoopTicksAsOftenAsAnAddOnNeeds(t *testing.T) {
	onlyAddons(t)
	if got := anchorTick(); got != anchorInterval {
		t.Fatalf("with no add-on the loop ticks every %s, not every %s", got, anchorInterval)
	}
	onlyAddons(t, Addon{TickAtMost: time.Hour + anchorInterval}, Addon{TickAtMost: anchorInterval / 2}, Addon{})
	if got := anchorTick(); got != anchorInterval/2 {
		t.Fatalf("an add-on needing a tick every %s got one every %s", anchorInterval/2, got)
	}
}

// The record's anchoring reads the chains every add-on keeps beside the log;
// where none keeps any, it treats them as chains it cannot read.
func TestTheAnchoringReadsTheChainsAddOnsKeep(t *testing.T) {
	onlyAddons(t, Addon{Name: "keeps none"})
	if _, err := (&CoreServer{}).anchoredChains(); !errors.Is(err, errNoAnchoredChains) {
		t.Fatalf("with no add-on keeping chains, the anchoring was given %v", err)
	}
	chain := fixedChains{"c1": {Seq: 3, Hash: "Ehead"}}
	onlyAddons(t, Addon{Name: "keeps one", AnchoredChains: func(*CoreServer) (AnchoredChains, error) { return chain, nil }})
	chains, err := (&CoreServer{}).anchoredChains()
	if err != nil || len(chains) != 1 {
		t.Fatalf("the anchoring was not given the add-on's chains: %v %v", chains, err)
	}
	if heads, _ := chains[0].Heads(); heads["c1"].Seq != 3 {
		t.Fatalf("the chain's head was not read: %+v", heads)
	}
}

// fixedChains are chains whose entries are their heads.
type fixedChains map[string]ChainHead

func (f fixedChains) Heads() (map[string]ChainHead, error) { return f, nil }
func (f fixedChains) EntryHash(id string, seq int) (string, error) {
	if h, ok := f[id]; ok && h.Seq == seq {
		return h.Hash, nil
	}
	return "", errors.New("no such entry")
}

func everyScopedRoute() map[string]string {
	return everyEntry(scopedRoutes, func(a Addon) map[string]string { return a.ScopedRoutes })
}
