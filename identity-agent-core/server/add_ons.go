package server

import (
	"context"
	"errors"
	"fmt"
	"identity-agent-core/authorisation"
	"identity-agent-core/didcomm"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Add-ons.
//
// An add-on is a package an app may include alongside the core: AI agents,
// sandboxed apps, an organisation's own features. Whatever the core links is
// carried by every app built on it, on every phone, so the core holds only
// what every Identity Agent needs and the rest comes as add-ons, each
// included only by an app that imports it.
//
// An add-on is a package of its own that the core never imports. An app
// includes it by importing that package, whose init calls RegisterAddon, and
// leaves it out by not importing it. Nothing in the core names an add-on: the
// core asks every registered one for what it would otherwise have to call by
// name — the routes it serves, the work it runs in the background, what it
// does on each tick, and what it must hear when a credential is withdrawn.
//
// An app built on the core registers its own add-ons the same way, beside the
// ones it imports from here.

// Addon is what an add-on gives the core. Every field is optional.
type Addon struct {
	// ID names the add-on to apps, in what /api/info says is included
	// ("ai_agents", "sandboxed_apps"). It is required, never changes once an
	// app relies on it, and no two add-ons share one.
	ID string
	// Name says which add-on, in logs.
	Name string

	// Prefixes are the paths the add-on owns ("/api/mcp", "/apps"): static,
	// and taken on a path segment's boundary. Every route it mounts must lie
	// under one; no two add-ons' may overlap; and none may cover a path any
	// route of the core's can match. New refuses an add-on that breaks any of
	// these, so an add-on never serves a request a core route would have.
	Prefixes []string

	// Routes adds routes under /api, behind the same authorisation as the
	// core's own. They are mounted after the core's own routes and before any
	// an overlay adds with MountExtraRoutes.
	Routes func(s *CoreServer, r chi.Router)
	// RootRoutes adds routes outside /api, behind the same router-wide
	// middleware as every other route.
	RootRoutes func(s *CoreServer, r chi.Router)

	// Prepare runs while New makes the server, once the core's stores, vault
	// and asset handler are made, and before the server starts.
	Prepare func(s *CoreServer)
	// Run is work that runs in the background from when the server starts
	// until it stops; stop closes when it does.
	Run func(s *CoreServer, stop <-chan struct{})
	// Stop ends what Prepare started, when the server stops: after its
	// background work is told to end and before the activity log closes.
	Stop func(s *CoreServer)

	// TickAtMost, when set, is the longest the add-on can wait between two
	// ticks of the loop every Identity Agent runs (what_runs_every_tick.go);
	// the loop ticks at least that often.
	TickAtMost time.Duration

	// AnchoredChains are chains the add-on keeps beside the activity log, such
	// as AI agents' conversations, whose newest entries the record's
	// anchoring fixes along with the log's head.
	AnchoredChains func(s *CoreServer) (AnchoredChains, error)

	// CredentialWithdrawn runs when a credential this identity issued is
	// withdrawn or revoked, so that whatever the add-on gave on the strength
	// of it ends now rather than when it would have lapsed. why says which.
	CredentialWithdrawn func(s *CoreServer, why string)

	// ConversationParty says whether conversation id is held here, and
	// whether party is in it, so a log row is filed under a conversation only
	// for one of its parties.
	ConversationParty func(s *CoreServer, id, party string) (held, isParty bool, err error)

	// Who is calling. The core detects that a caller presented a bearer
	// token or a body's signature, and asks the add-ons, in the order they
	// registered, who that is. A credential no add-on recognises is refused
	// exactly as an unknown one always was: the caller is remote, holds no
	// scopes, and is never taken for the owner, whatever else it carries.

	// ResolveBearerToken says who presented token, when it is one the add-on
	// issued; cc is the caller as far as the core knows it.
	ResolveBearerToken func(s *CoreServer, r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool)
	// ResolveBodySignature says who signed r with a body's key
	// (permission.HeaderBodyHost), when it is a live body of the add-on's.
	ResolveBodySignature func(s *CoreServer, r *http.Request, cc permission.CallerContext) (permission.CallerContext, bool)
	// EnrichProvenCaller fills in the lineage and scopes of a caller that
	// proved its identifier with a signed-request envelope, when the
	// identifier is one of the add-on's, and reports whether it was.
	EnrichProvenCaller func(s *CoreServer, caller *permission.CallerContext) bool
	// SealedSender is the DIDComm identity a sealed envelope from kid comes
	// from, when kid is one the add-on recognises, such as a live body's.
	SealedSender func(s *CoreServer, kid string) (didcomm.DID, bool)

	// The add-on's entries in the core's route tables (api_auth.go), keyed
	// "METHOD /chi/pattern" with the reason, as the core's own are: routes
	// open to anyone, routes open to a caller holding scopes, path prefixes
	// open to a caller holding scopes, and routes a browser session must not
	// take. A route the add-on does not list is the owner's.
	PublicRoutes     map[string]string
	ScopedRoutes     map[string]string
	ScopedPrefixes   []string
	SessionForbidden map[string]string

	// The add-on's rules for a machine acting for the owner (a controller),
	// beside the core's (what_a_controller_may_reach.go), keyed the same way.
	// ControllerOwnerOnly are its routes no controller may take, at any
	// score, with why. ControllerMinimumScore are the scores its routes need
	// other than the default. An add-on can only make an action harder to
	// take: a minimum below what the core asks counts for nothing, and a
	// negative one refuses everybody, as it does in the core.
	ControllerOwnerOnly    map[string]string
	ControllerMinimumScore map[string]int

	// GrantKinds are the kinds of grant the add-on issues, by schema, with
	// what the core's grant engine asks about each one. A grant of a kind no
	// add-on here issues is not appended when its signature comes back.
	GrantKinds map[*schemas.AssetGrant]GrantKind
}

// GrantKind is what the grant engine asks an add-on about a grant it issues
// when the device that holds the identity's key signs it.
type GrantKind struct {
	// StillWhatItGrants says why the grant must not be appended: what it is
	// for is gone, has changed, or was granted meanwhile.
	StillWhatItGrants func(s *CoreServer, shown *authorisation.ToSign) error
	// Arrived tells the add-on the grant is in force, under said.
	Arrived func(s *CoreServer, holder, said string)
	// Awaiting lists what waits for a grant of this kind, for the owner to
	// approve, under the key AwaitingKey in the list of what awaits approval.
	Awaiting    func(s *CoreServer) []map[string]any
	AwaitingKey string
}

// AnchoredChains are chains of entries, each entry naming the hash of the one
// before, kept beside the activity log.
type AnchoredChains interface {
	// Heads is each chain's newest entry, by the chain's id.
	Heads() (map[string]ChainHead, error)
	// EntryHash is the hash of entry seq of chain id.
	EntryHash(id string, seq int) (string, error)
}

// ChainHead is a chain's newest entry.
type ChainHead struct {
	Seq  int
	Hash string
}

var (
	addonsMu sync.Mutex
	addons   []Addon
	// addonsSealed is set once New first runs: the add-ons included are
	// settled then, and none is added while a server runs.
	addonsSealed bool
)

// RegisterAddon includes an add-on in every Identity Agent this process
// starts. An add-on's package calls it from its init, so importing the
// package is what includes it. Add-ons are asked in the order they were
// registered.
//
// It panics once a server has been made, and for an add-on with no ID or
// with an ID another already has: the list is fixed before anything runs, so
// nothing can join it mid-run, and an app can tell which is which.
func RegisterAddon(a Addon) {
	addonsMu.Lock()
	defer addonsMu.Unlock()
	if addonsSealed {
		panic("server.RegisterAddon(" + a.ID + ") after a server was made: an add-on registers from its package's init")
	}
	if a.ID == "" {
		panic("server.RegisterAddon: an add-on needs an ID (" + a.Name + ")")
	}
	for _, b := range addons {
		if b.ID == a.ID {
			panic("server.RegisterAddon: two add-ons are both " + a.ID)
		}
	}
	addons = append(addons, a)
}

// sealAddons settles the add-ons included: from now on RegisterAddon
// refuses.
func sealAddons() {
	addonsMu.Lock()
	defer addonsMu.Unlock()
	addonsSealed = true
}

// addonIDs are the IDs of the add-ons included, in the order they
// registered.
func addonIDs() []string {
	ids := []string{}
	for _, a := range registeredAddons() {
		ids = append(ids, a.ID)
	}
	return ids
}

// registeredAddons are the add-ons included, in the order they registered.
func registeredAddons() []Addon {
	addonsMu.Lock()
	defer addonsMu.Unlock()
	return append([]Addon(nil), addons...)
}

// mountAddonRoutes adds addons' routes under /api.
func (s *CoreServer) mountAddonRoutes(r chi.Router, addons []Addon) {
	for _, a := range addons {
		if a.Routes != nil {
			a.Routes(s, r)
		}
	}
}

// mountAddonRootRoutes adds addons' routes outside /api.
func (s *CoreServer) mountAddonRootRoutes(r chi.Router, addons []Addon) {
	for _, a := range addons {
		if a.RootRoutes != nil {
			a.RootRoutes(s, r)
		}
	}
}

// prepareAddons runs every add-on's Prepare.
func (s *CoreServer) prepareAddons() {
	for _, a := range registeredAddons() {
		if a.Prepare != nil {
			a.Prepare(s)
		}
	}
}

// runAddons starts every add-on's background work, to end when stop closes.
func (s *CoreServer) runAddons(stop <-chan struct{}) {
	for _, a := range registeredAddons() {
		if a.Run != nil {
			run := a.Run
			s.inBackground(func(context.Context) { run(s, stop) })
		}
	}
}

// stopAddons runs every add-on's Stop.
func (s *CoreServer) stopAddons() {
	for _, a := range registeredAddons() {
		if a.Stop != nil {
			a.Stop(s)
		}
	}
}

// addonsTickAtMost is the shortest TickAtMost an add-on asked for, or 0
// where none did.
func addonsTickAtMost() time.Duration {
	var at time.Duration
	for _, a := range registeredAddons() {
		if a.TickAtMost > 0 && (at == 0 || a.TickAtMost < at) {
			at = a.TickAtMost
		}
	}
	return at
}

// credentialWithdrawn tells every add-on that a credential was withdrawn.
func (s *CoreServer) credentialWithdrawn(why string) {
	for _, a := range registeredAddons() {
		if a.CredentialWithdrawn != nil {
			a.CredentialWithdrawn(s, why)
		}
	}
}

// errNoAnchoredChains is an Identity Agent none of whose add-ons keeps chains
// beside the log.
var errNoAnchoredChains = errors.New("no add-on here keeps chains beside the activity log")

// anchoredChains are the chains every add-on keeps beside the log. It fails
// when none keeps any, or when one cannot be opened, exactly as the record's
// anchoring treats chains it cannot read.
func (s *CoreServer) anchoredChains() ([]AnchoredChains, error) {
	var out []AnchoredChains
	for _, a := range registeredAddons() {
		if a.AnchoredChains == nil {
			continue
		}
		c, err := a.AnchoredChains(s)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errNoAnchoredChains
	}
	return out, nil
}

// resolveBearerToken asks the add-ons who presented token. A token more than
// one add-on claims is nobody's: it is refused as an unknown one is, since
// which of them it is cannot be told.
func (s *CoreServer) resolveBearerToken(r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
	var found []permission.CallerContext
	for _, a := range registeredAddons() {
		if a.ResolveBearerToken != nil {
			if resolved, ok := a.ResolveBearerToken(s, r, token, copyCaller(cc)); ok {
				found = append(found, resolved)
			}
		}
	}
	if len(found) != 1 {
		return cc, false
	}
	return found[0], true
}

// resolveBodySignature asks the add-ons who signed r with a body's key. A
// body more than one add-on claims is nobody's, as a token is.
func (s *CoreServer) resolveBodySignature(r *http.Request, cc permission.CallerContext) (permission.CallerContext, bool) {
	var found []permission.CallerContext
	for _, a := range registeredAddons() {
		if a.ResolveBodySignature != nil {
			if resolved, ok := a.ResolveBodySignature(s, r, copyCaller(cc)); ok {
				found = append(found, resolved)
			}
		}
	}
	if len(found) != 1 {
		return cc, false
	}
	return found[0], true
}

// copyCaller is cc with nothing shared, so what one add-on does to it reaches
// neither the caller nor another add-on.
func copyCaller(cc permission.CallerContext) permission.CallerContext {
	cc.Scopes = append([]string(nil), cc.Scopes...)
	cc.DelegationChain = append([]string(nil), cc.DelegationChain...)
	if cc.ResourceConstraints != nil {
		cc.ResourceConstraints = deepCopy(cc.ResourceConstraints).(map[string]interface{})
	}
	return cc
}

// deepCopy is v with every map and slice in it copied, at every depth, so
// nothing in the copy is shared with v. Other values are kept as they are.
func deepCopy(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case []string:
		return append([]string(nil), x...)
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, e := range x {
			out[k] = e
		}
		return out
	}
	return v
}

// enrichProvenCaller gives a caller that proved its identifier with a
// signed-request envelope, and has no lineage yet, what an add-on says that
// identifier holds. An identifier no add-on recognises, or more than one
// does, is granted nothing.
func (s *CoreServer) enrichProvenCaller(caller *permission.CallerContext) {
	if !caller.EnvelopeVerified || caller.CallerAID == "" || len(caller.DelegationChain) > 0 {
		return
	}
	// Each add-on works on a copy, so one that writes and then says the
	// identifier is not its own changes nothing; the caller takes what one
	// add-on, and only one, claims.
	var found []permission.CallerContext
	for _, a := range registeredAddons() {
		if a.EnrichProvenCaller == nil {
			continue
		}
		c := copyCaller(*caller)
		if a.EnrichProvenCaller(s, &c) {
			found = append(found, c)
		}
	}
	if len(found) == 1 {
		*caller = found[0]
	}
}

// sealedSenderOfAnAddon asks the add-ons who a sealed envelope from kid
// comes from. A kid more than one add-on claims is nobody's.
func (s *CoreServer) sealedSenderOfAnAddon(kid string) (didcomm.DID, bool) {
	var found []didcomm.DID
	for _, a := range registeredAddons() {
		if a.SealedSender != nil {
			if did, ok := a.SealedSender(s, kid); ok {
				found = append(found, did)
			}
		}
	}
	if len(found) != 1 {
		return didcomm.DID{}, false
	}
	return found[0], true
}

// errNoConversations is an Identity Agent none of whose add-ons keeps
// conversations.
var errNoConversations = errors.New("no add-on here keeps conversations")

// errConversationHeldTwice is a conversation more than one add-on says it
// holds: whose it is cannot be told, so it is filed under neither.
var errConversationHeldTwice = errors.New("more than one add-on says it holds this conversation")

// conversationParty asks the add-ons about conversation id. With none that
// keeps conversations it fails, as the conversations failing to open did; an
// add-on that fails makes it fail; and a conversation more than one add-on
// holds fails rather than being filed under one of them.
func (s *CoreServer) conversationParty(id, party string) (held, isParty bool, err error) {
	asked, holders := 0, 0
	for _, a := range registeredAddons() {
		if a.ConversationParty == nil {
			continue
		}
		asked++
		h, p, err := a.ConversationParty(s, id, party)
		if err != nil {
			return false, false, err
		}
		if h {
			holders++
			held, isParty = true, p
		}
	}
	switch {
	case asked == 0:
		return false, false, errNoConversations
	case holders > 1:
		return false, false, errConversationHeldTwice
	}
	return held, isParty, nil
}

// addonRouteEntry is an add-on's entry for key in one of the route tables.
func addonRouteEntry(table func(Addon) map[string]string, key string) (string, bool) {
	for _, a := range registeredAddons() {
		if why, ok := table(a)[key]; ok {
			return why, true
		}
	}
	return "", false
}

// routesIn are the routes r serves, as "METHOD /pattern".
func routesIn(r chi.Routes) map[string]bool {
	out := map[string]bool{}
	chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out[method+" "+route] = true
		return nil
	})
	return out
}

// addonRoutes are the routes add-on a mounts, alone.
func (s *CoreServer) addonRoutes(a Addon) map[string]bool {
	r := chi.NewRouter()
	if a.Routes != nil {
		r.Route("/api", func(r chi.Router) { a.Routes(s, r) })
	}
	if a.RootRoutes != nil {
		a.RootRoutes(s, r)
	}
	return routesIn(r)
}

// routeTakeovers are the routes mounted twice: by an add-on and the core, by
// two add-ons, or, among extras, by an overlay and the core or an add-on.
// The router keeps whichever mounted last, so a route mounted twice is one
// somebody else's handler can take over while it keeps the first owner's
// access class. None is allowed.
func (s *CoreServer) routeTakeovers(extras []func(chi.Router)) []string {
	var out []string
	core := routesIn(s.buildRouterOf("", nil, nil))
	whose := map[string]string{}
	for k := range core {
		whose[k] = "the core"
	}
	for _, a := range registeredAddons() {
		for k := range s.addonRoutes(a) {
			if owner, taken := whose[k]; taken {
				out = append(out, a.ID+" mounts "+k+", which "+owner+" serves")
				continue
			}
			whose[k] = "add-on " + a.ID
		}
	}
	if len(extras) > 0 {
		r := chi.NewRouter()
		r.Route("/api", func(r chi.Router) {
			for _, fn := range extras {
				fn(r)
			}
		})
		for k := range routesIn(r) {
			if owner, taken := whose[k]; taken {
				out = append(out, "an overlay mounts "+k+", which "+owner+" serves")
			}
		}
	}
	sort.Strings(out)
	return out
}

// prefixViolations are what breaks the add-ons' ownership of their path
// prefixes (Addon.Prefixes): a route an add-on mounts outside its own, two
// add-ons' that overlap, one that is not a static path, and one covering a
// path a core route matches.
func (s *CoreServer) prefixViolations() []string {
	var out []string
	core := routesIn(s.buildRouterOf("", nil, nil))
	type owned struct{ id, prefix string }
	var all []owned
	for _, a := range registeredAddons() {
		for _, p := range a.Prefixes {
			if _, err := prefixSegments(p); err != nil {
				out = append(out, a.ID+": "+err.Error())
				continue
			}
			for _, o := range all {
				if _, meets, _ := prefixAndRoute(p, o.prefix+"/*"); meets {
					out = append(out, a.ID+": prefix "+p+" overlaps "+o.id+"'s "+o.prefix)
				}
			}
			all = append(all, owned{a.ID, p})
			for k := range core {
				pattern := k[strings.Index(k, " ")+1:]
				if pattern == theWebUI {
					continue
				}
				if meets, _ := prefixMeetsTheCore(p, pattern); meets {
					out = append(out, a.ID+": prefix "+p+" covers the core's "+k)
				}
			}
		}
		for k := range s.addonRoutes(a) {
			pattern := k[strings.Index(k, " ")+1:]
			in := false
			for _, p := range a.Prefixes {
				if inside, _, err := prefixAndRoute(p, pattern); err == nil && inside {
					in = true
				}
			}
			if !in {
				out = append(out, a.ID+": mounts "+k+" outside its prefixes")
			}
		}
	}
	sort.Strings(out)
	return out
}

// overlayShadows are the overlay routes (MountExtraRoutes) that can match a
// request a route of the core's or an add-on's matches, with the same method.
func (s *CoreServer) overlayShadows(extras []func(chi.Router)) []string {
	if len(extras) == 0 {
		return nil
	}
	without := routesIn(s.buildRouterOf("", registeredAddons(), nil))
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		for _, fn := range extras {
			fn(r)
		}
	})
	var out []string
	for o := range routesIn(r) {
		om, op, _ := strings.Cut(o, " ")
		for k := range without {
			km, kp, _ := strings.Cut(k, " ")
			if km == om && kp != theWebUI && patternsMeet(op, kp) {
				out = append(out, "an overlay mounts "+o+", which can take requests "+k+" serves")
			}
		}
	}
	sort.Strings(out)
	return out
}

// underPrefix reports whether route pattern is p or lies under it, on a path
// segment's boundary: /api/controller covers /api/controller/x and not
// /api/controllers.
func underPrefix(pattern, p string) bool {
	q := strings.TrimSuffix(p, "/")
	return pattern == q || strings.HasPrefix(pattern, q+"/")
}

// addonEntriesNotItsOwn are the entries an add-on makes for a route it does
// not itself mount, as "add-on: table: entry", given served, everything the
// server serves. An entry that opens a route (PublicRoutes, ScopedRoutes,
// ScopedPrefixes) is one an add-on may make only for its own routes: a
// prefix must cover some route of the add-on's and nobody else's. With
// loosening only, those are all that are checked; otherwise the entries that
// close or rate a route are checked the same way.
func (s *CoreServer) addonEntriesNotItsOwn(served chi.Routes, loosening bool) []string {
	var all []string
	chi.Walk(served, func(_, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		all = append(all, route)
		return nil
	})
	var out []string
	core := routesIn(s.buildRouterOf("", nil, nil))
	for _, a := range registeredAddons() {
		// An add-on's own routes are those it adds that the server built
		// without it does not serve: re-mounting somebody else's route does
		// not make it the add-on's.
		without := map[string]bool{}
		for k := range core {
			without[k] = true
		}
		for _, b := range registeredAddons() {
			if b.ID != a.ID {
				for k := range s.addonRoutes(b) {
					without[k] = true
				}
			}
		}
		own, ownPattern := map[string]bool{}, map[string]bool{}
		for k := range s.addonRoutes(a) {
			if without[k] {
				continue
			}
			own[k] = true
			ownPattern[k[strings.Index(k, " ")+1:]] = true
		}
		check := func(table string, keys []string) {
			for _, k := range keys {
				if !own[k] {
					out = append(out, a.ID+": "+table+": "+k)
				}
			}
		}
		check("PublicRoutes", keysOf(a.PublicRoutes))
		check("ScopedRoutes", keysOf(a.ScopedRoutes))
		for _, p := range a.ScopedPrefixes {
			found, foreign := false, false
			for _, route := range all {
				if !underPrefix(route, p) {
					continue
				}
				if ownPattern[route] {
					found = true
				} else {
					foreign = true
				}
			}
			if !found || foreign {
				out = append(out, a.ID+": ScopedPrefixes: "+p)
			}
		}
		if !loosening {
			check("SessionForbidden", keysOf(a.SessionForbidden))
			check("ControllerOwnerOnly", keysOf(a.ControllerOwnerOnly))
			var mins []string
			for k := range a.ControllerMinimumScore {
				mins = append(mins, k)
			}
			check("ControllerMinimumScore", mins)
		}
	}
	sort.Strings(out)
	return out
}

// keysOf are m's keys.
func keysOf(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// addonsOpeningOthersRoutes says which route is mounted twice (among
// extras too, an overlay's routes), or which add-on opens a route it does
// not mount, given served, everything the server serves. An add-on may open only its own routes; one that would make
// a core route, or another's, public or scoped is a server that must not run.
func (s *CoreServer) addonsOpeningOthersRoutes(served chi.Routes, extras []func(chi.Router)) error {
	if bad := s.routeTakeovers(extras); len(bad) > 0 {
		return fmt.Errorf("a route is mounted twice, so one handler would take over another's: %s", strings.Join(bad, "; "))
	}
	if bad := s.prefixViolations(); len(bad) > 0 {
		return fmt.Errorf("an add-on serves outside the paths it owns, or owns paths the core serves: %s", strings.Join(bad, "; "))
	}
	if bad := s.overlayShadows(extras); len(bad) > 0 {
		return fmt.Errorf("an overlay route can take requests another route serves: %s", strings.Join(bad, "; "))
	}
	if bad := s.addonEntriesNotItsOwn(served, true); len(bad) > 0 {
		return fmt.Errorf("an add-on opens routes it does not serve, which only their owner may open: %s", strings.Join(bad, "; "))
	}
	return nil
}

// addonScopedPrefixes are the path prefixes the add-ons open to a caller
// holding scopes.
func addonScopedPrefixes() []string {
	var out []string
	for _, a := range registeredAddons() {
		out = append(out, a.ScopedPrefixes...)
	}
	return out
}

// grantKind is what an add-on says about grants of kind, and whether any
// add-on here issues them.
func grantKind(kind *schemas.AssetGrant) (GrantKind, bool) {
	for _, a := range registeredAddons() {
		if g, ok := a.GrantKinds[kind]; ok {
			return g, true
		}
	}
	return GrantKind{}, false
}
