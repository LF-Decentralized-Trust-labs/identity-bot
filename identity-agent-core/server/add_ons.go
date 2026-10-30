package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Add-ons.
//
// An add-on is a part of the Identity Agent that not every Identity Agent
// needs: AI agents, sandboxed apps, an organisation's own features. Whatever
// the core links is carried by every app built on it, on every phone, so the
// core holds only what every Identity Agent needs and the rest comes as
// add-ons, each included only by an app that chooses it.
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
	// Name says which add-on, in logs.
	Name string

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
)

// RegisterAddon includes an add-on in every Identity Agent this process
// starts. An add-on's package calls it from its init, so importing the
// package is what includes it. Add-ons are asked in the order they were
// registered.
func RegisterAddon(a Addon) {
	addonsMu.Lock()
	defer addonsMu.Unlock()
	addons = append(addons, a)
}

// registeredAddons are the add-ons included, in the order they registered.
func registeredAddons() []Addon {
	addonsMu.Lock()
	defer addonsMu.Unlock()
	return append([]Addon(nil), addons...)
}

// mountAddonRoutes adds every add-on's routes under /api.
func (s *CoreServer) mountAddonRoutes(r chi.Router) {
	for _, a := range registeredAddons() {
		if a.Routes != nil {
			a.Routes(s, r)
		}
	}
}

// mountAddonRootRoutes adds every add-on's routes outside /api.
func (s *CoreServer) mountAddonRootRoutes(r chi.Router) {
	for _, a := range registeredAddons() {
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
