package server

import (
	"context"
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

	// EveryTick runs on each tick of the loop every Identity Agent runs
	// (what_runs_every_tick.go), before the core's own work for that tick.
	EveryTick func(s *CoreServer)
	// TickAtMost, when set, is the longest the add-on can wait between two
	// ticks; the loop ticks at least that often.
	TickAtMost time.Duration

	// CredentialWithdrawn runs when a credential this identity issued is
	// withdrawn or revoked, so that whatever the add-on gave on the strength
	// of it ends now rather than when it would have lapsed. why says which.
	CredentialWithdrawn func(s *CoreServer, why string)

	// ReloadKeyLogs hands the KERI engine any key log the add-on writes to
	// besides the identity's own: at start, and whenever the core reloads
	// the identity's.
	ReloadKeyLogs func(s *CoreServer)
	// WitnessesCoverDelegates reports whether the identity's witnesses are
	// asked to witness identities delegated from it, as well as the identity.
	WitnessesCoverDelegates func(s *CoreServer) bool
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

// addonsTick runs every add-on's work for this tick.
func (s *CoreServer) addonsTick() {
	for _, a := range registeredAddons() {
		if a.EveryTick != nil {
			a.EveryTick(s)
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

// reloadAddonKeyLogs has every add-on hand the engine the key logs it writes.
func (s *CoreServer) reloadAddonKeyLogs() {
	for _, a := range registeredAddons() {
		if a.ReloadKeyLogs != nil {
			a.ReloadKeyLogs(s)
		}
	}
}

// witnessesCoverDelegates reports whether any add-on has the identity's
// witnesses witness the identities delegated from it.
func (s *CoreServer) witnessesCoverDelegates() bool {
	for _, a := range registeredAddons() {
		if a.WitnessesCoverDelegates != nil && a.WitnessesCoverDelegates(s) {
			return true
		}
	}
	return false
}
