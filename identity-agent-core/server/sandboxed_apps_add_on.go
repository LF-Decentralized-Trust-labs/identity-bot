package server

import "github.com/go-chi/chi/v5"

// The sandboxed-apps add-on: installing and running apps, the capability
// gateway and registry, the activity log's routes, and the trace viewer.
//
// It registers through the same seam an add-on in a package of its own uses
// (add_ons.go), so the core names none of it. It still lives in this package
// because the sandbox manager it drives also keeps the activity log the core
// writes to, and the capability gateway AI agents call through, so the core
// still makes the manager. Until those have a home of their own it registers
// from here, and every build includes it.
func init() {
	RegisterAddon(Addon{
		Name:   "sandboxed apps",
		Routes: func(s *CoreServer, r chi.Router) { s.sandboxRoutes(r) },
		RootRoutes: func(s *CoreServer, r chi.Router) {
			s.traceRoutes(r)
			// The display reverse proxy: intercepts container API calls to
			// serve from ai-memory.db.
			r.HandleFunc("/apps/{app_id}/*", s.handleAppDisplayProxy)
		},
	})
}
