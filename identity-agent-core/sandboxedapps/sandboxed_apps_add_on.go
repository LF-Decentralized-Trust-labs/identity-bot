package sandboxedapps

import (
	"log"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
	"identity-agent-core/server"
)

// The sandboxed-apps add-on registers through the server's add-on seam
// (server.RegisterAddon), so the core names none of it: an app that does not
// import this package runs no sandbox manager and serves none of its routes.
func init() {
	server.RegisterAddon(server.Addon{
		Name: "sandboxed apps",
		// The sandbox manager is made with the server, once its activity
		// log and vault are, and stopped before the log closes.
		Prepare: func(s *server.CoreServer) { of(s).makeManager() },
		Stop: func(s *server.CoreServer) {
			if m := Manager(s); m != nil {
				m.Stop()
			}
		},
		ScopedRoutes: map[string]string{
			"POST /api/capabilities/{id}/invoke": "capability invocation is gated by the grant, not by locality",
		},
		// The display proxy is reached from the container network, so its
		// caller is neither the owner nor a token holder; the handler behind
		// it is its own gate.
		ScopedPrefixes: []string{"/apps/{app_id}/"},
		Routes:         func(s *server.CoreServer, r chi.Router) { of(s).sandboxRoutes(r) },
		RootRoutes: func(s *server.CoreServer, r chi.Router) {
			of(s).traceRoutes(r)
			// The display reverse proxy: intercepts container API calls to
			// serve from ai-memory.db.
			r.HandleFunc("/apps/{app_id}/*", of(s).handleAppDisplayProxy)
		},
	})
}

// makeManager makes the sandbox manager and starts it. Failing to is not
// fatal: the server runs without sandboxed apps.
func (s *sandboxedApps) makeManager() {
	// Plug-in manifests directory. Defaults to ./manifests (relative to the
	// working dir); MANIFESTS_DIR overrides it so a service-managed agent (whose
	// working dir it doesn't control) can point at an absolute plug-in location.
	manifestsDir := filepath.Join(".", "manifests")
	if d := os.Getenv("MANIFESTS_DIR"); d != "" {
		manifestsDir = d
	}
	sbxMgr, err := sandbox.NewManager(sandbox.ManagerConfig{
		DataDir:      s.DataDir,
		ManifestsDir: manifestsDir,
		Log:          s.ActivityLog,
		Vault:        s.Vault,
	})
	if err != nil {
		log.Printf("[identity-agent-core] Sandbox manager init failed (non-fatal): %v", err)
		return
	}
	s.SandboxManager = sbxMgr
	// The endpoint uses the structural authorizer by default (host-control never
	// remote; a remote caller must hold the capability in its grant). An overlay
	// may inject a richer authorizer via SetAuthorizer.
	if startErr := s.SandboxManager.Start(); startErr != nil {
		log.Printf("[identity-agent-core] Sandbox manager start failed (non-fatal): %v", startErr)
	}
}
