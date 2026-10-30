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
		ID:   "sandboxed_apps",
		Name: "sandboxed apps",
		// Installing software on a computer is for the app running on it:
		// no machine acting for the owner may do it, at any score.
		ControllerOwnerOnly: map[string]string{
			"POST /api/sandbox/podman/setup": "installing software on a computer is done by the app running on it",
		},
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
		// The display proxy and the model proxy are reached from the
		// container network, so their caller is neither the owner nor a token
		// holder; the handler behind each is its own gate (the model proxy's
		// egress is structurally denied except the static model catalogue).
		ScopedPrefixes: []string{"/apps/{app_id}/", "/sandbox/llm/v1"},
		Routes: func(s *server.CoreServer, r chi.Router) {
			of(s).sandboxRoutes(r)
			// The conversations and per-app settings sandboxed apps keep in
			// ai-memory.db.
			of(s).aiMemoryRoutes(r)
		},
		RootRoutes: func(s *server.CoreServer, r chi.Router) {
			of(s).traceRoutes(r)
			// The model proxy a sandboxed app calls, and the model keys it
			// uses.
			of(s).llmRoutes(r)
			// The display reverse proxy: intercepts container API calls to
			// serve from ai-memory.db.
			r.HandleFunc("/apps/{app_id}/*", of(s).handleAppDisplayProxy)
		},
	})
}

// makeManager makes the sandbox manager and starts it. Failing to is not
// fatal: the server runs without sandboxed apps.
func (s *sandboxedApps) makeManager() {
	// The manager writes to the server's activity log, signed. Without it,
	// the manager would open a second handle on the same database that
	// nothing signs, so no manager is made: the server runs without
	// sandboxed apps, as when the manager cannot be made.
	if s.ActivityLog == nil {
		log.Printf("[identity-agent-core] Sandbox manager not made: the activity log is not open")
		return
	}
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
