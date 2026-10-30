// Package sandboxedapps is the sandboxed-apps add-on: installing and running
// apps in containers, the capability gateway and registry that apps and AI
// agents call capabilities through, the display proxy, the model proxy and
// model keys sandboxed apps use, the conversations they keep (ai-memory.db),
// and the trace viewer.
//
// An app includes it by importing it; it registers with the server when it
// starts (sandboxed_apps_add_on.go). The core names none of it, and an app
// that does not import it links none of it.
//
// The AI-agent add-on (aiagents) depends on this one: AI agents call
// capabilities through its gateway. This package depends on no other add-on.
package sandboxedapps

import (
	"identity-agent-core/addon"
	"identity-agent-core/internal/addontest"
	"identity-agent-core/sandbox"
	"identity-agent-core/server"
)

// sandboxedApps is the add-on on one server: the server, the handle on the
// parts of it that are not its public API, and what the add-on keeps for it.
type sandboxedApps struct {
	*server.CoreServer
	addon.Host
	*appsState
}

// appsState is what the add-on keeps for one server.
type appsState struct {
	// SandboxManager runs the apps and the capability gateway. Nil until the
	// server is made, and where it could not be.
	SandboxManager *sandbox.Manager
}

// appsStateKey is where a server keeps the add-on's state.
type appsStateKey struct{}

// of is the add-on on s.
func of(s *server.CoreServer) *sandboxedApps {
	h := addon.Of(s)
	st := h.AddonState(appsStateKey{}, func() any { return new(appsState) }).(*appsState)
	return &sandboxedApps{CoreServer: s, Host: h, appsState: st}
}

// helpers are the core's helpers that need no server.
var helpers = addon.Shared()

// Manager is the sandbox manager on s: what runs its apps and the capability
// gateway AI agents call through. Nil where s was made without this add-on,
// or the manager could not be made.
func Manager(s *server.CoreServer) *sandbox.Manager { return of(s).SandboxManager }

func init() {
	// What the other add-ons' tests use to give a server they make by hand a
	// sandbox manager of their own.
	addontest.UseSandboxManager = func(s *server.CoreServer, m *sandbox.Manager) { of(s).SandboxManager = m }
}
