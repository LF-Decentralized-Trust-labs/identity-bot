// Package sandboxedapps is the sandboxed-apps add-on: installing and running
// apps in containers, the capability gateway and registry that apps and AI
// agents call capabilities through, the display proxy, and the trace viewer.
//
// An app includes it by importing it; it registers with the server when it
// starts (sandboxed_apps_add_on.go). The core names none of it: the phone core
// and the free desktop app never link it.
package sandboxedapps

import (
	"identity-agent-core/internal/addonhost"
	"identity-agent-core/sandbox"
	"identity-agent-core/server"
)

// sandboxedApps is the add-on on one server: the server, the handle on the
// parts of it that are not its public API, and what the add-on keeps for it.
type sandboxedApps struct {
	*server.CoreServer
	addonhost.Host
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
	h := addonhost.Of(s)
	st := h.AddonState(appsStateKey{}, func() any { return new(appsState) }).(*appsState)
	return &sandboxedApps{CoreServer: s, Host: h, appsState: st}
}

// hostOf is the handle on s.
func hostOf(s *server.CoreServer) addonhost.Host { return addonhost.Of(s) }

// helpers are the core's helpers that need no server.
var helpers = addonhost.Shared()

// Manager is the sandbox manager on s: what runs its apps and the capability
// gateway AI agents call through. Nil where s was made without this add-on,
// or the manager could not be made.
func Manager(s *server.CoreServer) *sandbox.Manager { return of(s).SandboxManager }

// UseManager makes m the sandbox manager on s, for a server not made by
// server.New, as tests make one.
func UseManager(s *server.CoreServer, m *sandbox.Manager) { of(s).SandboxManager = m }
