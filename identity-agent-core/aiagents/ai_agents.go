// Package aiagents is the AI-agent add-on: AI agents, their bodies and
// machines, their conversations and the record they are anchored in, what is
// lent to them, and the MCP endpoint they call capabilities through.
//
// An app includes it by importing it; it registers with the server when it
// starts (ai_agents_add_on.go). The core names none of it: the phone core and
// the free desktop app never link it.
package aiagents

import (
	"sync"
	"sync/atomic"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/internal/addonhost"
	"identity-agent-core/lending"
	"identity-agent-core/server"
)

// aiAgents is the add-on on one server: the server, the handle on the parts
// of it that are not its public API, and what the add-on keeps for it.
type aiAgents struct {
	*server.CoreServer
	addonhost.Host
	*aiState
}

// aiState is what the add-on keeps for one server.
type aiState struct {
	// brainChecker, when set, replaces the providers a brain's sign-in is
	// checked against (brain_sign_in_check.go); tests stand them up locally.
	brainChecker *brainsignin.Checker
	// githubAPI, when set, replaces GitHub's API address (github_access.go);
	// tests stand GitHub up locally. Nothing a request sends can set it.
	githubAPI string
	// lendLedger is the one record of everything lent to AI agents' bodies —
	// brains' sign-ins and services' access alike (lends.go), made once.
	lendsOnce         sync.Once
	lendLedger        *lending.Ledger
	legacyLeasesMu    sync.Mutex
	legacyLeasesMoved atomic.Bool
	// modelCalls are the model calls under way for bodies whose brain's key
	// stays here (model_calls_through_the_identity_agent.go).
	modelCalls modelCallTable
}

// aiStateKey is where a server keeps the add-on's state.
type aiStateKey struct{}

// of is the add-on on s.
func of(s *server.CoreServer) *aiAgents {
	h := addonhost.Of(s)
	st := h.AddonState(aiStateKey{}, func() any { return new(aiState) }).(*aiState)
	return &aiAgents{CoreServer: s, Host: h, aiState: st}
}

// hostOf is the handle on s.
func hostOf(s *server.CoreServer) addonhost.Host { return addonhost.Of(s) }

// helpers are the core's helpers that need no server.
var helpers = addonhost.Shared()

// AgentConfigByAID is a provisioned AI agent's stored configuration on s, or
// nil where there is none (aiAgents.AgentConfigByAID).
func AgentConfigByAID(s *server.CoreServer, aid string) *asset.AgentConfig {
	return of(s).AgentConfigByAID(aid)
}
