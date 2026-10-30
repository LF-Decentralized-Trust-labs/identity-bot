package server

import (
	"errors"
	"log"

	"identity-agent-core/conversation"

	"github.com/go-chi/chi/v5"
)

// The AI-agent add-on: AI agents, their bodies and machines, their
// conversations, what is lent to them, and the record's anchoring.
//
// It registers through the same seam an add-on in a package of its own uses
// (add_ons.go), so the core names none of it. It still lives in this package
// because the core's authorisation consults it directly when it resolves a
// caller: an AI agent's token or body, the routes a body may call, the
// signers a request names. Until that has a seam of its own it registers from
// here, and every build includes it.
func init() {
	RegisterAddon(Addon{
		Name: "AI agents",
		Routes: func(s *CoreServer, r chi.Router) {
			s.aiAgentRoutes(r)
			s.aiMemoryRoutes(r)
		},
		RootRoutes: func(s *CoreServer, r chi.Router) { s.llmRoutes(r) },
		// A key an earlier version kept on an AI agent's record moves into
		// the vault, where every other sign-in is kept.
		Prepare: func(s *CoreServer) { s.moveBrainSecretsIntoTheVault() },
		Run:     func(s *CoreServer, stop <-chan struct{}) { s.keepSweepingLends(stop) },
		EveryTick: func(s *CoreServer) {
			if _, err := s.anchorRecord(); err != nil && !errors.Is(err, errKeyElsewhere) {
				log.Printf("[record] anchoring: %v", err)
			}
		},
		// Half the time a quiet conversation takes to close, so its last
		// entry is anchored before it closes.
		TickAtMost: conversation.IdleClose / 2,
		CredentialWithdrawn: func(s *CoreServer, why string) {
			// What was lent on the strength of a grant or a body's credential
			// is withdrawn once the credential is.
			s.endLendsNoLongerGranted(why)
			// And a machine made for an AI agent that may no longer act is
			// destroyed.
			s.sweepMachinesSoon(why)
		},
		ReloadKeyLogs:           func(s *CoreServer) { s.reloadRecordIdentity() },
		WitnessesCoverDelegates: func(s *CoreServer) bool { return s.anchorsItsRecord() },
	})
}

// aiAgentRoutes serves making and managing AI agents, their tokens, the MCP
// endpoint they call capabilities through, and the routes their bodies call.
func (s *CoreServer) aiAgentRoutes(r chi.Router) {
	r.Post("/mcp", s.handleMCP)
	r.Post("/mcp/agents", s.handleProvisionAgent)
	r.Get("/mcp/agents", s.handleListAgents)
	r.Patch("/mcp/agents/{id}", s.handleUpdateAgentConfig)
	r.Put("/mcp/agents/{id}/capabilities", s.handleSetAgentCapabilities)
	r.Group(func(r chi.Router) {
		r.Use(s.onlyWhileHoldingAIAgents)
		s.mountBodyRoutes(r)
		s.mountConversationRoutes(r)
		s.mountBrainSignInRoutes(r)
		s.mountScreenRoutes(r)
		s.mountGitHubRoutes(r)
		s.mountMachineRoutes(r)
	})
	r.Post("/mcp/agents/{id}/revoke", s.handleRevokeAIAgent)
	r.Post("/mcp/tokens", s.handleMintMCPToken)
	r.Get("/mcp/tokens", s.handleListMCPTokens)
	r.Delete("/mcp/tokens/{name}", s.handleRevokeMCPToken)
	r.Get("/endpoint/health", s.handleEndpointHealth)
}
