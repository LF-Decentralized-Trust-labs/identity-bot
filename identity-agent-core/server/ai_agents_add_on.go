package server

import (
	"identity-agent-core/authorisation"
	"identity-agent-core/conversation"
	"identity-agent-core/didcomm"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"net/http"

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
		// Half the time a quiet conversation takes to close, so its last
		// entry is anchored before it closes.
		TickAtMost: conversation.IdleClose / 2,
		// Conversations are anchored with the log.
		AnchoredChains: func(s *CoreServer) (AnchoredChains, error) {
			st, err := s.conversations()
			if err != nil {
				return nil, err
			}
			return conversationChains{st}, nil
		},
		ConversationParty: func(s *CoreServer, id, party string) (bool, bool, error) {
			return s.conversationHeldWith(id, party)
		},
		ResolveBearerToken: func(s *CoreServer, r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
			return s.callerFromToken(token, cc)
		},
		ResolveBodySignature: func(s *CoreServer, r *http.Request, cc permission.CallerContext) (permission.CallerContext, bool) {
			return s.callerFromBody(r, cc)
		},
		EnrichProvenCaller: func(s *CoreServer, caller *permission.CallerContext) bool {
			return s.enrichCallerFromIdentity(caller)
		},
		SealedSender:     func(s *CoreServer, kid string) (didcomm.DID, bool) { return s.bodySealingFrom(kid) },
		PublicRoutes:     aiAgentPublicRoutes,
		ScopedRoutes:     aiAgentScopedRoutes,
		ScopedPrefixes:   aiAgentScopedPrefixes,
		SessionForbidden: aiAgentSessionForbidden,
		GrantKinds: map[*schemas.AssetGrant]GrantKind{
			schemas.AIAgentGrant: {
				StillWhatItGrants: func(s *CoreServer, shown *authorisation.ToSign) error {
					return s.aiAgentGrantStillWhatItGrants(shown)
				},
				Arrived:     func(s *CoreServer, holder, said string) { s.aiAgentGrantArrived(holder, said) },
				Awaiting:    func(s *CoreServer) []map[string]any { return s.agentsAwaitingGrants() },
				AwaitingKey: "agents",
			},
		},
		CredentialWithdrawn: func(s *CoreServer, why string) {
			// What was lent on the strength of a grant or a body's credential
			// is withdrawn once the credential is.
			s.endLendsNoLongerGranted(why)
			// And a machine made for an AI agent that may no longer act is
			// destroyed.
			s.sweepMachinesSoon(why)
		},
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

// conversationChains are the conversations, as chains the record's anchoring
// fixes.
type conversationChains struct{ st *conversation.Store }

func (c conversationChains) Heads() (map[string]ChainHead, error) {
	heads, err := c.st.Heads()
	if err != nil {
		return nil, err
	}
	out := make(map[string]ChainHead, len(heads))
	for id, h := range heads {
		out[id] = ChainHead{Seq: h.Seq, Hash: h.HeadHash}
	}
	return out, nil
}

func (c conversationChains) EntryHash(id string, seq int) (string, error) {
	e, err := c.st.EntryAt(id, seq)
	if err != nil {
		return "", err
	}
	return e.Hash, nil
}

// aiAgentPublicRoutes are the AI-agent routes open to anyone. Keyed by
// "METHOD /chi/pattern"; each entry states why.
var aiAgentPublicRoutes = map[string]string{
	// A machine asking to become an AI agent's body has no standing yet: it
	// presents a one-time secret and signs with the key it offers, and nothing
	// is granted until a person compares six words and approves. The status
	// route answers only the machine that signs for it.
	"POST /api/agent-host/enrol":  "a machine asking, with a one-time secret, to become an AI agent's body",
	"GET /api/agent-host/binding": "a machine asking, signed by its own key, whether it was approved",
	// An AI agent's body sending and collecting messages. Each handler admits
	// only a request the sealed transport opened from a live body's keys and
	// that the body signed with its machine key; the gateway checks inside
	// decide what that AI agent may say and to whom.
	"POST /api/agent-host/messages":           "an AI agent's body speaking in a conversation, sealed and signed by its key",
	"GET /api/agent-host/inbox":               "an AI agent's body collecting its messages, sealed and signed by its key",
	"GET /api/agent-host/agents":              "an AI agent's body asking which AI agents it may message, sealed and signed",
	"GET /api/agent-host/conversations/{cid}": "an AI agent's body reading a conversation it is in, sealed and signed",
	// A body borrowing its AI agent's brain sign-in for one run, renewing it
	// and giving it back. Each handler admits only a sealed request a live
	// body signed, and the sign-in travels back sealed to that body's keys.
	"POST /api/agent-host/brain-sign-in":        "an AI agent's body borrowing its brain's sign-in for one run, sealed and signed",
	"POST /api/agent-host/brain-sign-in/renew":  "an AI agent's body keeping a borrowed sign-in while its run goes on, sealed and signed",
	"POST /api/agent-host/brain-sign-in/return": "an AI agent's body giving back a borrowed sign-in, sealed and signed",
	// A body whose brain's key stays here making that brain's model calls
	// through here, reading each answer as it arrives and stopping one its
	// brain gave up on. Each handler admits only a sealed request a live body
	// signed, and only for a run that holds an open lease on the sign-in.
	"POST /api/agent-host/model-calls":          "an AI agent's body making its brain's model call through the Identity Agent, which adds the key, sealed and signed",
	"GET /api/agent-host/model-calls/{call}":    "an AI agent's body reading the answer to its brain's model call as it arrives, sealed and signed",
	"DELETE /api/agent-host/model-calls/{call}": "an AI agent's body stopping a model call its brain gave up on, sealed and signed",
	// A body saying whether it has a screen and waiting to be watched, and
	// sending pictures of it while somebody does. Each handler admits only a
	// sealed request a live body signed, and a picture is kept only for a
	// viewing of that body.
	routeBodyScreen:      "an AI agent's body saying what screen it has and waiting to be watched, sealed and signed",
	routeBodyScreenFrame: "an AI agent's body sending a picture of its screen while watched, sealed and signed",
	// A body borrowing GitHub access for one run, and giving it back. Each
	// handler admits only a sealed request a live body signed; the token
	// travels back sealed to that body's keys.
	"POST /api/agent-host/github":        "an AI agent's body borrowing GitHub access for one run, sealed and signed",
	"POST /api/agent-host/github/return": "an AI agent's body giving back the GitHub access it borrowed, sealed and signed",
	// A body that makes machines for other AI agents collecting that work and
	// reporting on it. Each handler admits only a sealed request a live body
	// signed, whose AI agent's grant lets it make machines; an enrolment
	// string travels back sealed to that body's keys.
	"GET /api/agent-host/machine-requests":                  "a body that makes machines collecting the machines it is asked for, sealed and signed",
	"POST /api/agent-host/machine-requests/{rid}":           "a body that makes machines saying how one is going, sealed and signed",
	"POST /api/agent-host/machine-requests/{rid}/enrolment": "a body that makes machines asking for the enrolment string of one it is making, sealed and signed",
}

// aiAgentScopedRoutes are the AI-agent routes open to a caller holding
// capability scopes. The handler enforces the specific scope.
var aiAgentScopedRoutes = map[string]string{
	"POST /api/mcp": "MCP clients act under a minted token with explicit scopes",
}

// aiAgentScopedPrefixes are the container-facing LLM namespace. A sandboxed
// app reaches it from the container network, so it is neither the owner nor a
// token holder; the handler behind it is its own gate (LLM egress is
// structurally denied except the static model catalogue).
var aiAgentScopedPrefixes = []string{"/sandbox/llm/v1"}

// aiAgentSessionForbidden are the AI-agent routes a browser session must not
// take, and why.
var aiAgentSessionForbidden = map[string]string{
	// --- minting durable credentials for AI agents ---
	//
	// Provisioning an agent and minting its token both create a bearer credential
	// that outlives the session: the session can be ended, but a token it minted
	// keeps working. A session is a convenience the owner grants for a while; it
	// must not be able to leave behind permanent agent access. The owner's app on a
	// device that holds the key does this.
	"POST /api/mcp/agents": "provisioning an agent mints a durable token that outlives the session that made it",
	"POST /api/mcp/tokens": "minting a token creates durable bearer access that outlives the session that made it",
	// Re-issuing an agent's grant is the one place its ceiling can be changed
	// after it exists. A session that could reach it could widen what an agent
	// may do and leave that standing after the session ends — the same durable
	// grant as minting, by a different door.
	"PUT /api/mcp/agents/{id}/capabilities": "re-issuing an agent's grant can widen what it may do, and that outlives the session that changed it",
	// An AI agent's configuration says where its model is reached and with which
	// stored key, and whether it must run attested. A session that changed those
	// could point the AI agent at an endpoint it controls, and the change would
	// outlive the session.
	"PATCH /api/mcp/agents/{id}":     "changing where an AI agent's model is reached, and with which key, outlives the session that changed it",
	"PUT /api/mcp/agents/{id}/brain": "changing which model an AI agent uses, and what runs it, outlives the session that changed it",
	// The same, by the brain's sign-in: its key, its account, and a local
	// model server's address.
	"PUT /api/mcp/agents/{id}/brain-sign-in":    "signing an AI agent's brain in, with which key and at which address, outlives the session that did it",
	"DELETE /api/mcp/agents/{id}/brain-sign-in": "removing an AI agent's sign-in outlives the session that removed it",
	// Revoking an AI agent cannot be undone: it is never granted anything
	// again, and its machines are ended.
	"POST /api/mcp/agents/{id}/revoke": "revoking an AI agent cannot be undone, and outlives the session that did it",
	// Checking a sign-in sends a request from this Identity Agent to an address
	// the caller names. Only the owner's own app may ask for that, so a session
	// cannot use this Identity Agent to reach into the network it sits on.
	"POST /api/mcp/brain-sign-in/test":               "checking a sign-in makes this Identity Agent reach an address the caller names",
	"POST /api/mcp/agents/{id}/brain-sign-in/test":   "checking a sign-in makes this Identity Agent reach the address it names",
	"POST /api/mcp/brain-sign-in/models":             "listing a sign-in's models makes this Identity Agent reach an address the caller names",
	"POST /api/mcp/agents/{id}/brain-sign-in/models": "listing a sign-in's models makes this Identity Agent reach the address it names",
	// The organisation's GitHub App: its private key lets this Identity Agent
	// make tokens for the organisation's repositories, so connecting one,
	// disconnecting it and using it are for the owner's own app. Granting an
	// AI agent repositories re-issues its grant, which outlives the session.
	"PUT /api/github":                 "connecting a GitHub App keeps a key that makes tokens for the organisation's repositories, after the session ends",
	"DELETE /api/github":              "disconnecting the GitHub App ends every AI agent's access to the organisation's repositories",
	"GET /api/github/repositories":    "listing the repositories makes this Identity Agent use the GitHub App's key",
	"PUT /api/mcp/agents/{id}/github": "granting an AI agent repositories re-issues its grant, which outlives the session that changed it",
	// An enrolment string, and approving a body, let a machine speak as an AI
	// agent from then on — standing access that outlives the session.
	"POST /api/mcp/agents/{id}/body-enrolment":       "an enrolment string lets a machine ask to speak as an AI agent, after the session that made it ends",
	"POST /api/mcp/agents/{id}/bodies/{bid}/approve": "approving a body lets a machine speak as an AI agent, after the session that approved it ends",
	"POST /api/mcp/agents/{id}/bodies/{bid}/reject":  "rejecting a body hands back a fresh enrolment string, which outlives the session that asked for it",
	// Watching an AI agent's screen is open to a session; taking control of it
	// is not. Whoever clicks and types on the AI agent's machine can do what
	// that machine can, which is more than a convenience granted for a while
	// should carry.
	routeScreenControl: "taking control of an AI agent's screen lets whoever holds the session click and type on its machine",
	routeScreenInput:   "clicking and typing on an AI agent's machine is done from a device that can take control, not a session",
}
