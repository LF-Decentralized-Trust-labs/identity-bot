package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"identity-agent-core/sandbox"
)

// The master orchestrator — one agent that coordinates a workforce of other agents,
// entirely through the governed endpoint.
//
// An orchestrator agent submits a plan of steps; each step names a worker agent and a
// capability. For every step the endpoint invokes the capability UNDER THE WORKER'S OWN
// AUTHORITY (its delegated AID + capability grant), re-running the full access model +
// scope ceiling per step — orchestration never bypasses governance. Every step is
// signed into the invocation log with the worker as CallerAID and the orchestrator as
// OrchestratedBy, all sharing one correlation id and anchored to a dispatch event, so a
// whole multi-agent workflow is one verifiable trace: "who directed it, who executed
// each step, under whose authority, when."
//
// Authority to orchestrate is itself a capability: the orchestrator agent must hold the
// agent.orchestrate meta-capability in its grant (the local owner may orchestrate
// unconditionally). Defense in depth: O must be allowed to orchestrate AND each worker
// must independently be allowed to run its step.
const orchestrateCapabilityID = "agent.orchestrate"

type orchestrateStep struct {
	Worker       string          `json:"worker"`        // worker agent AID or display name
	CapabilityID string          `json:"capability_id"` // capability the worker should run
	Args         json.RawMessage `json:"args,omitempty"`
}

type orchestrateStepResult struct {
	Worker       string `json:"worker"`
	WorkerAID    string `json:"worker_aid,omitempty"`
	CapabilityID string `json:"capability_id"`
	Status       string `json:"status"` // ok | denied | error
	Detail       string `json:"detail,omitempty"`
}

// handleOrchestrate runs a plan of worker steps as the master orchestrator.
func (s *CoreServer) handleOrchestrate(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Goal  string            `json:"goal,omitempty"`
		Steps []orchestrateStep `json:"steps"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err := json.Unmarshal(body, &req); err != nil || len(req.Steps) == 0 {
		jsonError(w, "a non-empty steps array is required", http.StatusBadRequest)
		return
	}

	// Authenticate the orchestrator (same identity-first path as /mcp).
	caller := s.resolveCaller(r)
	if err := s.verifyRequestEnvelope(r, "orchestrate", body, &caller); err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.enrichCallerFromIdentity(&caller)

	// Authority to orchestrate: the owner may (locally, or a signed owner request on
	// rented hardware); any other caller must hold the agent.orchestrate
	// meta-capability in its grant.
	if !s.isOwner(r) && !containsString(caller.Scopes, orchestrateCapabilityID) {
		jsonError(w, "caller is not authorized to orchestrate (needs the "+orchestrateCapabilityID+" capability)", http.StatusForbidden)
		return
	}

	corr := caller.CorrelationID
	if corr == "" {
		corr = requestCorrelationID(r)
		caller.CorrelationID = corr
	}

	// Anchor the workflow with a signed dispatch event; worker steps reference its id.
	dispatchCaller := caller
	dispatchCaller.Transport = "orchestrate"
	parentID := s.SandboxManager.RecordGovernedEvent(dispatchCaller, orchestrateCapabilityID, "ok")
	parentRef := ""
	if parentID > 0 {
		parentRef = fmt.Sprintf("%d", parentID)
	}

	results := make([]orchestrateStepResult, 0, len(req.Steps))
	for _, step := range req.Steps {
		res := orchestrateStepResult{Worker: step.Worker, CapabilityID: step.CapabilityID}
		worker := s.findAgentAsset(step.Worker)
		if worker == nil {
			res.Status = "error"
			res.Detail = "no provisioned agent matches " + step.Worker
			results = append(results, res)
			continue
		}
		res.WorkerAID = worker.PairwiseAID
		wc := s.callerContextForAgent(worker, corr, caller.CallerAID, parentRef)
		args := []byte(step.Args)
		if len(args) == 0 {
			args = []byte("{}")
		}
		invRes, err := s.SandboxManager.InvokeCapability(r.Context(), wc, step.CapabilityID, args)
		switch {
		case err != nil && errors.Is(err, sandbox.ErrDenied):
			res.Status = "denied"
			res.Detail = err.Error()
		case err != nil:
			res.Status = "error"
			res.Detail = err.Error()
		default:
			res.Status = "ok"
			if invRes != nil && invRes.Status >= 400 {
				res.Status = "error"
			}
		}
		results = append(results, res)
	}

	jsonResponse(w, map[string]any{
		"goal":              req.Goal,
		"orchestrator_aid":  caller.CallerAID,
		"correlation_id":    corr,
		"dispatch_event_id": parentID,
		"steps":             results,
		"note":              "each step executed under its worker's own grant; the full workflow is queryable at /api/activity/invocations?correlation_id=" + corr,
	})
}

// callerContextForAgent builds a fully-scoped worker caller for a provisioned agent —
// its delegated AID, delegation lineage, and credential-proven capability ceiling —
// stamped with the orchestration correlation, the orchestrator that directed it, and
// the dispatch event it descends from.
func (s *CoreServer) callerContextForAgent(agent *assetAgentRef, corr, orchestratedBy, parentEventID string) sandbox.CallerContext {
	cc := sandbox.CallerContext{
		Remote:          true,
		CallerAID:       agent.PairwiseAID,
		DelegationChain: []string{agent.PairwiseAID},
		CorrelationID:   corr,
		Transport:       "orchestrate",
		AuthLevel:       "orchestrated",
		OrchestratedBy:  orchestratedBy,
		ParentEventID:   parentEventID,
		Scopes:          append([]string(nil), agent.Capabilities...),
	}
	if agent.DelegatorAID != "" {
		cc.DelegationChain = append(cc.DelegationChain, agent.DelegatorAID)
	}
	if grant := s.findCapabilityGrant(agent.PairwiseAID); grant != nil {
		s.applyGrantScopes(mcpToken{
			AgentAID:     agent.PairwiseAID,
			DelegatorAID: agent.DelegatorAID,
			GrantSAID:    grant.SAID,
			Scopes:       agent.Capabilities,
		}, &cc)
	}
	return cc
}

// findAgentAsset resolves a provisioned ai_agent asset by its delegated AID or, failing
// that, its display name.
func (s *CoreServer) findAgentAsset(nameOrAID string) *assetAgentRef {
	if a := s.findAgentAssetByAID(nameOrAID); a != nil {
		return a
	}
	if s.assetHandler == nil || nameOrAID == "" {
		return nil
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.AssetType == "ai_agent" && a.DisplayName == nameOrAID {
			return &assetAgentRef{ID: a.ID, PairwiseAID: a.PairwiseAID, DelegatorAID: a.DelegatorAID, Capabilities: a.Capabilities}
		}
	}
	return nil
}
