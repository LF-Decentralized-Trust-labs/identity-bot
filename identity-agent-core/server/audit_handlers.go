package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
)

// The gateway has always written a signed record of every governed invocation, and
// there has never been a way to read one back. Everything the log knows — who called,
// under whose authority, what it was for, why it was refused, what it cost — was
// reachable only by opening the database by hand.
//
// That gap is not cosmetic. A record nobody can read does not constrain anything: it
// cannot be reviewed, an anomaly in it cannot be noticed, and the guarantee it is
// supposed to provide ("you can always see what your Identity Agent did") is a claim
// rather than a fact. These endpoints make the record legible to the one party who is
// entitled to all of it.
//
// OWNER ONLY, deliberately. The log holds every caller's activity, the delegation
// lineage behind each call, and a preview of the arguments. Any caller that could read
// it would learn what every other caller has been doing, so a capability ceiling is the
// wrong instrument here — this is not a capability to be granted, it is the owner's
// view of their own agent. A remote caller gets 403 whatever it holds.

// The path is /api/activity, and the list endpoint REPLACES an earlier handler that
// served the same route. That one gated on isOwner alone — the hole described above,
// which would have let any AI agent on this machine read every other caller's
// activity. It also offered three filters, no bound on the result set, and no way to
// tell a full page from the whole log. Replacing it rather than registering beside it
// is deliberate: two handlers on one path leaves the hole open at whichever one the
// router happens to resolve to.
func (s *CoreServer) auditRoutes(r chi.Router) {
	r.Get("/activity/invocations", s.handleListInvocations)
	r.Get("/activity/invocations/{id}", s.handleGetInvocation)
	r.Get("/activity/summary", s.handleAuditSummary)
	r.Get("/activity/chain", s.handleVerifyAuditChain)
}

// requireOwner is the single gate for every audit read. Written once rather than
// repeated per handler, so a new endpoint cannot be added without it.
//
// isOwner alone is NOT sufficient here, and the reason is easy to miss: it treats any
// loopback request without forwarding headers as the owner — and every AI agent
// running on this machine also calls from loopback. Gating on isOwner alone would let
// any agent holding any token read the entire log, including every other caller's
// activity and argument previews. That is the opposite of what this endpoint is for.
//
// So a presented bearer token disqualifies a request from the loopback path: a token
// is what a delegated caller carries, and a delegated caller is not the owner. Such a
// request may still pass by proving the owner's signature, which is the one path that
// actually demonstrates who is asking rather than where from.
func (s *CoreServer) requireOwner(w http.ResponseWriter, r *http.Request) bool {
	if bearerFrom(r) != "" {
		if s.verifyOwnerSignature(r) == nil {
			return true
		}
		jsonError(w, "the invocation log is readable by the owner only; a delegated "+
			"caller cannot read the record of other callers", http.StatusForbidden)
		return false
	}
	if s.isOwner(r) {
		return true
	}
	jsonError(w, "the invocation log is readable by the owner only", http.StatusForbidden)
	return false
}

func (s *CoreServer) auditStore(w http.ResponseWriter) *sandbox.SandboxStore {
	if s.SandboxManager == nil {
		jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return nil
	}
	st := s.SandboxManager.Store()
	if st == nil {
		jsonError(w, "audit store unavailable", http.StatusServiceUnavailable)
		return nil
	}
	return st
}

// handleListInvocations returns the most recent events, newest first, narrowed by any
// combination of the supported filters.
func (s *CoreServer) handleListInvocations(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	st := s.auditStore(w)
	if st == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	f := sandbox.InvocationEventFilter{
		CapabilityID:  q.Get("capability_id"),
		CorrelationID: q.Get("correlation_id"),
		CallerAID:     q.Get("caller_aid"),
		WorkItem:      q.Get("work_item"),
		ResultStatus:  normaliseStatus(q.Get("status")),
		ExecutorType:  q.Get("executor_type"),
		Since:         q.Get("since"),
		Until:         q.Get("until"),
		Limit:         limit,
	}
	events, err := st.QueryInvocationEvents(f)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"events": events,
		"count":  len(events),
		// Say plainly that a page is a page. A reader who assumes a truncated list is
		// the whole log draws confident conclusions from a fraction of it.
		"truncated": len(events) >= f.EffectiveLimit(),
		"limit":     f.EffectiveLimit(),
	})
}

// handleGetInvocation returns one event in full, with its authority line resolved into
// something a person can read.
func (s *CoreServer) handleGetInvocation(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	st := s.auditStore(w)
	if st == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid event id", http.StatusBadRequest)
		return
	}
	ev, err := st.GetInvocationEvent(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"event":     ev,
		"authority": s.describeAuthority(ev),
	})
}

// authorityStep is one link in the answer to "under whose authority did this happen".
type authorityStep struct {
	AID   string `json:"aid"`
	Role  string `json:"role"`            // caller | delegator | root
	Name  string `json:"name,omitempty"`  // display name, when the AID is a known asset
	Owner string `json:"owner,omitempty"` // for an AI agent, who is answerable for it
}

// describeAuthority turns the stored delegation chain into named steps. The chain is
// already recorded root-last; this only resolves the names, because a column of raw
// AIDs is a proof rather than an explanation, and a person auditing their own agent
// needs both.
//
// Names are looked up locally and are best-effort: an unknown AID keeps its identifier
// and gains no name, which is honest. The AIDs themselves are the record — a name is a
// convenience layered on top and is never what anything is checked against.
func (s *CoreServer) describeAuthority(ev sandbox.InvocationEvent) []authorityStep {
	chain := ev.DelegationChain
	if len(chain) == 0 && ev.CallerAID != "" {
		chain = []string{ev.CallerAID}
	}
	out := make([]authorityStep, 0, len(chain))
	for i, aid := range chain {
		step := authorityStep{AID: aid, Role: "delegator"}
		switch {
		case i == 0:
			step.Role = "caller"
		case i == len(chain)-1:
			step.Role = "root"
		}
		if name, owner := s.describeAID(aid); name != "" {
			step.Name, step.Owner = name, owner
		}
		out = append(out, step)
	}
	return out
}

// describeAID resolves an AID to a display name, and for an AI agent to the AID of
// whoever is answerable for it. Empty when the AID is not a known local asset.
func (s *CoreServer) describeAID(aid string) (name, owner string) {
	if s.assetHandler == nil || aid == "" {
		return "", ""
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.PairwiseAID != aid {
			continue
		}
		name = a.DisplayName
		if name == "" {
			name = a.ID
		}
		// An AI agent is not a sovereign actor — it acts under whoever authorized it,
		// and that party is who a reader actually wants named.
		if a.AssetType == "ai_agent" {
			owner = a.DelegatorAID
		}
		return name, owner
	}
	return "", ""
}

// handleAuditSummary aggregates the log into the shape a console leads with: how much
// happened, how much of it failed, and what it cost.
func (s *CoreServer) handleAuditSummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	st := s.auditStore(w)
	if st == nil {
		return
	}
	sum, err := st.SummariseInvocations(r.URL.Query().Get("since"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, sum)
}

// handleVerifyAuditChain walks the log and reports whether it has been tampered with.
//
// This is the endpoint that makes the chain worth having. A chain nobody ever checks
// detects nothing; the check has to be something a person can actually run.
func (s *CoreServer) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) {
		return
	}
	st := s.auditStore(w)
	if st == nil {
		return
	}
	brokenAt, err := st.VerifyChain()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"intact": brokenAt == 0}
	if brokenAt != 0 {
		resp["broken_at"] = brokenAt
		resp["detail"] = "The record at this id does not follow from the one before it. " +
			"A record has been deleted, reordered or edited since it was written."
	}
	writeJSON(w, resp)
}

// normaliseStatus keeps the status filter to the values the log actually stores, so a
// typo returns an obvious empty result rather than silently matching nothing while
// looking like a legitimate query.
func normaliseStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ok", "denied", "error":
		return strings.ToLower(strings.TrimSpace(v))
	}
	return ""
}
