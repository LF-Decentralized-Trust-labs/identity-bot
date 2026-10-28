package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmachine"
	"identity-agent-core/asset"
	"identity-agent-core/sandbox"
	"identity-agent-core/screenview"

	"github.com/go-chi/chi/v5"
)

// An AI agent is given a new machine, made with only what its work needs.
//
// What an AI agent's machine must provide — a screen and browser, a code
// toolchain, Xcode — is kept on its record. It decides which machines can run
// it, and how a new one is built. What services it may use is its grant's to
// say, the same on any machine, and nothing here touches that.
//
// A provider is a live body whose AI agent's grant gives agent.machine.provide:
// a host that can make machines. It collects work, sealed and signed by its
// machine key, saying each time what the machines it makes can provide. When a
// person asks it for a machine for an AI agent, it makes one with what that AI
// agent needs, asks this Identity Agent for a one-time enrolment string, hands
// it to the new machine, and reports the six words the new machine shows. A
// person approves those words here, as for any machine: a provider can make a
// machine, never make one a body. Removing the machine asks its provider to
// destroy it.

// capabilityProvideMachines is the grant entry that makes a body a provider.
const capabilityProvideMachines = "agent.machine.provide"

var machineStoreOnce sync.Map

func (s *CoreServer) machines() *agentmachine.Store {
	dir, err := filepath.Abs(s.DataDir)
	if err != nil {
		dir = s.DataDir
	}
	v, _ := machineStoreOnce.LoadOrStore(dir, agentmachine.NewStore(dir))
	return v.(*agentmachine.Store)
}

func (s *CoreServer) mountMachineRoutes(r chi.Router) {
	// The owner's front end — the owner or a controller they authorised.
	r.Get("/mcp/agents/{id}/machine", s.handleGetAgentMachine)
	r.Put("/mcp/agents/{id}/machine", s.handleSetAgentMachine)
	r.Get("/mcp/agents/{id}/machines-that-fit", s.handleMachinesThatFit)
	r.Get("/mcp/agents/{id}/machine-requests", s.handleListMachineRequests)
	r.Post("/mcp/agents/{id}/machine-requests", s.handleAskForMachine)
	r.Delete("/mcp/agents/{id}/machine-requests/{rid}", s.handleCancelMachineRequest)
	// The provider's side: signed by its machine key, and taken only sealed.
	r.Get("/agent-host/machine-requests", s.handleProviderCollects)
	r.Post("/agent-host/machine-requests/{rid}", s.handleProviderReports)
	r.Post("/agent-host/machine-requests/{rid}/enrolment", s.handleProviderEnrolment)
}

// recordMachineEvent writes what happened to a machine request into the
// signed record, as the AI agent the machine is for.
func (s *CoreServer) recordMachineEvent(a asset.Asset, j agentmachine.Job, event, status, why string) {
	log.Printf("[machine] %s: %s for AI agent %s by %s (%s): %s", event, j.MachineName, a.PairwiseAID, j.ProviderName, status, why)
	if s.SandboxManager == nil {
		return
	}
	s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{
		CallerAID: a.PairwiseAID, DelegationChain: []string{a.PairwiseAID, a.DelegatorAID},
		Transport: "machine", WorkItem: j.ID, Reason: clampWhy(why),
	}, "agent.machine."+event, status)
}

// needsOf is what an AI agent's machine must provide.
func needsOf(a asset.Asset) []string {
	if a.AgentConfig == nil || a.AgentConfig.Machine == nil {
		return []string{}
	}
	return a.AgentConfig.Machine.Provides
}

func (s *CoreServer) handleGetAgentMachine(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"provides": needsOf(a), "known": agentmachine.Known})
}

func (s *CoreServer) handleSetAgentMachine(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, ok := s.aiAgentAsset(id)
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	var req asset.MachineNeeds
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		jsonError(w, "the request is unreadable", http.StatusBadRequest)
		return
	}
	provides, err := agentmachine.Needs(req.Provides)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	unlock := lockAgentGrant(a.ID)
	defer unlock()
	// Read again under the lock, so a configuration saved meanwhile is kept.
	if a, ok = s.aiAgentAsset(id); !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	cfg := asset.AgentConfig{Exposure: asset.Exposure{MCP: true}}
	if a.AgentConfig != nil {
		cfg = *a.AgentConfig
	}
	cfg.Machine = &asset.MachineNeeds{Provides: provides}
	if _, err := s.assetHandler.UpdateAgentConfig(a.ID, &cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[machine] what %s's machine must provide is now %v, set by %s", a.PairwiseAID, provides, whoDecided(r))
	writeJSONStatus(w, http.StatusOK, map[string]any{"provides": provides})
}

// machineProviderView is a provider as the person choosing a machine sees it.
type machineProviderView struct {
	Body     string   `json:"body"`
	Name     string   `json:"name"`
	Offers   []string `json:"offers"`
	Platform string   `json:"platform,omitempty"`
	Online   bool     `json:"online"`
	// Fits says it provides everything the AI agent's machine needs; Missing
	// is what it does not.
	Fits    bool     `json:"fits"`
	Missing []string `json:"missing,omitempty"`
}

// handleMachinesThatFit answers "where can this AI agent run?": every
// provider, live or not, saying whether it provides what the AI agent needs,
// and what a machine somebody sets up themselves must have.
func (s *CoreServer) handleMachinesThatFit(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	needs := needsOf(a)
	ps, err := s.machines().Providers()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	out := []machineProviderView{}
	for _, p := range ps {
		// Only a provider that is still a live body, whose AI agent may still
		// make machines, is offered.
		b, ok := s.providerStillGranted(p.Body)
		if !ok {
			continue
		}
		missing := agentmachine.Missing(needs, p.Offers)
		out = append(out, machineProviderView{Body: p.Body, Name: p.Name, Offers: p.Offers, Platform: b.Platform,
			Online: p.Online(now), Fits: len(missing) == 0, Missing: missing})
	}
	// A machine set up by hand runs whatever it was set up with; only Xcode
	// says which kind of computer it must be.
	yourself := "any computer, set up with what it needs, that can run agent-host"
	if slices.Contains(needs, agentmachine.Xcode) {
		yourself = "a Mac with Xcode installed, that can run agent-host"
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"needs": needs, "providers": out, "set_up_yourself": yourself,
	})
}

func (s *CoreServer) handleListMachineRequests(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"requests": s.machines().ForAgent(a.ID)})
}

// handleAskForMachine is a person asking a provider for a new machine for an
// AI agent, with what the AI agent's machine must provide now.
func (s *CoreServer) handleAskForMachine(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil || req.Provider == "" {
		jsonError(w, "say which provider makes the machine", http.StatusBadRequest)
		return
	}
	if s.agentStatus(a.PairwiseAID) == "revoked" || s.agentGrantLapsed(a.PairwiseAID) {
		jsonError(w, "this AI agent's grant is revoked or has lapsed, so no machine is made for it", http.StatusConflict)
		return
	}
	if _, ok := s.providerStillGranted(req.Provider); !ok {
		jsonError(w, "that provider is no longer a live machine here that may make machines", http.StatusNotFound)
		return
	}
	j, err := s.machines().Ask(a.ID, a.DisplayName, req.Provider, needsOf(a), whoDecided(r), time.Now())
	switch {
	case errors.Is(err, agentmachine.ErrOneAtATime):
		jsonError(w, "a machine is already being made for "+a.DisplayName+", or waits for its six words to be approved; finish or cancel it first", http.StatusConflict)
		return
	case errors.Is(err, agentmachine.ErrNotOffered):
		jsonError(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordMachineEvent(a, j, "requested", "pending", fmt.Sprintf("asked by %s, providing %v", j.RequestedBy, j.Needs))
	writeJSONStatus(w, http.StatusCreated, j)
}

// handleCancelMachineRequest stops a machine being made, or asks its provider
// to destroy one that was made but never became a body. A machine that is a
// live body is removed as a machine, which ends the body first.
func (s *CoreServer) handleCancelMachineRequest(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	// Under the same lock as approving, so a cancellation and an approval of
	// the same machine cannot both go through.
	unlock := lockAgentGrant(a.ID)
	defer unlock()
	j, ok := s.machines().Get(chi.URLParam(r, "rid"))
	if !ok || j.AgentAssetID != a.ID {
		jsonError(w, "no such machine request for this AI agent", http.StatusNotFound)
		return
	}
	b, hasBody := s.bodies().Get(j.Body)
	if hasBody && b.State == agentbody.StateActive {
		jsonError(w, "this machine is "+a.DisplayName+"'s live body; remove the machine, which also destroys it", http.StatusConflict)
		return
	}
	// A machine still waiting for its words to be approved can no longer be.
	if hasBody && b.State == agentbody.StatePending {
		if rejected, err := s.bodies().Decide(b.ID, a.ID, agentbody.StateRejected, whoDecided(r), "", time.Now()); err == nil {
			s.recordBodyEvent(a, rejected, "rejected", "denied", "its machine request was cancelled by "+whoDecided(r))
		}
	}
	j, err := s.forgetMachine(j)
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	s.recordMachineEvent(a, j, "cancelled", "ok", "cancelled by "+whoDecided(r))
	writeJSONStatus(w, http.StatusOK, j)
}

// endMachinesNoLongerWanted destroys machines nobody may use any more:
//
//   - every machine made for an AI agent whose grant is revoked or has
//     lapsed, or that is gone — its body ended first, and its body credential
//     withdrawn;
//   - a machine whose six words nobody approved before its enrolment window
//     ran out, or that was rejected or removed meanwhile;
//   - a machine whose enrolment string ran out before it asked at all.
//
// It also withdraws the credential of a body ended this way whose withdrawal
// could not be written before. It runs every minute, and in the background
// whenever a credential is revoked: never in the revoking request itself, which
// may hold an AI agent's lock this takes. One sweep runs at a time; one asked
// for while another runs runs again after it.
func (s *CoreServer) endMachinesNoLongerWanted(why string) {
	if s.assetHandler == nil {
		return
	}
	machineSweepAgain.Store(true)
	if !machineSweep.TryLock() {
		return
	}
	defer machineSweep.Unlock()
	for machineSweepAgain.Swap(false) {
		for _, j := range s.machines().Unfinished() {
			a, ok := s.aiAgentAsset(j.AgentAssetID)
			if s.whyEndMachine(a, ok, j, time.Now()) != "" {
				s.endMachine(a, ok, j, why)
			}
		}
		s.withdrawEndedBodies()
	}
}

var (
	machineSweep      sync.Mutex
	machineSweepAgain atomic.Bool
)

// sweepMachinesSoon runs the sweep in the background, for a caller that may
// hold an AI agent's lock.
func (s *CoreServer) sweepMachinesSoon(why string) {
	go s.endMachinesNoLongerWanted(why)
}

// whyEndMachine says why a request's machine should be destroyed now, or
// nothing if it should not.
func (s *CoreServer) whyEndMachine(a asset.Asset, haveAgent bool, j agentmachine.Job, now time.Time) string {
	switch {
	case !haveAgent:
		return "the AI agent it was made for is gone"
	case s.agentStatus(a.PairwiseAID) == "revoked":
		return "the AI agent it was made for is revoked"
	case s.agentGrantLapsed(a.PairwiseAID):
		return "the AI agent it was made for has a grant that lapsed"
	case j.State == agentmachine.StateEnrolling:
		// A request waiting for approval past its window was expired when the
		// body store was read.
		if b, ok := s.bodies().Get(j.Body); !ok || (b.State != agentbody.StatePending && b.State != agentbody.StateActive) {
			return "nobody approved its six words in time"
		}
	case j.State == agentmachine.StateMaking:
		if !j.EnrolmentGivenAt.IsZero() && now.Sub(j.EnrolmentGivenAt) > agentbody.EnrolmentWindow+time.Minute {
			return "its enrolment string ran out before it asked to become a body"
		}
	}
	return ""
}

// endMachine ends one request's machine: its body first — a live one ended and
// its credential withdrawn, one still waiting refused — then the request, which
// has its provider destroy the machine. The reason is decided again under the
// AI agent's lock, from the request and body as they are then, so an approval
// or a report that landed meanwhile is not undone.
func (s *CoreServer) endMachine(a asset.Asset, haveAgent bool, j agentmachine.Job, prompted string) {
	lockID := j.AgentAssetID
	unlock := lockAgentGrant(lockID)
	defer unlock()
	cur, ok := s.machines().Get(j.ID)
	if !ok {
		return
	}
	why := s.whyEndMachine(a, haveAgent, cur, time.Now())
	if why == "" || cur.Done() || cur.State == agentmachine.StateRemoving {
		return
	}
	why += " (" + prompted + ")"
	if b, ok := s.bodies().Get(cur.Body); ok {
		switch b.State {
		case agentbody.StateActive:
			var err error
			if haveAgent {
				b, err = s.endBinding(a, b, why)
			} else {
				b, err = s.bodies().Revoke(b.ID, cur.AgentAssetID, time.Now())
				s.screens().EndBody(b.Host, screenview.EndedBodyRemoved)
			}
			if err != nil {
				log.Printf("[machine] %s: its body could not be ended: %v", cur.MachineName, err)
				return
			}
			s.withdrawBodyCredential(b)
		case agentbody.StatePending:
			if rejected, err := s.bodies().Decide(b.ID, cur.AgentAssetID, agentbody.StateRejected, "the Identity Agent", "", time.Now()); err == nil && haveAgent {
				s.recordBodyEvent(a, rejected, "rejected", "denied", why)
			}
		}
	}
	// Ending its body may already have had its provider told to destroy it.
	if again, ok := s.machines().Get(cur.ID); ok && again.State == agentmachine.StateRemoving {
		return
	}
	cur, err := s.forgetMachine(cur)
	if err != nil {
		log.Printf("[machine] %s could not be ended: %v", cur.MachineName, err)
		return
	}
	if haveAgent {
		s.recordMachineEvent(a, cur, "removing", "ok", why)
	} else {
		log.Printf("[machine] %s: its provider is to destroy it: %s", cur.MachineName, why)
	}
}

// withdrawBodyCredential writes a body's revocation to the registry. A failure
// is left for the next sweep, which tries again.
func (s *CoreServer) withdrawBodyCredential(b agentbody.Binding) {
	rec, _ := s.DataStore.GetCredential(b.CredentialSAID)
	if rec == nil || rec.Status == "revoked" || rec.Status == credentialStatusWithdrawing {
		return
	}
	if _, _, err := s.withdrawCredential(rec); err != nil {
		log.Printf("[machine] the credential of body %s could not be withdrawn yet, the next sweep tries again: %v", b.ID, err)
	}
}

// withdrawEndedBodies retries the withdrawal of the credential of every body a
// machine request ended whose withdrawal did not go through.
func (s *CoreServer) withdrawEndedBodies() {
	for _, j := range s.machines().Ended() {
		if b, ok := s.bodies().Get(j.Body); ok && b.State == agentbody.StateRevoked {
			s.withdrawBodyCredential(b)
		}
	}
}

// forgetMachine has a request's provider destroy its machine, and voids the
// enrolment string it was given if no machine used it.
func (s *CoreServer) forgetMachine(j agentmachine.Job) (agentmachine.Job, error) {
	if j.Body == "" && j.EnrolmentDigest != "" {
		if err := s.bodies().VoidDigest(j.EnrolmentDigest); err != nil {
			log.Printf("[machine] %s: its unused enrolment string could not be voided: %v", j.MachineName, err)
		}
	}
	return s.machines().Remove(j.ID, time.Now())
}

// providerStillGranted is a provider's body, if it is still live and its AI
// agent still holds an unrevoked grant to make machines.
func (s *CoreServer) providerStillGranted(body string) (agentbody.Binding, bool) {
	b, ok := s.bodies().Get(body)
	if !ok || b.State != agentbody.StateActive {
		return b, false
	}
	pa, ok := s.aiAgentAsset(b.AgentAssetID)
	if !ok || s.agentStatus(pa.PairwiseAID) == "revoked" || s.agentGrantLapsed(pa.PairwiseAID) ||
		!slices.Contains(pa.Capabilities, capabilityProvideMachines) {
		return b, false
	}
	return b, true
}

// machineGone is called when a body ends: a machine a provider made for it is
// to be destroyed, and a provider that ended makes no more.
func (s *CoreServer) machineGone(b agentbody.Binding) {
	if j, ok := s.machines().ForBody(b.ID); ok {
		if j, err := s.machines().Remove(j.ID, time.Now()); err == nil {
			if a, ok := s.aiAgentAsset(j.AgentAssetID); ok {
				s.recordMachineEvent(a, j, "removing", "ok", "its body was removed, so its provider is to destroy it")
			}
		}
	}
	_ = s.machines().Forget(b.ID)
}

// theProvider admits a request from a live body whose AI agent may make
// machines, after the one check.
func (s *CoreServer) theProvider(w http.ResponseWriter, r *http.Request) (agentbody.Binding, asset.Asset, bool) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return b, a, false
	}
	refuse := func(why string) (agentbody.Binding, asset.Asset, bool) {
		s.recordLentEvent(a, cc, "agent.machine.provide", "denied", why)
		jsonError(w, why, http.StatusForbidden)
		return b, a, false
	}
	if err := s.mayBeLent(a, cc, "work making machines"); err != nil {
		return refuse(err.Error())
	}
	if s.SandboxManager == nil {
		return refuse("this Identity Agent has no gateway to check the grant against")
	}
	if ok, why := s.SandboxManager.MayServe(cc, capabilityProvideMachines); !ok {
		return refuse(why)
	}
	return b, a, true
}

// providerJob is a request as its provider is given it.
type providerJob struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	MachineName string   `json:"machine_name"`
	AgentName   string   `json:"agent_name"`
	Needs       []string `json:"needs"`
}

// handleProviderCollects is a provider saying what it offers and collecting
// work, waiting a while for some when asked to.
func (s *CoreServer) handleProviderCollects(w http.ResponseWriter, r *http.Request) {
	b, a, ok := s.theProvider(w, r)
	if !ok {
		return
	}
	var offers []string
	if o := r.URL.Query().Get("offers"); o != "" {
		offers = strings.Split(o, ",")
	}
	store := s.machines()
	if err := store.Seen(agentmachine.Provider{Body: b.ID, Name: a.DisplayName, Offers: offers,
		Platform: b.Platform, LastSeen: time.Now().UTC()}); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Subscribed before reading, so work asked for between the read and the
	// wait still ends the wait.
	changed := store.Changed()
	jobs := store.ForProvider(b.ID)
	if len(jobs) == 0 && r.URL.Query().Get("wait") != "" {
		select {
		case <-changed:
		case <-time.After(conversationWait):
		case <-r.Context().Done():
		}
		jobs = store.ForProvider(b.ID)
	}
	out := []providerJob{}
	for _, j := range jobs {
		out = append(out, providerJob{ID: j.ID, State: j.State, MachineName: j.MachineName, AgentName: j.AgentName, Needs: j.Needs})
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"requests": out})
}

// handleProviderReports is a provider saying how a machine is going. Words it
// reports are matched to the machine waiting for approval that shows them, so
// a person sees which request that machine came from.
func (s *CoreServer) handleProviderReports(w http.ResponseWriter, r *http.Request) {
	b, _, ok := s.theProvider(w, r)
	if !ok {
		return
	}
	var req struct {
		State  string   `json:"state"`
		Detail string   `json:"detail"`
		Words  []string `json:"words"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		jsonError(w, "the report is unreadable", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "rid")
	before, ok := s.machines().Get(id)
	if !ok || before.Provider != b.ID {
		jsonError(w, "that machine is not one this provider was asked to make", http.StatusNotFound)
		return
	}
	a, ok := s.aiAgentAsset(before.AgentAssetID)
	if !ok {
		jsonError(w, "the AI agent this machine was for is gone", http.StatusGone)
		return
	}
	// The machine that shows these words must have asked to become this AI
	// agent's body since its enrolment string was given for this request, so
	// a provider cannot claim a machine that was already there. A person may
	// have approved it already, before the provider's report arrived.
	var bound string
	boundActive := false
	if req.State == agentmachine.StateEnrolling {
		want := strings.Join(req.Words, " ")
		for _, c := range s.bodies().ForAgent(a.ID) {
			if before.EnrolmentGivenAt.IsZero() || c.EnrolledAt.Before(before.EnrolmentGivenAt) {
				continue
			}
			if (c.State == agentbody.StatePending || c.State == agentbody.StateActive) && strings.Join(c.Words, " ") == want {
				if other, ok := s.machines().ForBody(c.ID); ok && other.ID != id {
					continue
				}
				bound, boundActive = c.ID, c.State == agentbody.StateActive
			}
		}
		if bound == "" {
			jsonError(w, "no machine waiting for approval as "+a.DisplayName+" shows those six words", http.StatusConflict)
			return
		}
	}
	j, err := s.machines().Report(id, b.ID, req.State, clampWhy(req.Detail), req.Words, time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if bound != "" {
		if j, err = s.machines().Bound(id, bound, time.Now()); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if j.State != before.State {
		status := "ok"
		if j.State == agentmachine.StateFailed {
			status = "error"
		}
		s.recordMachineEvent(a, j, j.State, status, firstNonEmptyString(j.Detail, "reported by "+j.ProviderName))
	}
	if boundActive {
		s.machines().Approved(bound, time.Now())
		j, _ = s.machines().Get(id)
		s.recordMachineEvent(a, j, j.State, "ok", "a person had already approved its six words")
	}
	writeJSONStatus(w, http.StatusOK, j)
}

// handleProviderEnrolment gives a provider the one-time enrolment string for a
// machine it is making: the same string a person would be given, good once,
// for that AI agent only. The machine still waits for a person to approve its
// words. theProvider admits only a request the sealed transport opened, and
// its answer goes back sealed to the same body's keys, as a lent token does.
func (s *CoreServer) handleProviderEnrolment(w http.ResponseWriter, r *http.Request) {
	b, _, ok := s.theProvider(w, r)
	if !ok {
		return
	}
	j, ok := s.machines().Get(chi.URLParam(r, "rid"))
	if !ok || j.Provider != b.ID {
		jsonError(w, "that machine is not one this provider was asked to make", http.StatusNotFound)
		return
	}
	a, ok := s.aiAgentAsset(j.AgentAssetID)
	if !ok {
		jsonError(w, "the AI agent this machine was for is gone", http.StatusGone)
		return
	}
	if s.agentStatus(a.PairwiseAID) == "revoked" || s.agentGrantLapsed(a.PairwiseAID) {
		jsonError(w, "the AI agent this machine was for is revoked, or its grant has lapsed", http.StatusConflict)
		return
	}
	// Recorded before it is made, under the store's lock, so a second ask —
	// or one racing a cancellation — gets nothing.
	j, err := s.machines().GiveEnrolment(j.ID, b.ID, time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	str, expires, err := s.enrolmentFor(r, a)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Which string it was, kept only as a digest, so ending the request can
	// void exactly that string and no other.
	if e, perr := agentbody.ParseEnrolment(str); perr == nil {
		if j, err = s.machines().SetEnrolmentDigest(j.ID, agentbody.SecretDigest(e.Secret), time.Now()); err != nil {
			log.Printf("[machine] %s: which enrolment string it was given could not be kept: %v", j.MachineName, err)
		}
	}
	s.recordMachineEvent(a, j, "enrolment", "ok", "a one-time enrolment string was given to "+j.ProviderName+" for "+j.MachineName)
	writeJSONStatus(w, http.StatusCreated, map[string]any{"enrolment": str, "expires_at": expires})
}
