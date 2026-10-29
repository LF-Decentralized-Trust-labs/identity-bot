package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/lending"
	"identity-agent-core/permission"

	"github.com/go-chi/chi/v5"
)

// Checking a sign-in before it is kept, choosing which brains to offer, and
// keeping a sign-in its program refreshed during a run.

// brainCheck is the checker of sign-ins: one request to the provider, through
// this Identity Agent's governed way out — the same policy check, including
// any domain the owner blocked, proxy log and trace as its own model calls —
// without the vault adding a key of its own, and following no redirect, so
// the key goes only where it is checked. A model server is reached only at the
// addresses its name had when checked (brainsignin.ModelServerAddress).
func (s *CoreServer) brainCheck() (brainsignin.Checker, error) {
	if s.SandboxManager == nil {
		return brainsignin.Checker{}, errNoVault
	}
	send := func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error) {
		return s.SandboxManager.MakeTrackedRequestAsGiven(ctx, req, client)
	}
	if s.brainChecker != nil {
		c := *s.brainChecker
		c.Send = send
		return c, nil
	}
	return brainsignin.NewChecker(send), nil
}

// handleTestBrainSignIn checks a sign-in before it is kept, and keeps nothing.
func (s *CoreServer) handleTestBrainSignIn(w http.ResponseWriter, r *http.Request) {
	var q brainSignInRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil {
		jsonError(w, "the sign-in is unreadable", http.StatusBadRequest)
		return
	}
	rec, status, err := s.signInAsked(q, nil, time.Now().UTC())
	if err != nil {
		jsonError(w, err.Error(), status)
		return
	}
	s.answerCheck(w, r.Context(), rec)
}

// handleTestKeptBrainSignIn checks the sign-in kept for an AI agent.
func (s *CoreServer) handleTestKeptBrainSignIn(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	vault, err := s.brainVault()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !had {
		jsonError(w, "this AI agent has no sign-in to check", http.StatusNotFound)
		return
	}
	res := s.answerCheck(w, r.Context(), rec)
	status := "ok"
	if !res.OK {
		status = "failed"
	}
	s.recordBrainEvent(a, permission.CallerContext{}, "checked", status, "checked by "+
		firstNonEmptyString(madeByController(r), "the owner")+": "+firstNonEmptyString(res.Why, "it works"))
}

func (s *CoreServer) answerCheck(w http.ResponseWriter, ctx context.Context, rec brainsignin.Record) brainsignin.CheckResult {
	c, err := s.brainCheck()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return brainsignin.CheckResult{}
	}
	res := c.Check(ctx, rec)
	if res.Account == "" && res.OK {
		res.Account = rec.Account
	}
	out := map[string]any{"ok": res.OK, "account": res.Account, "checked": res.Checked, "why": res.Why,
		"expires_at": rec.ExpiresAt}
	writeJSONStatus(w, http.StatusOK, out)
	return res
}

// handleBrainChoices says which brains a body can run from a sign-in, so a
// screen offers only those.
func (s *CoreServer) handleBrainChoices(w http.ResponseWriter, _ *http.Request) {
	writeJSONStatus(w, http.StatusOK, map[string]any{"choices": brainsignin.Runnable()})
}

// handleListBrainSignIns lists every AI agent's sign-in, without secrets, so
// a screen can offer to use one an AI agent already has.
func (s *CoreServer) handleListBrainSignIns(w http.ResponseWriter, _ *http.Request) {
	if _, err := s.brainVault(); err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	kept := s.keptBrainSignIns()
	out := make([]map[string]any, 0, len(kept))
	for _, k := range kept {
		v := s.brainSignInViewAmong(k.asset.ID, k.rec, kept)
		v["agent_id"], v["agent_name"] = k.asset.ID, k.asset.DisplayName
		out = append(out, v)
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"sign_ins": out})
}

// refreshMu keeps one refreshed sign-in at a time.
var refreshMu sync.Mutex

// keepRefreshedSignIn keeps the sign-in file a run's program refreshed — Codex
// and Grok renew their own tokens while they run, and the token they were lent
// may stop working once they have — in place of the one lent.
//
// It is kept only while the borrowing AI agent's sign-in is still the one
// lent, and only when the refreshed file names the same account and the same
// person as the lent one (brainsignin.SameSignInAs), so a sign-in replaced
// during the run, or a body sending some other account's, changes nothing.
// It is written to the borrowing AI agent's sign-in, and to every other AI
// agent's that holds the very sign-in lent — one shared by naming the
// borrowing AI agent (same_as) is a copy of it — since the refresh retired
// that one for all of them. Another sign-in of the same account, made
// separately, is left alone. It says what it did, for the record.
func (s *CoreServer) keepRefreshedSignIn(a asset.Asset, lease lending.Lend, content string) (why string, tryAgain bool) {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	vault, err := s.brainVaultWritable()
	if err != nil {
		return "the refreshed sign-in could not be kept yet: " + err.Error(), true
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	switch {
	case err != nil:
		return "the refreshed sign-in could not be kept yet: " + err.Error(), true
	case !had:
		return "the refreshed sign-in was not kept: the sign-in was removed during the run", false
	case !brainsignin.RefreshesItself(rec.Kind, rec.Provider):
		return "the refreshed sign-in was not kept: this kind of sign-in is not refreshed by its program", false
	case lease.Lent == "" || brainsignin.Fingerprint(rec.Provider, rec.Secret) != lease.Lent:
		return "the refreshed sign-in was not kept: the sign-in was replaced during the run", false
	case rec.Secret == content:
		return "the sign-in was unchanged", false
	}
	if err := brainsignin.SameSignInAs(rec.Provider, rec.Secret, content); err != nil {
		return "the refreshed sign-in was not kept: " + err.Error(), false
	}
	fresh := rec
	fresh.Secret = content
	if err := fresh.Check(); err != nil {
		return "the refreshed sign-in was not kept: " + err.Error(), false
	}
	fresh.Identify()
	// The borrowing AI agent's own sign-in first: if that cannot be written,
	// nothing else is.
	if err := vault.SetBrainSignIn(brainsignin.Ref(a.ID), fresh); err != nil {
		return "the refreshed sign-in could not be kept yet: " + err.Error(), true
	}
	n := 0
	for _, k := range s.keptBrainSignIns() {
		if k.asset.ID == a.ID || k.rec.Provider != rec.Provider || brainsignin.Fingerprint(k.rec.Provider, k.rec.Secret) != lease.Lent {
			continue
		}
		upd := k.rec
		upd.Secret, upd.AccountID = fresh.Secret, fresh.AccountID
		if err := vault.SetBrainSignIn(brainsignin.Ref(k.asset.ID), upd); err != nil {
			log.Printf("[brain] AI agent %s: the refreshed sign-in could not be kept: %v", k.asset.PairwiseAID, err)
			continue
		}
		n++
	}
	if n == 0 {
		return "the sign-in its program refreshed was kept", false
	}
	return "the sign-in its program refreshed was kept, for every AI agent sharing it", false
}

// handleBrainSignInModels lists the models a sign-in may call, before it is
// kept, and keeps nothing.
func (s *CoreServer) handleBrainSignInModels(w http.ResponseWriter, r *http.Request) {
	var q brainSignInRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil {
		jsonError(w, "the sign-in is unreadable", http.StatusBadRequest)
		return
	}
	rec, status, err := s.signInAsked(q, nil, time.Now().UTC())
	if err != nil {
		jsonError(w, err.Error(), status)
		return
	}
	s.answerModels(w, r.Context(), rec)
}

// handleKeptBrainSignInModels lists the models the sign-in kept for an AI
// agent may call.
func (s *CoreServer) handleKeptBrainSignInModels(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	vault, err := s.brainVault()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !had {
		jsonError(w, "this AI agent has no sign-in to list models for", http.StatusNotFound)
		return
	}
	s.answerModels(w, r.Context(), rec)
}

func (s *CoreServer) answerModels(w http.ResponseWriter, ctx context.Context, rec brainsignin.Record) {
	c, err := s.brainCheck()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, c.Models(ctx, rec))
}

// brainChoice is a change to which AI an AI agent thinks with: any field left
// out keeps what it is.
type brainChoice struct {
	Kind     *string `json:"kind"`
	Provider *string `json:"provider"`
	Model    *string `json:"model"`
	Program  *string `json:"program"`
}

// handleChooseBrain changes which model an AI agent uses, and what runs it,
// and nothing else of its configuration: not its sign-in, which is kept
// apart, nor its role, instructions or machine. The program must fit the
// sign-in it has.
func (s *CoreServer) handleChooseBrain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.refuseIfRevoked(w, id) {
		return
	}
	a, ok := s.aiAgentAsset(id)
	if !ok || a.AgentConfig == nil {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	var q brainChoice
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&q); err != nil {
		jsonError(w, "the choice is unreadable", http.StatusBadRequest)
		return
	}
	cfg := *a.AgentConfig
	b := cfg.Brain
	if q.Provider != nil {
		b.Provider = brainsignin.NormaliseProvider(*q.Provider)
	}
	if q.Kind != nil {
		b.Kind = brainsignin.NormaliseKind(*q.Kind, b.Provider)
	}
	if q.Model != nil {
		m := strings.TrimSpace(*q.Model)
		if len(m) > 200 || !printableName(m) && m != "" {
			jsonError(w, "nothing was changed: a model's name is one short line", http.StatusBadRequest)
			return
		}
		b.Model = m
	}
	if q.Program != nil {
		b.Program = strings.TrimSpace(*q.Program)
		if len(b.Program) > 40 || !printableName(b.Program) {
			jsonError(w, "nothing was changed: that is not a program a brain is run by", http.StatusBadRequest)
			return
		}
	}
	if err := brainProgramFits(b); err != nil {
		jsonError(w, "nothing was changed: "+err.Error(), http.StatusBadRequest)
		return
	}
	vault, err := s.brainVault()
	if err != nil {
		jsonError(w, "nothing was changed: the AI agent's sign-in cannot be read now", http.StatusServiceUnavailable)
		return
	}
	kept, had, err := vault.BrainSignIn(brainsignin.Ref(id))
	if err != nil {
		jsonError(w, "nothing was changed: the AI agent's sign-in cannot be read now", http.StatusServiceUnavailable)
		return
	}
	{
		if had {
			// The AI it thinks with is the one it is signed in with: a choice
			// naming another would point the kept key at the wrong provider.
			if (q.Kind != nil || q.Provider != nil) && (b.Provider != kept.Provider || b.Kind != kept.Kind) {
				jsonError(w, fmt.Sprintf("nothing was changed: this AI agent is signed in with %s %s; sign it in with "+
					"the other AI first", kept.Kind, kept.Provider), http.StatusBadRequest)
				return
			}
			if err := brainsignin.ProgramFits(b.Program, kept.Kind, kept.Provider); err != nil {
				jsonError(w, "nothing was changed: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	cfg.Brain = b
	updated, err := s.assetHandler.UpdateAgentConfig(id, &cfg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordLentEvent(*updated, permission.CallerContext{}, "agent.brain.chosen", "ok", fmt.Sprintf("%s %s, model %s, run by %s, chosen by %s",
		b.Kind, b.Provider, firstNonEmptyString(printable(b.Model, 128), "its program's own"),
		firstNonEmptyString(b.Program, "its provider's program"), firstNonEmptyString(madeByController(r), "the owner")))
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"asset_id":     updated.ID,
		"agent_config": updated.AgentConfig.ForDisplay(s.isVaultEntry),
	})
}
