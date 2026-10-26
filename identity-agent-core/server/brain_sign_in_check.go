package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// Checking a sign-in before it is kept, choosing which brains to offer, and
// keeping a sign-in its program refreshed during a run.

// brainCheck is the checker of sign-ins: one request to the provider, through
// this Identity Agent's governed way out — the same policy check, proxy log
// and trace as its own model calls — without the vault adding a key of its
// own, and following no redirect, so the key goes only where it is checked.
func (s *CoreServer) brainCheck() (brainsignin.Checker, error) {
	if s.SandboxManager == nil {
		return brainsignin.Checker{}, errNoVault
	}
	client := brainsignin.NoRedirects()
	send := func(ctx context.Context, req *http.Request) (*http.Response, error) {
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
	s.recordBrainEvent(a, sandbox.CallerContext{}, "checked", status, "checked by "+
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
// may stop working once they have — in place of the one lent, and of every copy
// of it another AI agent shares. It is kept only while the sign-in is still the
// one lent and still the same account, so a sign-in replaced during the run, or
// a body sending some other account's, changes nothing. It says what it did,
// for the record.
func (s *CoreServer) keepRefreshedSignIn(a asset.Asset, lease brainsignin.Lease, content string) string {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	vault, err := s.brainVault()
	if err != nil {
		return "the refreshed sign-in was not kept: " + err.Error()
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	switch {
	case err != nil:
		return "the refreshed sign-in was not kept: " + err.Error()
	case !had:
		return "the refreshed sign-in was not kept: the sign-in was removed during the run"
	case rec.Kind != brainsignin.KindSubscription || (rec.Provider != brainsignin.Codex && rec.Provider != brainsignin.Grok):
		return "the refreshed sign-in was not kept: this kind of sign-in is not refreshed by its program"
	case lease.Lent == "" || brainsignin.Fingerprint(rec.Provider, rec.Secret) != lease.Lent:
		return "the refreshed sign-in was not kept: the sign-in was replaced during the run"
	case rec.Secret == content:
		return "the sign-in was unchanged"
	}
	fresh := rec
	fresh.Secret = content
	if err := fresh.Check(); err != nil {
		return "the refreshed sign-in was not kept: " + err.Error()
	}
	fresh.Identify()
	if fresh.AccountID != rec.AccountID {
		return "the refreshed sign-in was not kept: it is for another account"
	}
	n := 0
	for _, k := range s.keptBrainSignIns() {
		if k.rec.Provider != rec.Provider || brainsignin.Fingerprint(k.rec.Provider, k.rec.Secret) != lease.Lent {
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
		return "the refreshed sign-in could not be kept"
	}
	if n == 1 {
		return "the sign-in its program refreshed was kept"
	}
	return "the sign-in its program refreshed was kept, for every AI agent sharing it"
}
