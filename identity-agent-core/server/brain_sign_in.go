package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// An AI agent's brain is signed in once, here, and lent to a body per run.
//
// The sign-in — an API key, a subscription's sign-in token, or a model
// server's address — is kept in this Identity Agent's vault, never on the
// AI agent's record and never on a machine. When a body starts a run it asks
// for the sign-in, signed by its machine key and sealed to this Identity
// Agent; the answer is sealed back to the keys the body enrolled with, so
// nothing between the two reads it. The body puts it in the brain's
// environment for that run alone and returns it when the run ends.
//
// A subscription is one person's, so a sign-in carries a cap on how many runs
// may hold it at once across every machine. A run holds its place by a lease
// that lapses unless renewed, so a machine that crashed mid-run frees it.
//
// Every lend, return and refusal is written to the signed governance record,
// without the secret.

func (s *CoreServer) mountBrainSignInRoutes(r chi.Router) {
	// The owner's front end — the owner or a controller they authorised.
	r.Get("/mcp/agents/{id}/brain-sign-in", s.handleGetBrainSignIn)
	r.Put("/mcp/agents/{id}/brain-sign-in", s.handleSetBrainSignIn)
	r.Delete("/mcp/agents/{id}/brain-sign-in", s.handleRemoveBrainSignIn)
	// The body's side: signed by its machine key, and taken only sealed.
	r.Post("/agent-host/brain-sign-in", s.handleBodyBorrowsSignIn)
	r.Post("/agent-host/brain-sign-in/renew", s.handleBodyRenewsSignIn)
	r.Post("/agent-host/brain-sign-in/return", s.handleBodyReturnsSignIn)
}

// errNoVault is an Identity Agent with nowhere safe to keep a sign-in.
var errNoVault = errors.New("this Identity Agent has no credential vault, so it cannot keep a sign-in safely")

// brainVault is where sign-ins are kept.
func (s *CoreServer) brainVault() (*sandbox.Manager, error) {
	if s.SandboxManager == nil {
		return nil, errNoVault
	}
	return s.SandboxManager, nil
}

func (s *CoreServer) brainLeases() *brainsignin.Leases { return brainsignin.LeasesIn(s.DataDir) }

// brainVaultWritable is the vault, when a sign-in can be kept in it now.
// Asked before anything else is written, so a locked vault changes nothing.
func (s *CoreServer) brainVaultWritable() (*sandbox.Manager, error) {
	vault, err := s.brainVault()
	if err != nil {
		return nil, err
	}
	if err := vault.VaultWritable(); err != nil {
		return nil, err
	}
	return vault, nil
}

// recordLapsedLeases writes every lease that lapsed unrenewed into the
// record, once each.
func (s *CoreServer) recordLapsedLeases() {
	lapsed, err := s.brainLeases().Lapsed(time.Now().UTC())
	if err != nil {
		log.Printf("[brain] %v", err)
	}
	for _, x := range lapsed {
		if xa, ok := s.aiAgentAsset(x.Agent); ok {
			s.recordBrainEvent(xa, sandbox.CallerContext{Transport: "body", BodyHost: x.Host},
				"lapsed", "ok", "lease "+x.ID+" was not renewed, so its run's place was freed")
		}
	}
}

// mayBorrow says why an AI agent's body may not be lent its sign-in: an AI
// agent whose grant is revoked or lapsed is lent nothing, though its body
// still stands.
func (s *CoreServer) mayBorrow(a asset.Asset, cc sandbox.CallerContext) error {
	if s.agentStatus(a.PairwiseAID) == "revoked" {
		return errors.New("this AI agent's grant is revoked, so its sign-in is not lent")
	}
	if s.agentGrantLapsed(a.PairwiseAID) {
		return errors.New("this AI agent's grant has lapsed, so its sign-in is not lent")
	}
	if cc.NoScopesBecause != "" {
		return errors.New("this AI agent may do nothing now (" + cc.NoScopesBecause + "), so its sign-in is not lent")
	}
	return nil
}

// brainSignInRequest is a sign-in as a screen sends it.
type brainSignInRequest struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Account  string `json:"account,omitempty"`
	// Secret is the key or sign-in token. Never returned.
	Secret    string     `json:"secret,omitempty"`
	Endpoint  string     `json:"endpoint,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// MaxConcurrentRuns is the cap on simultaneous runs; absent keeps the
	// current one, or the default for the kind, and 0 is no cap.
	MaxConcurrentRuns *int `json:"max_concurrent_runs,omitempty"`
}

// record is the sign-in to keep, given the one kept now, if any. A field left
// out keeps its current value while the sign-in stays the same kind for the
// same provider, so changing only the cap does not ask for the key again.
func (q brainSignInRequest) record(prev *brainsignin.Record, now time.Time) (brainsignin.Record, error) {
	provider := brainsignin.NormaliseProvider(q.Provider)
	kind := brainsignin.NormaliseKind(q.Kind, provider)
	if provider == "" && kind == brainsignin.KindLocal {
		provider = brainsignin.Local
	}
	if provider == "" && q.Kind == "" && prev != nil {
		provider, kind = prev.Provider, prev.Kind
	}
	same := prev != nil && prev.Provider == provider && prev.Kind == kind
	rec := brainsignin.Record{
		Kind: kind, Provider: provider, Account: strings.TrimSpace(q.Account),
		Endpoint: strings.TrimSpace(q.Endpoint), ExpiresAt: q.ExpiresAt,
		Secret: strings.TrimSpace(q.Secret), SetAt: now,
		MaxConcurrentRuns: brainsignin.DefaultMaxConcurrentRuns(kind, provider),
	}
	if same {
		if rec.Secret == "" {
			rec.Secret = prev.Secret
		}
		if rec.Account == "" {
			rec.Account = prev.Account
		}
		if rec.Endpoint == "" {
			rec.Endpoint = prev.Endpoint
		}
		if rec.ExpiresAt == nil {
			rec.ExpiresAt = prev.ExpiresAt
		}
		rec.MaxConcurrentRuns = prev.MaxConcurrentRuns
	}
	if q.MaxConcurrentRuns != nil {
		rec.MaxConcurrentRuns = *q.MaxConcurrentRuns
	}
	return rec, rec.Check()
}

// brainSignInView is a sign-in as it may be shown: never its secret.
func (s *CoreServer) brainSignInView(assetID string, rec brainsignin.Record) map[string]any {
	now := time.Now()
	return map[string]any{
		"kind": rec.Kind, "provider": rec.Provider, "account": rec.Account,
		"endpoint": rec.Endpoint, "expires_at": rec.ExpiresAt, "expired": rec.Expired(now),
		"max_concurrent_runs": rec.MaxConcurrentRuns, "has_secret": rec.HasSecret(),
		"set_at": rec.SetAt, "runs_in_use": s.brainLeases().InUse(assetID, now),
		"harness": brainsignin.Harness(rec.Provider),
	}
}

// keepBrainSignIn keeps an AI agent's sign-in in the vault and points the AI
// agent's brain at it. The vault is written first: an AI agent never names a
// sign-in that is not kept.
func (s *CoreServer) keepBrainSignIn(a asset.Asset, rec brainsignin.Record, by string) (asset.Asset, error) {
	vault, err := s.brainVault()
	if err != nil {
		return a, err
	}
	ref := brainsignin.Ref(a.ID)
	prev, had, err := vault.BrainSignIn(ref)
	if err != nil {
		return a, err
	}
	if err := vault.SetBrainSignIn(ref, rec); err != nil {
		return a, err
	}
	// A different secret is a different sign-in: the places runs hold on the
	// old one are not places on the new one.
	if had && prev.Secret != rec.Secret {
		if err := s.brainLeases().Forget(a.ID); err != nil {
			log.Printf("[brain] AI agent %s: the runs holding its previous sign-in could not be forgotten: %v", a.PairwiseAID, err)
		}
	}
	cfg := asset.AgentConfig{Exposure: asset.Exposure{MCP: true}}
	if a.AgentConfig != nil {
		cfg = *a.AgentConfig
	}
	cfg.Brain.Kind, cfg.Brain.Provider, cfg.Brain.CredentialRef = rec.Kind, rec.Provider, ref
	if rec.Endpoint != "" {
		cfg.Brain.Endpoint = rec.Endpoint
	}
	a.AgentConfig = &cfg
	a.UpdatedAt = time.Now().UTC()
	if err := s.assetHandler.Store.UpsertAsset(a); err != nil {
		return a, fmt.Errorf("the sign-in is kept, but the AI agent could not be pointed at it: %w", err)
	}
	s.recordBrainEvent(a, sandbox.CallerContext{}, "set", "ok", fmt.Sprintf("%s sign-in for %s set by %s",
		rec.Kind, rec.Provider, firstNonEmptyString(by, "the owner")))
	return a, nil
}

// recordBrainEvent writes what happened to an AI agent's sign-in into the
// signed record, as the AI agent, never with the secret.
func (s *CoreServer) recordBrainEvent(a asset.Asset, cc sandbox.CallerContext, event, status, why string) {
	log.Printf("[brain] %s for AI agent %s: %s (%s)", event, a.PairwiseAID, why, status)
	if s.SandboxManager == nil {
		return
	}
	cc.CallerAID = a.PairwiseAID
	if len(cc.DelegationChain) == 0 {
		cc.DelegationChain = []string{a.PairwiseAID, a.DelegatorAID}
	}
	cc.Reason = why
	s.SandboxManager.RecordGovernanceEvent(cc, "agent.brain.sign_in."+event, status)
}

// brainSignInShown is an AI agent's sign-in as a list of AI agents shows it,
// or nil where it has none here or the vault cannot be read.
func (s *CoreServer) brainSignInShown(a asset.Asset) map[string]any {
	if s.SandboxManager == nil {
		return nil
	}
	rec, had, err := s.SandboxManager.BrainSignIn(brainsignin.Ref(a.ID))
	if err != nil || !had {
		return nil
	}
	return s.brainSignInView(a.ID, rec)
}

// removeBrainSignInOf deletes an AI agent's sign-in and the runs holding it.
func (s *CoreServer) removeBrainSignInOf(assetID string) error {
	vault, err := s.brainVault()
	if err != nil {
		return err
	}
	_ = s.brainLeases().Forget(assetID)
	return vault.RemoveBrainSignIn(brainsignin.Ref(assetID))
}

// forgetBrainSignInOf removes the sign-in kept for an AI agent whose making
// was undone, so the vault holds nothing for an AI agent that does not exist.
func (s *CoreServer) forgetBrainSignInOf(assetID string, kept bool) {
	if !kept {
		return
	}
	if err := s.removeBrainSignInOf(assetID); err != nil {
		log.Printf("[brain] the sign-in kept for an AI agent that was not made could not be removed: %v", err)
	}
}

func firstNonEmptyString(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ── The owner's side ─────────────────────────────────────────────────────────

func (s *CoreServer) handleGetBrainSignIn(w http.ResponseWriter, r *http.Request) {
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
		writeJSONStatus(w, http.StatusOK, map[string]any{"sign_in": nil})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"sign_in": s.brainSignInView(a.ID, rec)})
}

// handleSetBrainSignIn signs an AI agent's brain in, or replaces or adjusts
// its sign-in.
func (s *CoreServer) handleSetBrainSignIn(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	var q brainSignInRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil {
		jsonError(w, "the sign-in is unreadable", http.StatusBadRequest)
		return
	}
	vault, err := s.brainVaultWritable()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	var prev *brainsignin.Record
	if p, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID)); err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	} else if had {
		prev = &p
	}
	rec, err := q.record(prev, time.Now().UTC())
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	updated, err := s.keepBrainSignIn(a, rec, madeByController(r))
	if err != nil {
		jsonError(w, "the sign-in was not kept: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"asset_id": updated.ID, "sign_in": s.brainSignInView(updated.ID, rec),
		"agent_config": updated.AgentConfig.ForDisplay(s.isVaultEntry),
	})
}

func (s *CoreServer) handleRemoveBrainSignIn(w http.ResponseWriter, r *http.Request) {
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
	if err := vault.RemoveBrainSignIn(brainsignin.Ref(a.ID)); err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_ = s.brainLeases().Forget(a.ID)
	if a.AgentConfig != nil && brainsignin.IsRef(a.AgentConfig.Brain.CredentialRef) {
		cfg := *a.AgentConfig
		cfg.Brain.CredentialRef = ""
		a.AgentConfig = &cfg
		a.UpdatedAt = time.Now().UTC()
		if err := s.assetHandler.Store.UpsertAsset(a); err != nil {
			jsonError(w, "the sign-in was removed, but the AI agent still names it: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.recordBrainEvent(a, sandbox.CallerContext{}, "removed", "ok",
		"sign-in removed by "+firstNonEmptyString(madeByController(r), "the owner"))
	writeJSONStatus(w, http.StatusOK, map[string]any{"removed": true})
}

// brainSecretFrom moves a secret sent in a brain's credential reference into a
// sign-in, and returns the brain with the secret taken out. A reference to a
// sign-in, or to an entry the vault already holds, is not a secret and is left.
func (s *CoreServer) brainSecretFrom(b asset.BrainConfig) (asset.BrainConfig, *brainsignin.Record) {
	b = b.Normalised()
	if !b.HoldsASecret(s.isVaultEntry) {
		return b, nil
	}
	secret := strings.TrimSpace(b.CredentialRef)
	b.CredentialRef = ""
	kind := brainsignin.NormaliseKind(b.Kind, b.Provider)
	provider := b.Provider
	if kind == brainsignin.KindLocal {
		provider = brainsignin.Local
	}
	return b, &brainsignin.Record{
		Kind: kind, Provider: provider, Endpoint: b.Endpoint, Secret: secret, SetAt: time.Now().UTC(),
		MaxConcurrentRuns: brainsignin.DefaultMaxConcurrentRuns(kind, provider),
	}
}

func (s *CoreServer) isVaultEntry(name string) bool {
	return s.SandboxManager != nil && s.SandboxManager.HasServiceCredential(name)
}

// brainSecretsMoved holds, by data directory, whether every key on an AI
// agent's record has been moved, so the check stops once it has.
var (
	brainSecretsMoved    sync.Map
	brainSecretsMovingMu sync.Mutex
)

// moveBrainSecretsIntoTheVault moves any key an earlier version stored on an
// AI agent's record into the vault: at start, and again each time AI agents
// are listed or a body borrows, until none is left — the vault's key may only
// be here after setup, or after the device holding it unlocks it. Moving a secret already
// held here into the vault grants nothing to anybody, so it needs no decision
// by the owner. A secret that cannot be moved yet — the vault is locked — is
// left, said so, and never shown: every view of an AI agent hides it.
func (s *CoreServer) moveBrainSecretsIntoTheVault() {
	if s.assetHandler == nil || s.SandboxManager == nil {
		return
	}
	if done, _ := brainSecretsMoved.Load(s.DataDir); done == true {
		return
	}
	brainSecretsMovingMu.Lock()
	defer brainSecretsMovingMu.Unlock()
	left := 0
	defer func() {
		if left == 0 {
			brainSecretsMoved.Store(s.DataDir, true)
		}
	}()
	for _, a := range s.assetHandler.ListAgents() {
		if a.AgentConfig == nil {
			continue
		}
		brain, rec := s.brainSecretFrom(a.AgentConfig.Brain)
		if rec == nil {
			continue
		}
		if err := rec.Check(); err != nil {
			// Kept as it is, even if the brain's provider is one a sign-in is
			// not made for yet: the secret is still moved off the record.
			log.Printf("[brain] AI agent %s: the key on its record moves to the vault as it is (%v)", a.PairwiseAID, err)
		}
		cfg := *a.AgentConfig
		cfg.Brain = brain
		a.AgentConfig = &cfg
		if _, err := s.keepBrainSignIn(a, *rec, "moving a key off the AI agent's record"); err != nil {
			left++
			log.Printf("[brain] AI agent %s: a key stored on its record could not be moved into the vault yet: %v", a.PairwiseAID, err)
			continue
		}
		log.Printf("[brain] AI agent %s: a key stored on its record was moved into the vault", a.PairwiseAID)
	}
}

// ── The body's side ──────────────────────────────────────────────────────────

// leaseRequest names a lease a body holds.
type leaseRequest struct {
	LeaseID string `json:"lease_id"`
}

// theBodyAndItsAgent is the live body a sealed, signed request comes from,
// and its AI agent.
func (s *CoreServer) theBodyAndItsAgent(w http.ResponseWriter, r *http.Request) (sandbox.CallerContext, agentbody.Binding, asset.Asset, bool) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		jsonError(w, "a body borrows its AI agent's sign-in sealed to this Identity Agent, signed by its own key: "+
			err.Error(), http.StatusForbidden)
		return cc, b, asset.Asset{}, false
	}
	a, ok := s.aiAgentAsset(b.AgentAssetID)
	if !ok {
		jsonError(w, "this body's AI agent is gone", http.StatusNotFound)
		return cc, b, asset.Asset{}, false
	}
	return cc, b, a, true
}

// handleBodyBorrowsSignIn lends a body its AI agent's sign-in for one run.
func (s *CoreServer) handleBodyBorrowsSignIn(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	s.moveBrainSecretsIntoTheVault()
	s.recordLapsedLeases()
	if err := s.mayBorrow(a, cc); err != nil {
		s.recordBrainEvent(a, cc, "lend", "denied", err.Error())
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	// Whether a sign-in was ever kept for this AI agent is on its record, so a
	// vault that cannot be read does not stop the bodies of AI agents that
	// never had one.
	named := a.AgentConfig != nil && brainsignin.IsRef(a.AgentConfig.Brain.CredentialRef)
	var rec brainsignin.Record
	had := false
	vault, err := s.brainVault()
	if err == nil {
		rec, had, err = vault.BrainSignIn(brainsignin.Ref(a.ID))
	}
	if err != nil && named {
		jsonError(w, "this AI agent's sign-in cannot be read: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !had {
		// Not a refusal: the machine's brain runs with whatever it was signed in
		// with by hand.
		writeJSONStatus(w, http.StatusNotFound, map[string]any{
			"error": "no sign-in is kept for this AI agent", "no_sign_in": true})
		return
	}
	now := time.Now().UTC()
	if rec.Expired(now) {
		s.recordBrainEvent(a, cc, "lend", "denied", "the sign-in expired; it must be signed in again")
		writeJSONStatus(w, http.StatusGone, map[string]any{
			"error": "this AI agent's sign-in has expired; sign it in again", "expired": true})
		return
	}
	lease, lapsed, err := s.brainLeases().Lend(a.ID, b.Host, rec.MaxConcurrentRuns, now)
	for _, x := range lapsed {
		xa, ok := s.aiAgentAsset(x.Agent)
		if !ok {
			continue
		}
		s.recordBrainEvent(xa, sandbox.CallerContext{Transport: "body", BodyHost: x.Host},
			"lapsed", "ok", "lease "+x.ID+" was not renewed, so its run's place was freed")
	}
	if errors.Is(err, brainsignin.ErrInUse) {
		s.recordBrainEvent(a, cc, "lend", "denied", fmt.Sprintf("%s: all %d in use",
			brainsignin.ErrInUse, rec.MaxConcurrentRuns))
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": brainsignin.ErrInUse.Error(), "in_use": true,
			"max_concurrent_runs": rec.MaxConcurrentRuns, "retry_after_seconds": 30})
		return
	}
	if err != nil {
		jsonError(w, "the sign-in could not be lent: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordBrainEvent(a, cc, "lent", "ok", fmt.Sprintf("lease %s of the %s sign-in for %s, until %s",
		lease.ID, rec.Kind, rec.Provider, lease.Expires.Format(time.RFC3339)))
	// This answer travels sealed to the keys the body enrolled with: the
	// route is reached only through the sealed transport (theBodyAsking).
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"lease_id": lease.ID, "lease_expires_at": lease.Expires,
		"renew_every_seconds": int(brainsignin.RenewEvery / time.Second),
		"kind":                rec.Kind, "provider": rec.Provider, "account": rec.Account,
		"endpoint": rec.Endpoint, "expires_at": rec.ExpiresAt, "secret": rec.Secret,
		"harness": brainsignin.Harness(rec.Provider),
	})
}

func (s *CoreServer) handleBodyRenewsSignIn(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q leaseRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q); err != nil || q.LeaseID == "" {
		jsonError(w, "name the lease to renew", http.StatusBadRequest)
		return
	}
	s.recordLapsedLeases()
	if err := s.mayBorrow(a, cc); err != nil {
		// The run keeps what it holds until it ends; its place is not kept.
		s.recordBrainEvent(a, cc, "renew", "denied", err.Error())
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	lease, err := s.brainLeases().Renew(q.LeaseID, b.Host, a.ID, time.Now().UTC())
	if err != nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": brainsignin.ErrNoLease.Error(), "no_lease": true})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"lease_id": lease.ID, "lease_expires_at": lease.Expires})
}

func (s *CoreServer) handleBodyReturnsSignIn(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q leaseRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q); err != nil || q.LeaseID == "" {
		jsonError(w, "name the lease to return", http.StatusBadRequest)
		return
	}
	s.recordLapsedLeases()
	lease, err := s.brainLeases().Return(q.LeaseID, b.Host, a.ID, time.Now().UTC())
	switch {
	case lease.ID != "":
		why := "lease " + lease.ID + " returned"
		if err != nil {
			why += ", after it had lapsed"
		}
		s.recordBrainEvent(a, cc, "returned", "ok", why)
		writeJSONStatus(w, http.StatusOK, map[string]any{"returned": true})
	default:
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": brainsignin.ErrNoLease.Error(), "no_lease": true})
	}
}
