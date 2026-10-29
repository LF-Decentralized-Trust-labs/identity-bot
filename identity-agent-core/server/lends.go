package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/lending"
	"identity-agent-core/permission"
	"identity-agent-core/vault"
)

// Everything this Identity Agent lends to an AI agent's bodies — a brain's
// sign-in, access to GitHub — is kept in one record, in the vault (the lending
// package). Each kind plugs in only what differs: whether the AI agent's grant
// still covers a lend, and how what was lent is withdrawn. So one sweep ends
// every lend its grant no longer covers, of every kind, at once: when any
// credential is revoked or withdrawn, when an AI agent's grant is re-issued,
// when a machine is removed as a body, and every minute.

// The kinds of lend.
const (
	lendBrainSignIn = "brain_sign_in"
	lendGitHub      = "github"
)

var lendsRef = vault.KeptRef("lends")

const keptLends = "lends"

// vaultLends keeps the ledger in the vault.
type vaultLends struct{ s *CoreServer }

func (v vaultLends) Read(out any) (bool, error) {
	theVault, err := v.s.brainVault()
	if err != nil {
		return false, err
	}
	return theVault.Kept(lendsRef, keptLends, out)
}

func (v vaultLends) Write(x any) error {
	theVault, err := v.s.brainVault()
	if err != nil {
		return err
	}
	return theVault.SetKept(lendsRef, keptLends, x)
}

// lends is the record of everything lent. Leases a version before this one
// kept in a file of their own are moved into it the first time the vault can
// take them.
func (s *CoreServer) lends() *lending.Ledger {
	s.lendsOnce.Do(func() {
		s.lendLedger = lending.New(vaultLends{s}, s.brainLendService(), s.githubLendService())
	})
	s.moveLegacyLeases()
	return s.lendLedger
}

// moveLegacyLeases moves the brain sign-in leases kept beside the vault into
// the ledger, once. A vault that cannot take them yet leaves them where they
// are, to be moved next time.
func (s *CoreServer) moveLegacyLeases() {
	if s.legacyLeasesMoved.Load() {
		return
	}
	s.legacyLeasesMu.Lock()
	defer s.legacyLeasesMu.Unlock()
	if s.legacyLeasesMoved.Load() {
		return
	}
	old, had, err := brainsignin.LegacyLeases(s.DataDir)
	if !had {
		s.legacyLeasesMoved.Store(true)
		return
	}
	if err != nil {
		log.Printf("[lent] the leases kept before every lend was in one record cannot be read, so they are not moved: %v", err)
		s.legacyLeasesMoved.Store(true)
		return
	}
	moved := make([]lending.Lend, 0, len(old))
	for _, x := range old {
		l := lending.Lend{ID: x.ID, Kind: lendBrainSignIn, Agent: x.Agent, Host: x.Host,
			Pool: brainsignin.PoolOr(x.Pool, x.Agent), Lent: x.Lent, LentAt: x.LentAt, Expires: x.Expires}
		if x.LapsedAt != nil {
			t := *x.LapsedAt
			l.EndedAt, l.Ended = &t, "lapsed"
		}
		moved = append(moved, l)
	}
	if err := s.lendLedger.Import(moved); err != nil {
		return
	}
	if err := brainsignin.RetireLegacyLeases(s.DataDir); err != nil {
		log.Printf("[lent] the leases were moved into the one record, but their old file could not be removed: %v", err)
	}
	s.legacyLeasesMoved.Store(true)
}

// lentStillCovered is why what a body holds for an AI agent is no longer
// covered — the AI agent gone, revoked or lapsed, may do nothing now, or the
// machine no longer its body — or "" when it still is, with the AI agent and
// its caller context.
func (s *CoreServer) lentStillCovered(agentID, host, what string) (asset.Asset, permission.CallerContext, string) {
	a, ok := s.aiAgentAsset(agentID)
	if !ok {
		return a, permission.CallerContext{}, "the AI agent is gone"
	}
	if b, ok := s.bodies().ActiveByHost(host); !ok || b.AgentAssetID != a.ID {
		return a, permission.CallerContext{}, "the machine is no longer this AI agent's body"
	}
	cc, ok := s.ResolveAgentCaller(a.PairwiseAID)
	if !ok {
		return a, cc, "the AI agent is gone"
	}
	if err := s.mayBeLent(a, cc, what); err != nil {
		return a, cc, err.Error()
	}
	return a, cc, ""
}

// brainLendService is a brain's sign-in as a lend: nothing to withdraw — the
// run keeps the key it was given until it ends — but a lend its grant no
// longer covers holds no place and is not renewed. An ended lease is kept for
// its body to give back with a sign-in its program refreshed.
func (s *CoreServer) brainLendService() lending.Service {
	return lending.Service{Kind: lendBrainSignIn, IDPrefix: "bl_", KeptAfterEnd: brainsignin.LapsedKept,
		Check: func(x lending.Lend) *lending.Narrowed {
			if _, _, why := s.lentStillCovered(x.Agent, x.Host, "its sign-in"); why != "" {
				return &lending.Narrowed{Why: why}
			}
			return nil
		}}
}

// recordLapsedLends ends every lend that lapsed unrenewed, and records each
// once. It asks no service anything, so it is cheap enough for every renewal.
func (s *CoreServer) recordLapsedLends() {
	ended, err := s.lends().Lapse(time.Now().UTC())
	if err != nil {
		log.Printf("[lent] %v", err)
	}
	s.recordEnded(ended, "")
}

// endLendsNoLongerGranted is the one sweep of everything lent: every lend whose
// AI agent's grant no longer covers it ends, of every kind, and is withdrawn
// at its service; every withdrawal a service could not be reached for is
// tried again. why says what prompted it.
func (s *CoreServer) endLendsNoLongerGranted(why string) {
	if s.SandboxManager == nil || s.assetHandler == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ended, err := s.lends().Sweep(ctx, time.Now().UTC())
	if err != nil {
		log.Printf("[lent] what is lent could not be checked (%s): %v", why, err)
	}
	s.recordEnded(ended, why)
}

// recordEnded writes each lend that ended into the signed record, as its AI
// agent, naming its body. prompted is what started the sweep, if anything.
func (s *CoreServer) recordEnded(ended []lending.Ended, prompted string) {
	for _, e := range ended {
		a, ok := s.aiAgentAsset(e.Lend.Agent)
		if !ok {
			continue
		}
		cc := permission.CallerContext{Transport: "body", BodyHost: e.Lend.Host}
		why := e.Why
		if prompted != "" {
			why += " (" + prompted + ")"
		}
		switch e.Lend.Kind {
		case lendBrainSignIn:
			if e.Lapsed {
				s.recordBrainEvent(a, cc, "lapsed", "ok", "lease "+e.Lend.ID+" was not renewed, so its run's place was freed")
				continue
			}
			s.recordBrainEvent(a, cc, "ended", "ok", "lease "+e.Lend.ID+" ended because "+why+", so its run's place was freed")
		case lendGitHub:
			if e.Lapsed {
				continue
			}
			status := "ok"
			if !e.Withdrawn {
				status = "error"
			}
			what := "lend " + e.Lend.ID
			if e.Partly {
				what = "part of lend " + e.Lend.ID
			}
			s.recordGitHubLendEvent(a, cc, "withdrawn", status, fmt.Sprintf("%s withdrawn because %s", what, why))
		}
	}
}

// keepSweepingLends sweeps what is lent every minute: a grant that lapses by
// time changes nothing anybody does, and a withdrawal a service could not be
// reached for is tried again.
func (s *CoreServer) keepSweepingLends(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.endLendsNoLongerGranted("checked every minute")
			s.endMachinesNoLongerWanted("checked every minute")
		}
	}
}
