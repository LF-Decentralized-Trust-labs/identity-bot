package server

import (
	"testing"

	"identity-agent-core/asset"
)

// The endpoint that writes this map is unauthenticated, and has to be: a pairwise
// counterparty we have never met cannot authenticate before publishing the key
// that identifies it. What must never follow is a stranger's claim overriding
// what we already know about our own assets — this function feeds signed-request
// verification, so an override there is a forged request as that agent.

func serverWithAsset(t *testing.T, a asset.Asset) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	store, err := asset.NewStore(dir)
	if err != nil {
		t.Fatalf("asset store: %v", err)
	}
	if err := store.UpsertAsset(a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	return &CoreServer{DataDir: dir, assetHandler: &asset.Handler{Store: store}}
}

func TestSelfRegisteredKeyCannotOverrideOurOwnAsset(t *testing.T) {
	const aid = "EOurOwnProvisionedAgentAID"
	s := serverWithAsset(t, asset.Asset{
		ID: "a1", AssetType: "ai_agent", PairwiseAID: aid,
		PublicKey: "the-real-key-recorded-at-enrolment",
	})

	// An attacker who knows the AID publishes a key of their own choosing.
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "attacker-supplied-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != "the-real-key-recorded-at-enrolment" {
		t.Fatalf("a self-registered key overrode our own record: got %q", got)
	}
}

func TestAKnownAssetWeCannotResolveAnswersNothing(t *testing.T) {
	// Falling back to the map here would be the same hole by another route: a
	// known asset with an unresolvable key must be a failure to answer, not an
	// invitation to accept whatever a stranger published for it.
	const aid = "EKnownButUnresolvable"
	s := serverWithAsset(t, asset.Asset{
		ID: "a2", AssetType: "ai_agent", PairwiseAID: aid,
		// no PublicKey, no SigningIndex
	})
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "attacker-supplied-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != "" {
		t.Fatalf("a known asset we cannot resolve must answer nothing, got %q", got)
	}
}

func TestAStrangerIsStillAnsweredFromTheRegistry(t *testing.T) {
	// The legitimate case the endpoint exists for: an AID we hold no record of.
	// Closing the hole must not close this.
	const aid = "ESomeCounterpartyWeHaveNeverMet"
	s := serverWithAsset(t, asset.Asset{ID: "a3", PairwiseAID: "EDifferentAID", PublicKey: "x"})

	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "their-published-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != "their-published-key" {
		t.Fatalf("an unknown AID should still resolve from the registry, got %q", got)
	}
}
