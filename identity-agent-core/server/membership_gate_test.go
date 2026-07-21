package server

import (
	"testing"

	"identity-agent-core/asset"
)

type verifyResolver struct{ active map[string]bool }

func (r verifyResolver) Admit(aid, _ string) (bool, string) {
	if r.active[aid] {
		return true, ""
	}
	return false, "not active"
}

// Proves the core's login authorizer routes a non-default MembershipSource
// through a registered resolver: fail-closed with none, admit/deny per resolver.
func TestMembershipResolverGateChain(t *testing.T) {
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	s := &CoreServer{}
	s.assetHandler = h
	if err := h.Store.UpsertAsset(asset.Asset{
		ID: "a1", PairwiseAID: "ESite",
		Policy: asset.EnrollmentPolicy{Mode: asset.EnrollmentInvite, MembershipSource: "verify_src"},
	}); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	// No resolver registered for "verify_src" → fail closed.
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "Ealice", nil); ok {
		t.Fatal("admitted with no resolver registered (should fail closed)")
	}
	// Register a resolver admitting Ealice only.
	RegisterMembershipResolver("verify_src", verifyResolver{active: map[string]bool{"Ealice": true}})
	if ok, reason := s.authorizeAssetAccess(nil, "ESite", "Ealice", nil); !ok {
		t.Fatalf("resolver-admitted AID denied: %s", reason)
	}
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "Ebob", nil); ok {
		t.Fatal("resolver-denied AID admitted")
	}
}
