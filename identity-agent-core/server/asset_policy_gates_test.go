package server

import (
	"strings"
	"testing"

	"identity-agent-core/asset"
)

func gateServer(t *testing.T, p asset.EnrollmentPolicy) *CoreServer {
	t.Helper()
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	s.assetHandler = h
	if err := h.Store.UpsertAsset(asset.Asset{ID: "a1", PairwiseAID: "ESite", Policy: p}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenPolicyAdmits(t *testing.T) {
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	if ok, r := s.authorizeAssetAccess(nil, "ESite", "Ex", nil); !ok {
		t.Fatalf("open policy refused: %s", r)
	}
}

// No asset for the audience: today's behaviour is to refuse ("asset not found").
func TestNoAssetForAudienceRefusesAsToday(t *testing.T) {
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	if ok, r := s.authorizeAssetAccess(nil, "EOther", "Ex", nil); ok || r != "asset not found" {
		t.Fatalf("got %v %q", ok, r)
	}
}

func TestMinimumScoreGateRefusesAndNamesItself(t *testing.T) {
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen, RequiredOFAScore: 70})
	ok, r := s.authorizeAssetAccess(nil, "ESite", "Ex", nil)
	if ok || !strings.Contains(r, "minimum score gate is not available") {
		t.Fatalf("got %v %q", ok, r)
	}
}

func TestBadgeGateRefusesAndNamesItself(t *testing.T) {
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen, RequiredBadge: "green"})
	ok, r := s.authorizeAssetAccess(nil, "ESite", "Ex", nil)
	if ok || !strings.Contains(r, "badge gate is not available") {
		t.Fatalf("got %v %q", ok, r)
	}
}

func TestCredentialGateRefusesWhenNotPresentedAndAdmitsWhenPresented(t *testing.T) {
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen, RequiredCredSchema: "SCH"})
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "Ex", nil); ok {
		t.Fatal("admitted without the credential")
	}
	pres := []interface{}{map[string]interface{}{"schema_said": "SCH", "status": "issued"}}
	if ok, r := s.authorizeAssetAccess(nil, "ESite", "Ex", pres); !ok {
		t.Fatalf("refused with credential: %s", r)
	}
}

func TestEmployeesMembershipGate(t *testing.T) {
	registerResolverForTest(t, "employees", verifyResolver{active: map[string]bool{"Eann": true}})
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentInvite, MembershipSource: "employees"})
	if ok, r := s.authorizeAssetAccess(nil, "ESite", "Eann", nil); !ok {
		t.Fatalf("active employee refused: %s", r)
	}
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "Ebob", nil); ok {
		t.Fatal("non-employee admitted")
	}
}
