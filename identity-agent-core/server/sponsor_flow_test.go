package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/asset"

	"github.com/go-chi/chi/v5"
)

// Drives the sponsor data flow end-to-end at the API level (no KERI driver
// needed for redeem/roster/gate): seed a sponsor invite → the individual redeems
// with a vouch → the org roster has an ACTIVE super-admin with the vouch stored →
// the membership gate admits that AID for an employees-gated asset.
func newTestServerWithAssets(t *testing.T) (*CoreServer, *asset.Handler) {
	t.Helper()
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	s := &CoreServer{}
	s.assetHandler = h
	return s, h
}

func TestSponsorRedeemMakesActiveSuperAdmin(t *testing.T) {
	s, h := newTestServerWithAssets(t)
	// Seed the sponsor invite the org would have minted.
	if err := h.Store.CreateEmployeeInvite(asset.EmployeeInvite{
		Token: "sptok", Role: "Super Admin", IsSponsor: true, MaxUses: 1,
	}); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) { s.mountSponsorRoutes(r) })
	srv := httptest.NewServer(r)
	defer srv.Close()

	body := `{"pairwise_aid":"ESponsorPairwiseAID","name":"Rob","oobi":"https://x/oobi/E","vouch_sig":"SIG","vouch_payload":"{\"org_aid\":\"EOrg\"}"}`
	resp, err := http.Post(srv.URL+"/api/sponsor/invites/sptok/redeem", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("redeem post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem status = %d, want 200", resp.StatusCode)
	}

	// The sponsor must now be an ACTIVE super-admin with the vouch stored.
	if !h.Store.IsActiveEmployee("ESponsorPairwiseAID") {
		t.Fatal("sponsor is not an active employee after redeem")
	}
	emps := h.Store.ListEmployees()
	if len(emps) != 1 {
		t.Fatalf("roster size = %d, want 1", len(emps))
	}
	e := emps[0]
	if e.Status != "active" || e.Role != "Super Admin" || !e.IsSponsor {
		t.Fatalf("roster entry = %+v, want active Super Admin sponsor", e)
	}
	if e.VouchSig != "SIG" {
		t.Fatalf("vouch not stored: %q", e.VouchSig)
	}

	// A non-sponsor invite token must be rejected by the sponsor redeem path.
	_ = h.Store.CreateEmployeeInvite(asset.EmployeeInvite{Token: "emptok", Role: "Employee"})
	resp2, _ := http.Post(srv.URL+"/api/sponsor/invites/emptok/redeem", "application/json", strings.NewReader(body))
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("sponsor redeem accepted a non-sponsor invite")
	}
}

func TestEmployeesGateAdmitsActiveSponsorOnly(t *testing.T) {
	s, h := newTestServerWithAssets(t)
	// An org portal asset gated on the ACTIVE employee list.
	if err := h.Store.UpsertAsset(asset.Asset{
		ID: "a1", PairwiseAID: "ESite", DisplayName: "Portal",
		Policy: asset.EnrollmentPolicy{Mode: asset.EnrollmentInvite, MembershipSource: "employees"},
	}); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	// Before enrollment: denied.
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "ESponsorPairwiseAID", nil); ok {
		t.Fatal("gate admitted a non-employee")
	}
	// Sponsor becomes active.
	if err := h.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: "ESponsorPairwiseAID", Role: "Super Admin", Status: "active", IsSponsor: true,
	}); err != nil {
		t.Fatalf("upsert employee: %v", err)
	}
	if ok, reason := s.authorizeAssetAccess(nil, "ESite", "ESponsorPairwiseAID", nil); !ok {
		t.Fatalf("gate denied an active super-admin: %s", reason)
	}
	// Revoked → denied again.
	_, _, _ = h.Store.SetEmployeeStatus("ESponsorPairwiseAID", "revoked", "")
	if ok, _ := s.authorizeAssetAccess(nil, "ESite", "ESponsorPairwiseAID", nil); ok {
		t.Fatal("gate admitted a revoked employee")
	}
}

func TestSponsorAskPreview(t *testing.T) {
	ask, _ := json.Marshal(map[string]interface{}{
		"v": "ASK1", "t": 4, "org_name": "Acme Corp", "org_aid": "EOrg",
		"invite_token": "sptok",
	})
	pv, err := addSponsorAsk{}.Preview(nil, AskContext{AskBytes: ask, T: 4})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if pv.T != 4 || pv.Action != "sponsor_org" {
		t.Fatalf("preview = %+v, want t=4 sponsor_org", pv)
	}
	if !strings.Contains(pv.Subtitle, "Acme Corp") || !strings.Contains(pv.Subtitle, "super-admin") {
		t.Fatalf("preview subtitle missing org/role: %q", pv.Subtitle)
	}
}
