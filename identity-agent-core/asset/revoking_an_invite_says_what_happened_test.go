package asset

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Withdrawing a code must tell the caller the truth: 200 only when a live code
// was withdrawn, 404 for a code nobody holds, 409 for one already revoked or used
// up, and a 5xx when the withdrawal could not be saved.
func revokeRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Delete("/assets/{id}/invites/{token}", h.HandleRevokeInvite)
	r.Delete("/employees/invites/{token}", h.HandleRevokeEmployeeInvite)
	return r
}

func del(r http.Handler, path string) int {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))
	return rec.Code
}

func TestRevokingAnInviteSaysWhatHappened(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: s}
	r := revokeRouter(h)

	s.CreateInvite(AssetInvite{Token: "live", AssetID: "a1"})
	s.CreateInvite(AssetInvite{Token: "spent", AssetID: "a1", MaxUses: 1, UseCount: 1})
	s.CreateEmployeeInvite(EmployeeInvite{Token: "elive", Role: "staff"})
	s.CreateEmployeeInvite(EmployeeInvite{Token: "espent", Role: "staff", MaxUses: 1, UseCount: 1})

	cases := []struct {
		name, path string
		want       int
	}{
		{"asset: unknown", "/assets/a1/invites/nope", 404},
		{"asset: live", "/assets/a1/invites/live", 200},
		{"asset: again", "/assets/a1/invites/live", 409},
		{"asset: used up", "/assets/a1/invites/spent", 409},
		{"employee: unknown", "/employees/invites/nope", 404},
		{"employee: live", "/employees/invites/elive", 200},
		{"employee: again", "/employees/invites/elive", 409},
		{"employee: used up", "/employees/invites/espent", 409},
	}
	for _, c := range cases {
		if got := del(r, c.path); got != c.want {
			t.Errorf("%s: DELETE %s = %d, want %d", c.name, c.path, got, c.want)
		}
	}
	if inv, _ := s.GetInvite("spent"); inv.Revoked {
		t.Error("a used-up code must be left as it was, not marked revoked")
	}
}

func TestARevokeThatCannotBeSavedIsNotReportedAsRevoked(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: s}
	r := revokeRouter(h)
	s.CreateInvite(AssetInvite{Token: "live", AssetID: "a1"})
	s.CreateEmployeeInvite(EmployeeInvite{Token: "elive", Role: "staff"})

	// Make every later save fail: replace the store directory with a file.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"/assets/a1/invites/live", "/employees/invites/elive"} {
		if got := del(r, p); got != http.StatusInternalServerError {
			t.Errorf("DELETE %s with an unwritable store = %d, want 500", p, got)
		}
	}
	// The failed save must not leave the code looking revoked in memory.
	if inv, _ := s.GetInvite("live"); inv.Revoked {
		t.Error("a revoke that failed to save must not stick in memory")
	}
	if inv, _ := s.GetEmployeeInvite("elive"); inv.Revoked {
		t.Error("an employee revoke that failed to save must not stick in memory")
	}
}

// A code can only be withdrawn through the asset it belongs to. Naming another
// asset in the URL answers 404, the same as an unknown code, and leaves the code live.
func TestRevokingAnotherAssetsInviteLeavesItLive(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := revokeRouter(&Handler{Store: s})
	s.CreateInvite(AssetInvite{Token: "theirs", AssetID: "a2"})

	if got := del(r, "/assets/a1/invites/theirs"); got != http.StatusNotFound {
		t.Fatalf("revoking a2's code through a1 = %d, want 404", got)
	}
	if inv, _ := s.GetInvite("theirs"); inv.Revoked {
		t.Fatal("a2's code was revoked through a1")
	}
	if got := del(r, "/assets/a1/invites/nope"); got != http.StatusNotFound {
		t.Fatalf("unknown code = %d, want 404", got)
	}
	if got := del(r, "/assets/a2/invites/theirs"); got != http.StatusOK {
		t.Fatalf("revoking through its own asset = %d, want 200", got)
	}
}

// A code redeemed as many times as it allows is closed: the revoke route says
// so (409), and the read and redeem routes refuse it, so the 409 is true.
func TestAUsedUpInviteCannotBeRedeemed(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: s}
	r := chi.NewRouter()
	r.Get("/invites/{token}", h.HandleGetInviteInfo)
	r.Post("/invites/{token}/redeem", h.HandleRedeemInvite)
	s.CreateInvite(AssetInvite{Token: "once", AssetID: "a1", MaxUses: 1})

	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	if got := do(http.MethodPost, "/invites/once/redeem"); got != http.StatusOK {
		t.Fatalf("first redeem = %d, want 200", got)
	}
	if got := do(http.MethodPost, "/invites/once/redeem"); got != http.StatusBadRequest {
		t.Errorf("redeeming a used-up code = %d, want 400", got)
	}
	if got := do(http.MethodGet, "/invites/once"); got != http.StatusNotFound {
		t.Errorf("reading a used-up code = %d, want 404", got)
	}
	if inv, _ := s.GetInvite("once"); inv.UseCount != 1 {
		t.Errorf("use count = %d, want 1: a refused redeem must not count", inv.UseCount)
	}
}
