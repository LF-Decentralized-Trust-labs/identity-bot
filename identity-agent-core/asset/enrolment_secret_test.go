package asset

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/enrolsecret"
)

// Nothing the store writes can be used as a token.
func TestAnIssuedTokenIsNotRecoverableFromTheStore(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if e.Token == "" {
		t.Fatal("the issuer was not given the token")
	}
	files, _ := filepath.Glob(filepath.Join(h.Store.dataDir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), e.Token) {
			t.Errorf("%s holds the token in the clear", f)
		}
	}
	for _, l := range h.Store.ListEnrolments() {
		if l.Token != "" {
			t.Error("listing enrolments returned a token")
		}
	}
	if _, ok := h.Store.GetEnrolment(e.ID); ok {
		t.Error("the stored ID was accepted as if it were the token")
	}
	if _, err := h.Store.ClaimEnrolment(e.ID, time.Now()); err == nil {
		t.Error("the stored ID claimed the enrolment")
	}
}

// Two machines of the same kind and name each keep their own token: issuing a
// second must not quietly cancel the first.
func TestTwoOutstandingTokensForTheSameKindAndNameBothWork(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	first := issueToken(t, h, "the build box", "host", "")
	second := issueToken(t, h, "the build box", "host", "")
	if first.ID == second.ID {
		t.Fatal("two tokens share an identity")
	}
	if w := enrol(t, h, first.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("the first token was cancelled by issuing the second: %d", w.Code)
	}
	if w := enrol(t, h, second.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("the second token was refused: %d", w.Code)
	}
}

// Replacing is something the issuer asks for by naming the enrolment: that one
// ends, and no other does.
func TestReplacingATokenEndsThatOneAndNoOther(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	old := issueToken(t, h, "the build box", "host", "")
	bystander := issueToken(t, h, "the build box", "host", "")
	newer, err := h.Store.CreateEnrolment(Enrolment{DisplayName: "the build box", AssetType: "host", Replaces: old.ID})
	if err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, old.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("the replaced token still works: %d", w.Code)
	}
	if w := enrol(t, h, bystander.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("a token that was not named was ended: %d", w.Code)
	}
	if w := enrol(t, h, newer.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("the replacement was refused: %d", w.Code)
	}
	if _, err := h.Store.CreateEnrolment(Enrolment{DisplayName: "x", AssetType: "host", Replaces: "no-such-id"}); err == nil {
		t.Error("replacing an enrolment that does not exist should be refused")
	}
}

func TestATokenCannotBeReusedAfterEnrolling(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Fatalf("first use: %d", w.Code)
	}
	if _, err := h.Store.ClaimEnrolment(e.Token, time.Now()); err == nil {
		t.Error("a spent token was claimed again")
	}
}

func TestARevokedTokenCanBeRevokedByItsListedID(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if err := h.Store.RevokeEnrolment(e.ID); err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("a revoked token was accepted: %d", w.Code)
	}
}

// A file an earlier version wrote holds the token as its key. Opening the store
// carries a good token across and leaves no plaintext behind.
func TestATokenStoredInTheClearByAnEarlierVersionIsCarriedAcross(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	dir := h.Store.dataDir
	const legacy = "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
	now := time.Now().UTC()
	b, _ := json.Marshal(map[string]Enrolment{legacy: {
		Token: legacy, DisplayName: "old", AssetType: "host",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}})
	if err := os.WriteFile(filepath.Join(dir, "asset_enrolments.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	// A restart: the store opens over the old file and migrates it.
	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.Store = reopened
	if w := enrol(t, h, legacy, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Fatalf("a still-good token from the old file was refused: %d", w.Code)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "asset_enrolments.json"))
	if strings.Contains(string(raw), legacy) {
		t.Error("the old plaintext token is still in the file")
	}
}

// If the old file cannot be rewritten, the store does not start: clear tokens
// must not be left on disk behind a running agent.
func TestAFailedMigrationRefusesToStart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	now := time.Now().UTC()
	b, _ := json.Marshal(map[string]Enrolment{"clear": {
		Token: "clear", DisplayName: "old", AssetType: "host", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}})
	if err := os.WriteFile(filepath.Join(dir, "asset_enrolments.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	s, err := NewStore(dir)
	if !errors.Is(err, ErrSecretsNotMigrated) || s != nil {
		t.Fatalf("NewStore = %v, %v; want it to refuse with ErrSecretsNotMigrated", s, err)
	}
}

func TestInviteCodesAreNeverStoredAndMigrateFromTheClear(t *testing.T) {
	dir := t.TempDir()
	legacyAsset, _ := json.Marshal(map[string]AssetInvite{"asset-code-1": {Token: "asset-code-1", AssetID: "a1", MaxUses: 2}})
	legacyEmp, _ := json.Marshal(map[string]EmployeeInvite{"emp-code-1": {Token: "emp-code-1", Role: "staff"}})
	os.WriteFile(filepath.Join(dir, "asset_invites.json"), legacyAsset, 0o600)
	os.WriteFile(filepath.Join(dir, "employee_invites.json"), legacyEmp, 0o600)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if inv, ok := s.GetInvite("asset-code-1"); !ok || inv.AssetID != "a1" {
		t.Error("a good asset invite did not survive the migration")
	}
	if _, ok := s.GetEmployeeInvite("emp-code-1"); !ok {
		t.Error("a good employee invite did not survive the migration")
	}
	if err := s.CreateInvite(AssetInvite{Token: "asset-code-2", AssetID: "a1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEmployeeInvite(EmployeeInvite{Token: "emp-code-2", Role: "staff"}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		for _, code := range []string{"asset-code-1", "emp-code-1", "asset-code-2", "emp-code-2"} {
			if strings.Contains(string(raw), code) {
				t.Errorf("%s holds the code %q in the clear", f, code)
			}
		}
	}
	for _, inv := range s.ListInvites("a1") {
		if inv.Token != "" {
			t.Error("listing asset invites returned a code")
		}
	}
	for _, inv := range s.ListEmployeeInvites() {
		if inv.Token != "" {
			t.Error("listing employee invites returned a code")
		}
	}
	// The stored digest is not itself a code.
	id := enrolsecret.Digest("asset-code-2")
	if _, ok := s.GetInvite(id); ok {
		t.Error("the stored digest was accepted as if it were the code")
	}
}

// Revoking is by the listed ID. A code in the path does nothing, so no route
// that withdraws something takes a secret.
func TestAnInviteCodeInARevokePathRevokesNothing(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := revokeRouter(&Handler{Store: s})
	s.CreateInvite(AssetInvite{Token: "code", AssetID: "a1"})
	s.CreateEmployeeInvite(EmployeeInvite{Token: "ecode", Role: "staff"})
	if got := del(r, "/assets/a1/invites/code"); got != http.StatusNotFound {
		t.Errorf("revoking an asset invite by its code = %d, want 404", got)
	}
	if got := del(r, "/employees/invites/ecode"); got != http.StatusNotFound {
		t.Errorf("revoking an employee invite by its code = %d, want 404", got)
	}
	if inv, _ := s.GetInvite("code"); inv.Revoked {
		t.Error("an asset invite was revoked by its code")
	}
}

func TestAnEnrolmentCannotBeRevokedByItsToken(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if err := h.Store.RevokeEnrolment(e.Token); err == nil {
		t.Error("the token itself revoked an enrolment")
	}
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("a refused revoke still ended the token: %d", w.Code)
	}
}
