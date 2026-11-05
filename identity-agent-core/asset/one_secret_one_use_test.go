package asset

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/enrolsecret"
)

func writeLegacyEnrolment(t *testing.T, dir, token string) {
	t.Helper()
	now := time.Now().UTC()
	b, _ := json.Marshal(map[string]Enrolment{token: {
		Token: token, DisplayName: "old", AssetType: "host", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}})
	if err := os.WriteFile(filepath.Join(dir, "asset_enrolments.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A crash after the token was adopted but before the old file was rewritten
// leaves the clear token on disk; the next start adopts it again. The token
// must still mint exactly one identity.
func TestACrashDuringMigrationDoesNotLetOneTokenBeSpentTwice(t *testing.T) {
	dir := t.TempDir()
	writeLegacyEnrolment(t, dir, "legacy-token")

	// The crashed first start: adopted, file not rewritten.
	now := time.Now().UTC()
	pre := enrolsecret.Open(filepath.Join(dir, "asset_enrolment_secrets.json"))
	if err := pre.Adopt(enrolsecret.Entry{Digest: enrolsecret.Digest("legacy-token"), Expires: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(dir) // the restart
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimEnrolment("legacy-token", time.Now().UTC()); err != nil {
		t.Fatalf("the first claim was refused: %v", err)
	}
	if _, err := s.ClaimEnrolment("legacy-token", time.Now().UTC()); err == nil {
		t.Fatal("one token was claimed twice")
	}
}

// A record already marked used is refused even if the secret store still holds
// the digest.
func TestAUsedRecordIsRefusedEvenIfTheSecretIsStillThere(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.CreateEnrolment(Enrolment{DisplayName: "x", AssetType: "host"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimEnrolment(e.Token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Put the secret back as a duplicate would leave it, leaving the record used.
	if err := s.enrolSecrets.Adopt(enrolsecret.Entry{Digest: e.ID, Expires: e.ExpiresAt}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimEnrolment(e.Token, time.Now().UTC()); err == nil {
		t.Fatal("a record already used was claimed again")
	}
}

func TestConcurrentRedeemsOfAOneUseInviteSucceedOnce(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvite(AssetInvite{Token: "a-code", AssetID: "a1", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEmployeeInvite(EmployeeInvite{Token: "e-code", Role: "staff", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEmployeeInvite(EmployeeInvite{Token: "s-code", Role: "Owner", IsSigner: true, MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	for name, redeem := range map[string]func() error{
		"asset":    func() error { _, e := s.RedeemInvite("a-code"); return e },
		"employee": func() error { _, e := s.ReserveEmployeeInvite("e-code", false); return e },
		"signer":   func() error { _, e := s.ReserveEmployeeInvite("s-code", true); return e },
	} {
		var won int32
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if redeem() == nil {
					atomic.AddInt32(&won, 1)
				}
			}()
		}
		wg.Wait()
		if won != 1 {
			t.Errorf("%s: %d redeems of a one-use invite succeeded; want exactly 1", name, won)
		}
	}
}

// When the use cannot be saved the redeem fails and the invite is still
// redeemable once the store works again.
func TestARedeemFailsWhenTheUseCannotBeSaved(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvite(AssetInvite{Token: "a-code", AssetID: "a1", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEmployeeInvite(EmployeeInvite{Token: "e-code", Role: "staff", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	// A file where a directory is needed: every save fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	okA, okE := s.invitesPath, s.empInvitesPath
	s.invitesPath, s.empInvitesPath = filepath.Join(blocker, "i.json"), filepath.Join(blocker, "e.json")

	if _, err := s.RedeemInvite("a-code"); err == nil || errors.Is(err, ErrInviteExhausted) {
		t.Errorf("asset redeem with a failing save = %v; want the save error", err)
	}
	if _, err := s.ReserveEmployeeInvite("e-code", false); err == nil || errors.Is(err, ErrInviteExhausted) {
		t.Errorf("employee redeem with a failing save = %v; want the save error", err)
	}
	s.invitesPath, s.empInvitesPath = okA, okE
	if _, err := s.RedeemInvite("a-code"); err != nil {
		t.Errorf("a failed save spent the asset invite: %v", err)
	}
	if _, err := s.ReserveEmployeeInvite("e-code", false); err != nil {
		t.Errorf("a failed save spent the employee invite: %v", err)
	}
}

// ReleaseEmployeeInvite gives back a reserved use.
func TestAReleasedEmployeeInviteCanBeRedeemedAgain(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEmployeeInvite(EmployeeInvite{Token: "e-code", Role: "staff", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveEmployeeInvite("e-code", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveEmployeeInvite("e-code", false); !errors.Is(err, ErrInviteExhausted) {
		t.Fatalf("second reserve = %v", err)
	}
	if err := s.ReleaseEmployeeInvite("e-code"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveEmployeeInvite("e-code", false); err != nil {
		t.Fatalf("released use was not given back: %v", err)
	}
}

// Only a file that can hold a secret stops the store from starting, and it is
// named. Any other unreadable file is an error on the store, not the refusal.
func TestOnlySecretFilesRefuseToStart(t *testing.T) {
	for _, name := range []string{"asset_invites.json", "employee_invites.json", "asset_enrolments.json"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, name), []byte(`{"code":{"token":"code"`), 0o600)
		_, err := NewStore(dir)
		if !errors.Is(err, ErrSecretsNotMigrated) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: NewStore = %v; want ErrSecretsNotMigrated naming it", name, err)
		}
	}
	for _, name := range []string{"assets.json", "asset_members.json", "asset_requests.json", "employees.json"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, name), []byte(`{"x":`), 0o600)
		_, err := NewStore(dir)
		if err == nil || errors.Is(err, ErrSecretsNotMigrated) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: NewStore = %v; want a plain error naming it", name, err)
		}
	}
}

// Clear secrets in the readable files are still carried to digests when an
// unrelated file is damaged.
func TestSecretsAreMigratedEvenWhenAnotherFileIsDamaged(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "employees.json"), []byte(`{"x":`), 0o600)
	os.WriteFile(filepath.Join(dir, "employee_invites.json"), []byte(`{"clear-code":{"token":"clear-code","max_uses":1}}`), 0o600)
	if _, err := NewStore(dir); err == nil || errors.Is(err, ErrSecretsNotMigrated) {
		t.Fatalf("NewStore = %v; want a plain error", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "employee_invites.json")); strings.Contains(string(b), "clear-code") {
		t.Fatalf("the clear code is still on disk: %s", b)
	}
}

// IncrementEmployeeInviteUse is kept for one caller and says so.
func TestIncrementEmployeeInviteUseIsMarkedDeprecated(t *testing.T) {
	src, err := os.ReadFile("employee_store.go")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "func (s *Store) IncrementEmployeeInviteUse")
	if i < 0 || !strings.Contains(string(src)[max(0, i-600):i], "Deprecated: ") {
		t.Fatal("IncrementEmployeeInviteUse must carry a Deprecated: paragraph")
	}
}
