package server

import (
	"os"
	"strings"
	"testing"
)

// Saving a ceremony writes digests of the invitees' codes, never the codes,
// and leaves the caller's copy able to hand them out.
func TestACeremonyOnDiskHoldsNoInviteCode(t *testing.T) {
	s := ceremonyServer(t)
	c := collecting("Ada")
	ceremonyMu.Lock()
	err := s.saveCeremony(c)
	ceremonyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if c.Invited[0].Token != "tok-a" {
		t.Error("saving took the code out of the caller's copy")
	}
	raw, _ := os.ReadFile(s.ceremonyPath())
	if strings.Contains(string(raw), "tok-a") {
		t.Errorf("the ceremony file holds an invite code in the clear:\n%s", raw)
	}
	got, complete, err := s.recordAcceptance("tok-a", "EAda", "key", "next")
	if err != nil || got == nil || !complete {
		t.Fatalf("the code did not still redeem its invite: %v %v %v", got, complete, err)
	}
	if got, _, _ := s.recordAcceptance("tok-b", "EX", "k", "n"); got != nil {
		t.Error("a wrong code redeemed an invite")
	}
}

// A ceremony file from an earlier version, with clear codes, is rewritten as
// digests when the server is made, and its codes still work.
func TestACeremonyWithClearCodesIsMigrated(t *testing.T) {
	s := ceremonyServer(t)
	legacy := `{"id":"c1","threshold":2,"status":"collecting","invited":[{"name":"Ada","token":"clear-code","invite_url":"u"}]}`
	if err := os.WriteFile(s.ceremonyPath(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateCeremony(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(s.ceremonyPath())
	if strings.Contains(string(raw), "clear-code") {
		t.Errorf("the clear code is still on disk:\n%s", raw)
	}
	if got, _, err := s.recordAcceptance("clear-code", "EAda", "k", "n"); err != nil || got == nil {
		t.Fatalf("a migrated code no longer redeems: %v %v", got, err)
	}
}

// If the old file cannot be rewritten the server does not start.
func TestACeremonyThatCannotBeMigratedStopsTheStart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	s := ceremonyServer(t)
	legacy := `{"id":"c1","status":"collecting","invited":[{"name":"Ada","token":"clear-code"}]}`
	os.WriteFile(s.ceremonyPath(), []byte(legacy), 0o600)
	os.Chmod(s.DataDir, 0o500) // the file can be read but not rewritten
	defer os.Chmod(s.DataDir, 0o700)
	if err := s.migrateCeremony(); err == nil {
		t.Fatal("a ceremony holding clear codes was left as it was")
	}
}
