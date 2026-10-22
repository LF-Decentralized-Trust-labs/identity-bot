package server

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// A root seed that is stored and cannot be read is refused, never replaced.
// Replacing it would put a new random seed over the only copy of every key
// derived from the old one.
func TestASeedThatCannotBeReadIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secureenclave", "root_seed.key")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	damaged := []byte(`{"v":1,"wrap":"some-wrapping-this-build-cannot-open","blob":"AAAA"}`)
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureRootSeed(dir); err == nil {
		t.Fatal("an unreadable seed was answered with a seed")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, damaged) {
		t.Fatal("the unreadable seed was overwritten")
	}
}

// A machine that never held a seed gets one.
func TestAMachineWithNoSeedGetsOne(t *testing.T) {
	dir := t.TempDir()
	if _, err := secureenclave.LoadRootSeed(dir); !errors.Is(err, secureenclave.ErrNoRootSeed) {
		t.Fatalf("a missing seed is not reported as missing: %v", err)
	}
	seed, err := ensureRootSeed(dir)
	if err != nil || len(seed) != 64 {
		t.Fatalf("no seed was made: %v", err)
	}
	again, err := ensureRootSeed(dir)
	if err != nil || !bytes.Equal(seed, again) {
		t.Fatal("the seed made was not the one read back")
	}
}

// A claimed machine whose seed is missing does not get a new one for a relay:
// its keys derive from the seed it had, and a new one would enrol as somebody
// else.
func TestARelayDoesNotMakeASeedForAClaimedMachine(t *testing.T) {
	dir := t.TempDir()
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: testDataStore(t, dir)}
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: "ECLAIMEDIDENTITY"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadRelayEnrolment(privateRelay, "https://relay.example"); err == nil {
		t.Fatal("a relay enrolled a claimed machine with no seed")
	}
	if _, err := secureenclave.LoadRootSeed(dir); !errors.Is(err, secureenclave.ErrNoRootSeed) {
		t.Fatal("a relay made a root seed for a claimed machine")
	}
}
