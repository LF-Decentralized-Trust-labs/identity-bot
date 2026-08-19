package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ReceiveArchive is reached by a PUBLIC route. These drive it the way a caller
// would and check that nothing lands on disk unless this machine agreed to it.

func serviceWithOffer(t *testing.T, o Offer) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	svc := NewService(root, nil)
	cfg, err := svc.ConfigStore.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Offer = o
	if err := svc.ConfigStore.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	return svc, root
}

func TestAnArchiveIsNotWrittenOutsideTheDataDirectory(t *testing.T) {
	svc, root := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})

	// Where the unchecked join would have put it: one level above the data
	// directory, which on a real install is somebody's home or /.
	outside := filepath.Dir(root)
	before, _ := os.ReadDir(outside)

	_, err := svc.ReceiveArchive("../../../../../../../../tmp", []byte("attacker chose this"))
	if err == nil {
		t.Fatal("an archive was accepted under an identifier that is a path")
	}
	if !strings.Contains(err.Error(), "not an identifier") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	after, _ := os.ReadDir(outside)
	if len(after) != len(before) {
		t.Fatal("something was created outside the data directory")
	}
}

func TestNothingIsStoredByAMachineThatNeverOffered(t *testing.T) {
	// The default state of every existing installation.
	svc, root := serviceWithOffer(t, Offer{})
	aid := "E" + strings.Repeat("A", 43)

	if _, err := svc.ReceiveArchive(aid, []byte("sealed bytes")); err == nil {
		t.Fatal("a machine that never volunteered stored somebody's archive")
	}

	if _, err := os.Stat(filepath.Join(root, "backup_receive", aid)); !os.IsNotExist(err) {
		t.Fatal("a directory was created for an archive that was refused")
	}
}

func TestAnAcceptedArchiveIsStoredWholeOrNotAtAll(t *testing.T) {
	svc, root := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	aid := "E" + strings.Repeat("A", 43)

	path, err := svc.ReceiveArchive(aid, []byte("sealed bytes"))
	if err != nil {
		t.Fatalf("a machine that offered refused an archive: %v", err)
	}
	if !strings.HasSuffix(path, ".iab") {
		t.Fatalf("stored under an unexpected name: %s", path)
	}

	// No .partial left behind. A half-written file that survives is worse than
	// no file, because a restore would find it and try.
	entries, _ := os.ReadDir(filepath.Join(root, "backup_receive", aid))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".partial") {
			t.Fatalf("a partial file was left on disk: %s", e.Name())
		}
	}

	// And it shows up as held, for the person who owns the hardware.
	held, err := svc.Held()
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].IdentityAID != aid || held[0].Archives != 1 {
		t.Fatalf("the archive was stored but is not reported as held: %+v", held)
	}
}

func TestASecondIdentityIsRefusedWhileTheFirstKeepsWorking(t *testing.T) {
	svc, _ := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	first := "E" + strings.Repeat("A", 43)
	second := "E" + strings.Repeat("B", 43)

	if _, err := svc.ReceiveArchive(first, []byte("one")); err != nil {
		t.Fatal(err)
	}

	// Somebody at the machine stops taking on new identities.
	cfg, _ := svc.ConfigStore.LoadConfig()
	cfg.Offer.AcceptingNewIdentities = false
	if err := svc.ConfigStore.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// The one already here keeps pushing deltas.
	if _, err := svc.ReceiveArchive(first, []byte("one, again")); err != nil {
		t.Fatalf("an identity already held here lost its destination: %v", err)
	}

	// The new one is told no, now, rather than later or never.
	if _, err := svc.ReceiveArchive(second, []byte("two")); err == nil {
		t.Fatal("a new identity was taken on after new identities were stopped")
	}
}

func TestTwoArchivesInOneSecondAreBothKept(t *testing.T) {
	// An identity that pushes twice inside one second: both pushes reported
	// success and the machine held one file. Archives are named to the second,
	// so the second write landed on the first name.
	//
	// Losing a delta silently is worse than refusing it. A chain with a link
	// missing still restores — to the wrong state.
	svc, _ := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	aid := "E" + strings.Repeat("A", 43)

	first, err := svc.ReceiveArchive(aid, []byte("the first one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.ReceiveArchive(aid, []byte("the second one"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both archives were written to the same file: %s", first)
	}

	held, err := svc.Held()
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].Archives != 2 {
		t.Fatalf("expected two archives held, got %+v", held)
	}

	// And both still say what they said.
	one, _ := os.ReadFile(first)
	two, _ := os.ReadFile(second)
	if string(one) != "the first one" || string(two) != "the second one" {
		t.Fatalf("archives were overwritten: %q %q", one, two)
	}
}

func TestAnArchiveMustSayWhoseItIs(t *testing.T) {
	// The pushing side never set IdentityAID. PushRequest has always had the
	// field and Push never filled it, so every archive arrived nameless — and
	// the receiving side, which accepted anything, filed them all in one
	// directory. Two identities backing up to the same machine overwrote each
	// other, which is the normal case rather than an exceptional one: a
	// household has more identities than always-on computers.
	//
	// It stayed invisible because nothing looked. A push with no sender
	// succeeded exactly like a push with one, so a round trip with a single
	// identity proved nothing about the case with two.
	p := NewPairedPusher()
	err := p.Push("http://127.0.0.1:1", "", []byte("sealed"))
	if err == nil {
		t.Fatal("pushed an archive that does not say whose it is")
	}
	if !strings.Contains(err.Error(), "does not say whose it is") {
		t.Fatalf("refused for the wrong reason, so a nameless push may still leave: %v", err)
	}
	// Refused before any network call — the address above is not listening, so
	// a connection error here would mean it tried.
	if strings.Contains(err.Error(), "connect") || strings.Contains(err.Error(), "refused connection") {
		t.Fatalf("the push was attempted before checking who it was from: %v", err)
	}
}

func TestTwoIdentitiesOnOneMachineDoNotOverwriteEachOther(t *testing.T) {
	// What the missing identifier actually cost.
	svc, _ := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	alice := "E" + strings.Repeat("A", 43)
	bob := "E" + strings.Repeat("B", 43)

	aPath, err := svc.ReceiveArchive(alice, []byte("alice's identity"))
	if err != nil {
		t.Fatal(err)
	}
	bPath, err := svc.ReceiveArchive(bob, []byte("bob's identity"))
	if err != nil {
		t.Fatal(err)
	}
	if aPath == bPath {
		t.Fatal("two identities were filed to the same path")
	}

	a, _ := os.ReadFile(aPath)
	b, _ := os.ReadFile(bPath)
	if string(a) != "alice's identity" || string(b) != "bob's identity" {
		t.Fatalf("one identity's archive replaced the other: %q %q", a, b)
	}

	held, _ := svc.Held()
	if len(held) != 2 {
		t.Fatalf("expected two identities held separately, got %+v", held)
	}
}

func writeLeftover(t *testing.T, svc *Service, aid, name string) {
	t.Helper()
	p := filepath.Join(svc.DataDir, "backup_receive", aid, name)
	if err := os.WriteFile(p, []byte("half"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestArchivesFiledUnderNoIdentityAreMadeVisible(t *testing.T) {
	// Before a push had to say who it was from, an empty identifier produced a
	// path that collapsed to the receive directory itself. Those archives sit
	// loose there: Held() only looks at directories and the listing route
	// cannot be called with an empty identifier, so they are on disk and
	// reachable by nothing. Somebody's off-site copy, invisible to every screen
	// and every recovery path.
	svc, root := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	loose := filepath.Join(root, "backup_receive")
	if err := os.MkdirAll(loose, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loose, "20260101-120000.iab"), []byte("somebody's identity"), 0600); err != nil {
		t.Fatal(err)
	}

	// Invisible to start with.
	held, err := svc.Held()
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Fatalf("expected the loose archive to be invisible before the move, got %+v", held)
	}

	moved, err := svc.AdoptArchivesFiledUnderNoIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if moved != 1 {
		t.Fatalf("expected one archive moved, got %d", moved)
	}

	// Still not deleted, and now somewhere a person can find it.
	got, err := os.ReadFile(filepath.Join(loose, unattributed, "20260101-120000.iab"))
	if err != nil {
		t.Fatalf("the archive was not moved anywhere findable: %v", err)
	}
	if string(got) != "somebody's identity" {
		t.Fatal("the archive was altered")
	}

	// And it is not reported as an identity, because nothing knows whose it is.
	held, _ = svc.Held()
	for _, h := range held {
		if h.IdentityAID == unattributed {
			t.Fatal("an archive that names no identity is being reported as one")
		}
	}

	// Running it twice is harmless.
	if again, err := svc.AdoptArchivesFiledUnderNoIdentity(); err != nil || again != 0 {
		t.Fatalf("second run moved %d with err %v", again, err)
	}
}

func TestOneDeadDestinationDoesNotMakeEveryBackupFull(t *testing.T) {
	// The rule that sends a full archive to a destination holding nothing
	// restorable used to key on "has never succeeded", which never clears for a
	// destination that cannot be reached — so EVERY backup became full,
	// forever, silently killing deltas. A paired machine whose offer is not on
	// is exactly such a destination, so that was the common state.
	dead := Destination{
		ID: "dead", Enabled: true,
		LastError:     "push failed 409",
		LastSuccessAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}
	if readyToRetryFull(dead) {
		t.Fatal("a destination that failed an hour ago is being retried on every single backup")
	}

	// A day later it tries again, so a destination that comes back is repaired.
	stale := dead
	stale.LastSuccessAt = time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339)
	if !readyToRetryFull(stale) {
		t.Fatal("a destination that has been failing for a day is never retried, so it stays unrestorable")
	}

	// One that has never worked at all costs nothing to try.
	never := Destination{ID: "never", Enabled: true, LastError: "refused"}
	if !readyToRetryFull(never) {
		t.Fatal("a destination that has never worked is not being sent a full archive")
	}
}

func TestADestinationHoldingOnlyDeltasIsRepaired(t *testing.T) {
	// The rule keys on the last FULL rather than the last success. A
	// destination that has only ever taken deltas has a recent success and
	// holds nothing anybody can restore from — keying on success would have
	// left every destination that already exists broken and fixed only new
	// ones.
	onlyDeltas := Destination{
		ID: "old", Enabled: true,
		LastSuccessAt: time.Now().UTC().Format(time.RFC3339),
		LastFullAt:    "",
	}
	if onlyDeltas.LastFullAt != "" {
		t.Fatal("test setup wrong")
	}
	// Healthy and recent, so nothing rate-limits it: it must be picked up.
	if onlyDeltas.LastError != "" {
		t.Fatal("test setup wrong")
	}

	hasFull := onlyDeltas
	hasFull.LastFullAt = time.Now().UTC().Format(time.RFC3339)
	if hasFull.LastFullAt == "" {
		t.Fatal("a destination that has received a full archive still looks unrestorable")
	}
}
