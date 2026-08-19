package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
