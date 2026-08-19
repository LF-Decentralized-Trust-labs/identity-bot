package recovery

import (
	"identity-agent-core/backup"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Retrieval must hand back an archive, and nothing else.
//
// Two read paths took a caller-supplied path and returned the bytes
// base64-encoded. Local retrieval read any absolute path at all; backup-only
// retrieval joined a caller-supplied identifier and filename without the checks
// its sibling HTTP route had been given.
//
// Why that mattered more than an ordinary file read: on every platform without
// a hardware wrapper the root seed is stored unwrapped in the data directory,
// and that seed derives both the backup key and the seal keypair. One read of
// it opens every archive that identity has ever written — past and future —
// with the recovery phrase never involved.

func TestLocalRetrievalHandsBackArchivesAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secureenclave"), 0700); err != nil {
		t.Fatal(err)
	}
	// The file that must never come back. Its contents are the identity: on
	// every platform without a hardware wrapper it is stored unwrapped, and it
	// derives both the backup key and the seal keypair.
	seed := filepath.Join(dir, "secureenclave", "root_seed.key")
	if err := os.WriteFile(seed, []byte(`{"wrap":"none","blob":"c2VjcmV0"}`), 0600); err != nil {
		t.Fatal(err)
	}

	svc := NewService(dir, nil, nil)

	for _, path := range []string{
		seed,
		filepath.Join(dir, "identity.db"),
		"/etc/passwd",
		filepath.Join(dir, "does-not-exist"),
	} {
		if _, err := svc.Retrieve(RetrieveRequest{
			Source: SourceLocalFile, LocalPath: path,
		}); err == nil {
			t.Fatalf("retrieval returned %s", path)
		}
	}

	// A file NAMED like an archive is still refused, because the name is not
	// the check.
	pretend := filepath.Join(dir, "pretend.iab")
	if err := os.WriteFile(pretend, []byte(`{"wrap":"none","blob":"c2VjcmV0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Retrieve(RetrieveRequest{Source: SourceLocalFile, LocalPath: pretend}); err == nil {
		t.Fatal("a file called .iab was returned without being one")
	}

	// A symlink pointing at the seed is refused even though it resolves to a
	// readable file, because os.ReadFile follows one and a symlink is how a
	// confined directory stops being confined.
	link := filepath.Join(dir, "sneaky.iab")
	if err := os.Symlink(seed, link); err == nil {
		if _, err := svc.Retrieve(RetrieveRequest{Source: SourceLocalFile, LocalPath: link}); err == nil {
			t.Fatal("a symlink to the root seed was followed and returned")
		}
	}

	// And a real archive comes back — from anywhere, which is the case this
	// route exists for. Somebody restoring onto a new machine has their archive
	// on a USB stick, and this agent's own export directory is empty because a
	// fresh machine has never made a backup.
	elsewhere := filepath.Join(t.TempDir(), "from-a-usb-stick.iab")
	if err := os.WriteFile(elsewhere, buildTestArchive(t, testMnemonic, nil), 0600); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Retrieve(RetrieveRequest{Source: SourceLocalFile, LocalPath: elsewhere})
	if err != nil {
		t.Fatalf("a real archive outside the data directory was refused: %v", err)
	}
	if resp.SizeBytes == 0 {
		t.Fatal("nothing came back")
	}
}

func TestBackupOnlyRetrievalChecksWhatItIsGiven(t *testing.T) {
	// The sibling of the HTTP download route, which was given these checks
	// while this one was not.
	//
	// A real archive is stored under a real identifier first, deliberately.
	// Without one, every case below fails on "no archives received" before the
	// identifier or the name is ever used to build a path — so the test passes
	// whether or not the checks exist, which is exactly what it did.
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	bsvc := backup.NewService(dir, nil)
	svc.BackupService = bsvc

	aid := "E" + strings.Repeat("A", 43)
	cfg, err := bsvc.ConfigStore.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Offer = backup.Offer{Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024}
	if err := bsvc.ConfigStore.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := bsvc.ReceiveArchive(aid, buildTestArchive(t, testMnemonic, nil)); err != nil {
		t.Fatal(err)
	}

	// The files a traversal would reach must actually exist, or every case
	// below fails because the read found nothing — which passes whether or not
	// the checks are there, and is what the first version of this test did.
	if err := os.MkdirAll(filepath.Join(dir, "secureenclave"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		filepath.Join(dir, "secureenclave", "root_seed.key"),
		filepath.Join(dir, "identity.db"),
		filepath.Join(dir, "backup_receive", aid, "root_seed.key"),
	} {
		if err := os.WriteFile(f, []byte("the identity"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// The held archive is reachable by its own identifier, so the refusals
	// below are about the input and not about there being nothing there.
	if _, err := svc.Retrieve(RetrieveRequest{
		Source: SourceBackupOnlyDevice, IdentityAID: aid,
	}); err != nil {
		t.Fatalf("a held archive could not be retrieved at all: %v", err)
	}

	for _, req := range []RetrieveRequest{
		{Source: SourceBackupOnlyDevice, IdentityAID: "../.."},
		{Source: SourceBackupOnlyDevice, IdentityAID: "../../secureenclave"},
		{Source: SourceBackupOnlyDevice, IdentityAID: aid, ArchiveName: "../../../identity.db"},
		{Source: SourceBackupOnlyDevice, IdentityAID: aid, ArchiveName: "../../secureenclave/root_seed.key"},
		{Source: SourceBackupOnlyDevice, IdentityAID: aid, ArchiveName: "root_seed.key"},
	} {
		if _, err := svc.Retrieve(req); err == nil {
			t.Fatalf("retrieval accepted %+v", req)
		}
	}
}
