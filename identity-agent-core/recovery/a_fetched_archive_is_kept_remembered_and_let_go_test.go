package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/backup"
)

// fetchedInto puts an archive on disk the way a cloud fetch does and registers
// it, returning its reference and whether its cleanup has run.
func fetchedInto(t *testing.T, svc *Service, archive []byte, key string) (ref string, released func() bool) {
	t.Helper()
	d, err := os.MkdirTemp(svc.DataDir, backup.RestoringPrefix+"fetch-")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "archive.iab")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	ref = svc.keepFetched(p, key, func() { ran = true; os.RemoveAll(d) })
	return ref, func() bool { return ran }
}

// Opening an archive for restore is remembered, so that an older one opened
// later can be recognised. Fails if the restore never calls NoteArchiveSeen.
func TestOpeningAnArchiveForRestoreIsRemembered(t *testing.T) {
	dir := t.TempDir()
	bs := backup.NewService(dir, nil)
	svc := NewService(dir, nil, bs)
	archive := buildTestArchive(t, testMnemonic, nil)
	if !bs.ConfigStore.NewestArchiveSeen().IsZero() {
		t.Fatal("a new machine has seen nothing")
	}
	ref, _ := fetchedInto(t, svc, archive, "EtestRecoveryAID/backup-full-x.iab")
	got, err := svc.Verify(VerifyRequest{ArchiveRef: ref, Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	want, err := time.Parse(time.RFC3339, got.ArchiveCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if seen := bs.ConfigStore.NewestArchiveSeen(); !seen.Equal(want) {
		t.Fatalf("the archive opened was not remembered: seen %v, archive made %v", seen, want)
	}
}

// An archive older than one this device has already made or opened is warned
// about. Fails if the restore ignores the newest-seen record.
func TestAnOlderArchiveThanOneAlreadySeenIsWarnedAbout(t *testing.T) {
	dir := t.TempDir()
	bs := backup.NewService(dir, nil)
	svc := NewService(dir, nil, bs)
	archive := buildTestArchive(t, testMnemonic, nil)

	bs.ConfigStore.NoteArchiveSeen(time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339))
	ref, _ := fetchedInto(t, svc, archive, "EtestRecoveryAID/backup-full-x.iab")
	got, err := svc.Verify(VerifyRequest{ArchiveRef: ref, Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "not the newest backup this device has seen") {
		t.Fatalf("an archive older than one already seen went unremarked: %v", got.Warnings)
	}

	// The same through Start, which is what records the session the person acts on.
	ref, _ = fetchedInto(t, svc, archive, "EtestRecoveryAID/backup-full-x.iab")
	sess, err := svc.Start(StartRequest{ArchiveRef: ref, Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.Warnings) != 1 || !strings.Contains(sess.Warnings[0], "not the newest backup this device has seen") {
		t.Fatalf("Start dropped the warning: %v", sess.Warnings)
	}
}

// Only maxFetched archives are kept; fetching another lets the oldest go,
// running its cleanup. Fails if eviction is removed.
func TestFetchingMoreThanTheLimitLetsTheOldestGo(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, backup.NewService(dir, nil))
	archive := buildTestArchive(t, testMnemonic, nil)

	var refs []string
	var released []func() bool
	for i := 0; i <= maxFetched; i++ {
		ref, rel := fetchedInto(t, svc, archive, "EtestRecoveryAID/backup-full-x.iab")
		refs = append(refs, ref)
		released = append(released, rel)
		time.Sleep(5 * time.Millisecond) // distinct "made" times
	}
	if !released[0]() {
		t.Fatal("the oldest fetched archive was not cleaned up")
	}
	if _, err := svc.Verify(VerifyRequest{ArchiveRef: refs[0], Mnemonic: testMnemonic}); err == nil ||
		!strings.Contains(err.Error(), "gone") {
		t.Fatalf("the evicted reference still works: %v", err)
	}
	for i := 1; i <= maxFetched; i++ {
		if released[i]() {
			t.Fatalf("archive %d was cleaned up though it is within the limit", i)
		}
		if _, err := svc.Verify(VerifyRequest{ArchiveRef: refs[i], Mnemonic: testMnemonic}); err != nil {
			t.Fatalf("archive %d should still be there: %v", i, err)
		}
	}
}

// Once a recovery has started from a fetched archive, the session holds what it
// needs and the file is removed. Fails if Start does not call finishedWith.
func TestAFetchedArchiveIsLetGoOnceARecoveryHasStarted(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, backup.NewService(dir, nil))
	archive := buildTestArchive(t, testMnemonic, nil)
	ref, released := fetchedInto(t, svc, archive, "EtestRecoveryAID/backup-full-x.iab")

	// Verify alone does not let it go: the person goes on to Start.
	if _, err := svc.Verify(VerifyRequest{ArchiveRef: ref, Mnemonic: testMnemonic}); err != nil {
		t.Fatal(err)
	}
	if released() {
		t.Fatal("Verify removed the archive before Start could use it")
	}
	if _, err := svc.Start(StartRequest{ArchiveRef: ref, Mnemonic: testMnemonic}); err != nil {
		t.Fatal(err)
	}
	if !released() {
		t.Fatal("Start left the fetched archive on disk")
	}
	if _, err := svc.Start(StartRequest{ArchiveRef: ref, Mnemonic: testMnemonic}); err == nil {
		t.Fatal("the reference still works after the archive was let go")
	}
}
