package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/backup"
)

// The restore screen is given the time from inside the archive, and a warning
// when the archive is not what its name says or what this device has seen.
func TestRestoreShowsWhenTheArchiveWasMadeAndWarnsOfARenamedOldOne(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, backup.NewService(dir, nil))
	archive := buildTestArchive(t, testMnemonic, nil)

	fetch := func(key string) string {
		d, err := os.MkdirTemp(dir, backup.RestoringPrefix+"fetch-")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "archive.iab")
		if err := os.WriteFile(p, archive, 0o600); err != nil {
			t.Fatal(err)
		}
		return svc.keepFetched(p, key, func() { os.RemoveAll(d) })
	}

	// Made now, named for 2031: an old archive wearing a later name.
	ref := fetch("EtestRecoveryAID/backup-full-20310101-000000.iab")
	got, err := svc.Verify(VerifyRequest{ArchiveRef: ref, Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if got.ArchiveCreatedAt == "" {
		t.Fatal("the time the archive was made, from inside it, is not shown")
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "renamed") {
		t.Fatalf("a renamed archive must be warned about: %v", got.Warnings)
	}

	// An archive named truthfully is not warned about.
	ref = fetch("EtestRecoveryAID/backup-full-" + strings.NewReplacer("-", "", ":", "", "T", "-", "Z", "").Replace(got.ArchiveCreatedAt) + ".iab")
	got, err = svc.Verify(VerifyRequest{ArchiveRef: ref, Mnemonic: testMnemonic})
	if err != nil || len(got.Warnings) != 0 {
		t.Fatalf("%v %v", got, err)
	}

	// A reference is not a way to name a file: one this agent did not make is refused.
	if _, err := svc.Verify(VerifyRequest{ArchiveRef: "../../etc/passwd", Mnemonic: testMnemonic}); err == nil {
		t.Fatal("a made-up reference was accepted")
	}
}

// A local folder and a backup server hand the archive over directly, so the
// name it was found under comes back with it and is checked the same way.
func TestAnArchiveFromAFolderOrABackupServerIsHeldToItsOwnTimeToo(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, backup.NewService(dir, nil))
	archive := buildTestArchive(t, testMnemonic, nil)

	local := filepath.Join(t.TempDir(), "backup-full-20310101-000000.iab")
	if err := os.WriteFile(local, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Retrieve(RetrieveRequest{Source: SourceLocalFile, LocalPath: local})
	if err != nil || got.ArchiveName != "backup-full-20310101-000000.iab" {
		t.Fatalf("the name the archive was found under is not reported: %+v %v", got, err)
	}
	v, err := svc.Verify(VerifyRequest{ArchiveB64: got.ArchiveB64, ArchiveName: got.ArchiveName, Mnemonic: testMnemonic})
	if err != nil || len(v.Warnings) != 1 || !strings.Contains(v.Warnings[0], "renamed") {
		t.Fatalf("a renamed archive from a folder went unremarked: %v %v", v, err)
	}

	// The backup server's newest-by-name choice.
	aid := "E" + strings.Repeat("a", 43)
	held := filepath.Join(dir, "backup_receive", aid)
	if err := os.MkdirAll(held, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "20310101-000000.iab"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = svc.Retrieve(RetrieveRequest{Source: SourceBackupOnlyDevice, IdentityAID: aid})
	if err != nil || got.ArchiveName != "20310101-000000.iab" {
		t.Fatalf("%+v %v", got, err)
	}
	v, err = svc.Verify(VerifyRequest{ArchiveB64: got.ArchiveB64, ArchiveName: got.ArchiveName, Mnemonic: testMnemonic})
	if err != nil || len(v.Warnings) != 1 || !strings.Contains(v.Warnings[0], "renamed") {
		t.Fatalf("a renamed archive from a backup server went unremarked: %v %v", v, err)
	}
}
