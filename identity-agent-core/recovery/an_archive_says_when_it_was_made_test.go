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
