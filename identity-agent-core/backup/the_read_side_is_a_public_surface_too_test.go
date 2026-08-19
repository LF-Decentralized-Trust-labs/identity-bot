package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The receiving routes are unauthenticated, and half of them hand data OUT.
//
// The write path was given an identifier check. The two read routes beside it
// were not, and they take the same caller-supplied identifier and join it onto
// a path. So this answered, to anybody who could open a connection:
//
//	GET /api/backup/receive/..                             -> the data directory, listed
//	GET /api/backup/receive/../download/backup_config.json -> the file
//
// Hardening the side that stores data and not the side that serves it leaves
// the same hole with the arrow reversed.

func TestAnArchiveNameCannotBeAPath(t *testing.T) {
	for _, notAName := range []string{
		"../backup_config.json",
		"../../identity.json",
		"/etc/passwd",
		"contacts.json",
		"..",
		".",
		"",
		".iab",
		"20260819-120000.iab.partial", // a half-written file is not an archive
		"20260819-120000.iab/../../x",
		"a20260819.iab",
	} {
		if err := AcceptableArchiveName(notAName); err == nil {
			t.Fatalf("accepted %q as an archive name, so a caller could read any file", notAName)
		}
	}

	// The names this package actually produces must still work.
	for _, real := range []string{"20260819-120000.iab", "20260819-120000-1.iab"} {
		if err := AcceptableArchiveName(real); err != nil {
			t.Fatalf("refused a name we write ourselves, %q: %v", real, err)
		}
	}
}

func TestAPartialIsNeverOfferedAsAnArchive(t *testing.T) {
	// Recovery takes the last entry from ListReceived, and ".iab.partial"
	// sorts AFTER the ".iab" it was going to replace — so a transfer that died
	// became the file somebody restored from. Writing aside and renaming
	// achieves nothing if the reader picks up the aside copy.
	svc, _ := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	aid := "E" + strings.Repeat("A", 43)

	if _, err := svc.ReceiveArchive(aid, []byte("a real one")); err != nil {
		t.Fatal(err)
	}

	// A leftover from a push that died.
	writeLeftover(t, svc, aid, "20260819-999999.iab"+partialSuffix)

	paths, err := svc.ListReceived(aid)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, partialSuffix) {
			t.Fatalf("a half-written file is being offered as an archive: %s", p)
		}
	}
	if len(paths) != 1 {
		t.Fatalf("expected exactly the one finished archive, got %v", paths)
	}
}

func TestArchivesThatNameNobodyAreReportedRatherThanTidiedAway(t *testing.T) {
	// Moving orphaned archives into a directory is not the same as making them
	// visible. Held() skips any directory that is not a well-formed identifier,
	// deliberately — so moving them without also reporting them leaves them
	// exactly where they started, which is unseen, and an archive nobody can
	// see is the state this screen exists to end.
	svc, root := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})

	// Nothing loose: nothing reported.
	if u, err := svc.UnattributedArchives(); err != nil || u != nil {
		t.Fatalf("reported unattributed archives on a machine with none: %+v %v", u, err)
	}

	loose := filepath.Join(root, "backup_receive")
	if err := os.MkdirAll(loose, 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"20260101-120000.iab", "20260102-120000.iab"} {
		if err := os.WriteFile(filepath.Join(loose, n), make([]byte, 500), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.AdoptArchivesFiledUnderNoIdentity(); err != nil {
		t.Fatal(err)
	}

	u, err := svc.UnattributedArchives()
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("orphaned archives were moved and then reported nowhere, which is where they started")
	}
	if u.Archives != 2 || u.TotalBytes != 1000 {
		t.Fatalf("wrong count for what is held unattributed: %+v", u)
	}
	if u.LastArrivedAt == "" || u.Directory == "" {
		t.Fatalf("nothing a person could act on: %+v", u)
	}

	// And still not an identity, because nothing knows whose they are.
	held, _ := svc.Held()
	for _, h := range held {
		if h.IdentityAID == unattributed {
			t.Fatal("archives that name no identity are being reported as one")
		}
	}
}
