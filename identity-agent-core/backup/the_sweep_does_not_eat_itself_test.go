package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A backup written into the data directory must not end up inside the next one.
//
// Without an exclusion this compounds: run one carries nothing, run two carries
// run one, run three carries run two carrying run one. The archive grows
// without bound and nothing reports an error, because every individual step
// worked exactly as written.
func TestAnArchiveIsNotCarriedInsideTheNextArchive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backup-full-20260813-120000.iab"),
		make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Collector{DataDir: dir}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	skipped, err := c.collectEveryOtherFile(bundle)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	for name := range bundle.Sections {
		if strings.HasSuffix(name, ".iab") {
			t.Fatalf("an archive was carried inside the archive: %s", name)
		}
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "nest") {
		t.Errorf("the exclusion should be recorded with its reason, got %+v", skipped)
	}
}

// A file the collector has never heard of is carried, including a nested one.
func TestAnUnknownFileIsCarriedWhereverItSits(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "some", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "some", "nested", "state.db"),
		[]byte("kept by something built on top of this core"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Collector{DataDir: dir}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	if _, err := c.collectEveryOtherFile(bundle); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// Forward slashes regardless of platform, so an archive taken on one
	// restores on another.
	if _, ok := bundle.Sections["file:some/nested/state.db"]; !ok {
		var names []string
		for n := range bundle.Sections {
			names = append(names, n)
		}
		t.Fatalf("a nested file was not carried under a portable name, got %v", names)
	}
}

// A section name is the one part of an archive that becomes a filesystem path.
func TestASectionNameCannotEscapeTheDataDirectory(t *testing.T) {
	for _, bad := range []string{
		FileSectionPrefix + "../outside.txt",
		FileSectionPrefix + "../../etc/passwd",
		FileSectionPrefix + "",
	} {
		if _, ok := FilePathOfSection(bad); ok {
			t.Errorf("%q was accepted as a path to write to", bad)
		}
	}
	if _, ok := FilePathOfSection("contacts"); ok {
		t.Error("a section that is not a file section was treated as one")
	}
	if got, ok := FilePathOfSection(FileSectionPrefix + "a/b.db"); !ok ||
		got != filepath.FromSlash("a/b.db") {
		t.Errorf("an ordinary nested path should resolve, got %q ok=%v", got, ok)
	}
}

// The sweep never leaves the agent's own storage.
//
// It takes everything the Identity Agent keeps, which is everything under its
// data directory — not everything on the machine. Worth a test rather than a
// comment: the difference between those two readings is somebody's entire home
// directory ending up inside a backup archive.
func TestTheSweepStaysInsideTheDataDirectory(t *testing.T) {
	parent := t.TempDir()

	// The agent's storage, and a sibling that has nothing to do with it.
	dataDir := filepath.Join(parent, "agent-data")
	elsewhere := filepath.Join(parent, "somebody-elses-documents")
	for _, d := range []string{dataDir, elsewhere} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "mine.db"), []byte("the agent's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "tax-returns.pdf"),
		[]byte("nothing to do with the Identity Agent"), 0o600); err != nil {
		t.Fatal(err)
	}

	// And a symlink from inside the data directory pointing out of it, which is
	// the way a sweep escapes without anybody meaning it to.
	_ = os.Symlink(elsewhere, filepath.Join(dataDir, "a-link-outward"))

	c := &Collector{DataDir: dataDir}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	if _, err := c.collectEveryOtherFile(bundle); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if _, ok := bundle.Sections["file:mine.db"]; !ok {
		t.Error("the agent's own file was not collected")
	}
	for name, data := range bundle.Sections {
		if strings.Contains(name, "tax-returns") || strings.Contains(string(data), "nothing to do with") {
			t.Fatalf("the sweep reached outside the agent's storage: %s", name)
		}
	}
}
