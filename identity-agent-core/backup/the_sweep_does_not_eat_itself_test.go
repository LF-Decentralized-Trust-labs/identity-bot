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
