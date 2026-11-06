package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A write replaces the file whole, with the mode asked for, and leaves
// nothing beside it.
func TestAWriteReplacesTheFileAndLeavesNothingBeside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("read back %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// A create never replaces what is there.
func TestACreateNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := Create(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, []byte("second"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("%v, want it to exist already", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "first" {
		t.Fatalf("read back %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// A write into a directory that is not there fails, and makes nothing.
func TestAWriteThatCannotHappenSaysSo(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "missing", "record.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("a write into a missing directory reported success")
	}
}

// A write stopped after its contents are on disk and before they take the
// target's name, as a crash would stop it, leaves no target and nothing
// beside it: never an empty or half-written file under the real name.
func TestAStoppedWriteLeavesNoPartialFile(t *testing.T) {
	stop := errors.New("stopped")
	beforePlacing = func() error { return stop }
	defer func() { beforePlacing = func() error { return nil } }()
	for _, write := range []func(string, []byte, fs.FileMode) error{Write, Create} {
		dir := t.TempDir()
		path := filepath.Join(dir, "owner_authority.json")
		if err := write(path, []byte(`{"aid":"E"}`), 0o600); !errors.Is(err, stop) {
			t.Fatalf("%v, want the stop", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("a stopped write left the target: %v", err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("a stopped write left %v", entries)
		}
	}
}

// Only a temporary this package names is one: the target's name, ".tmp-"
// and digits.
func TestATemporaryIsRecognisedByItsWholeName(t *testing.T) {
	for name, want := range map[string]bool{
		"didcomm_keys.json.tmp-123456": true,
		"shares_held/E.json.tmp-9":     true,
		"notes.tmp-draft":              false,
		".tmp-123":                     false,
		"record.json.tmp-":             false,
		"record.json":                  false,
	} {
		if IsTemp(name) != want {
			t.Errorf("IsTemp(%q) = %v, want %v", name, !want, want)
		}
	}
}

// Leftovers are removed at every depth once they are old, and one that is
// fresh, which may be a write in flight, is not. Nothing else is touched.
func TestStaleTemporariesAreRemovedAndFreshOnesKept(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "shares_held")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	write := func(path string, mtime time.Time) {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	staleTop := filepath.Join(root, "didcomm_keys.json.tmp-1")
	staleSub := filepath.Join(sub, "E.json.tmp-2")
	fresh := filepath.Join(sub, "F.json.tmp-3")
	kept := filepath.Join(sub, "E.json")
	write(staleTop, old)
	write(staleSub, old)
	write(fresh, time.Now())
	write(kept, old)
	removed, err := RemoveStale(root, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed %v, want the two stale temporaries", removed)
	}
	for _, p := range []string{staleTop, staleSub} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was left", p)
		}
	}
	for _, p := range []string{fresh, kept} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed: %v", p, err)
		}
	}
}

// noHardLinks makes Create's os.Link fail the way a filesystem without hard
// links does, for the length of the test.
func noHardLinks(t *testing.T) {
	t.Helper()
	old := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	t.Cleanup(func() { link = old })
}

func TestCreateWithoutHardLinksStillCreatesWhole(t *testing.T) {
	noHardLinks(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := Create(path, []byte("key"), 0o600); err != nil {
		t.Fatalf("Create failed where links are unsupported: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "key" {
		t.Fatalf("read back %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

func TestCreateWithoutHardLinksNeverReplaces(t *testing.T) {
	noHardLinks(t)
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("winner"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Create(path, []byte("loser"), 0o600)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "winner" {
		t.Fatalf("the existing file was replaced: %q", b)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// Several Creates of one path at once: one wins, the rest see it exist, and
// whoever reads afterwards sees the winner's whole content.
func TestCreateWithoutHardLinksHasOneWinner(t *testing.T) {
	noHardLinks(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	const n = 16
	var wins, exists atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch err := Create(path, []byte(fmt.Sprintf("writer-%02d", i)), 0o600); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, fs.ErrExist):
				exists.Add(1)
			default:
				t.Errorf("writer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 || exists.Load() != n-1 {
		t.Fatalf("%d winners, %d saw it exist; want 1 and %d", wins.Load(), exists.Load(), n-1)
	}
	if b, _ := os.ReadFile(path); len(b) != len("writer-00") {
		t.Fatalf("torn content %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// A lock left by a process that died must not block a Create for ever.
func TestCreateWithoutHardLinksReclaimsAStaleLock(t *testing.T) {
	noHardLinks(t)
	path := filepath.Join(t.TempDir(), "master.key")
	lock := path + ".lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); err == nil {
		t.Fatal("lock left behind")
	}
}

// Only "this filesystem has no hard links" falls back to the lock-and-rename
// way; any other failure from os.Link is returned and nothing is placed.
func TestCreateFallsBackOnlyWhereLinksAreUnsupported(t *testing.T) {
	old := link
	t.Cleanup(func() { link = old })
	for _, e := range []syscall.Errno{syscall.EPERM, syscall.ENOTSUP, syscall.EXDEV, syscall.EOPNOTSUPP} {
		link = func(string, string) error { return &os.LinkError{Op: "link", Err: e} }
		path := filepath.Join(t.TempDir(), "master.key")
		if err := Create(path, []byte("key"), 0o600); err != nil {
			t.Fatalf("%v: should fall back, got %v", e, err)
		}
		if b, _ := os.ReadFile(path); string(b) != "key" {
			t.Fatalf("%v: read back %q", e, b)
		}
	}
	for _, e := range []syscall.Errno{syscall.ENOSPC, syscall.EACCES, syscall.EIO} {
		link = func(string, string) error { return &os.LinkError{Op: "link", Err: e} }
		dir := t.TempDir()
		path := filepath.Join(dir, "master.key")
		err := Create(path, []byte("key"), 0o600)
		if !errors.Is(err, e) {
			t.Fatalf("%v: got %v, want that error returned", e, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("%v: left behind %v", e, entries)
		}
	}
}

func deadPid(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

// A lock whose holder's pid is gone is reclaimed at once, however young,
// not after the stale age or the 10 second wait.
func TestCreateWithoutHardLinksReclaimsADeadHoldersLockAtOnce(t *testing.T) {
	noHardLinks(t)
	path := filepath.Join(t.TempDir(), "master.key")
	host, _ := os.Hostname()
	if err := os.WriteFile(path+".lock", []byte(fmt.Sprintf("%d %s", deadPid(t), host)), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := Create(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("stalled %v behind a dead holder's lock", d)
	}
	if _, err := os.Stat(path + ".lock"); err == nil {
		t.Fatal("lock left behind")
	}
}

// A young lock held by a live process, this one, is not stale.
func TestALiveHoldersLockIsNotStale(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "master.key.lock")
	if err := os.WriteFile(lock, lockBody(), 0o600); err != nil {
		t.Fatal(err)
	}
	if lockIsStale(lock) {
		t.Fatal("a live holder's lock was taken as stale")
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(lock, old, old)
	if lockIsStale(lock) {
		t.Fatal("a live holder's old lock was taken as stale; only its pid decides")
	}
}
