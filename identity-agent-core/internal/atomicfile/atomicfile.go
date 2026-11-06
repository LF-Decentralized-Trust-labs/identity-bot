// Package atomicfile writes a file so that a crash leaves either the old file
// or the new one, never part of either and never an empty one.
//
// Writing beside the target and renaming is not enough on its own. Without a
// flush the rename can reach the disk before the bytes do, and a power cut then
// leaves an empty file under the real name; without flushing the directory the
// rename itself can be lost. Each copy of this routine got a different subset of
// those steps right, so there is one, here.
package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Write replaces path with data, readable as perm.
func Write(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	if err := beforePlacing(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// beforePlacing runs after the new contents are written and flushed and
// before they take the target's name. Tests set it to stop a write there, as
// a crash would.
var beforePlacing = func() error { return nil }

// Create writes data to path only if nothing is there yet. When something
// is, the error satisfies errors.Is(err, fs.ErrExist) and the existing file
// is untouched: a caller racing another process for the same file adopts the
// one that won rather than replacing it.
func Create(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := beforePlacing(); err != nil {
		return err
	}
	if err := link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", filepath.Base(path), fs.ErrExist)
		}
		if !linksUnsupported(err) {
			// Any other failure (no space, permission on the directory, a
			// vanished directory) is the caller's to see, not a reason to
			// try a second way that would fail the same.
			return err
		}
		// No hard links here (FAT, some network and container mounts). Place
		// the file another way that still never shows a partial file.
		return createWithoutLink(tmp, path)
	}
	return syncDir(filepath.Dir(path))
}

// link is os.Link; tests replace it to stand in for a filesystem without
// hard links.
var link = os.Link

// linksUnsupported reports whether err from os.Link means this filesystem
// cannot make hard links, as opposed to any other failure.
func linksUnsupported(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EOPNOTSUPP) ||
		linkUnsupportedPlatform(err)
}

const (
	// lockWait is how long a Create waits for another Create of the same
	// path before giving up.
	lockWait = 10 * time.Second
	// lockStale is how old a lock must be before it is taken as left behind
	// when its holder cannot be identified (no readable pid, or one written
	// on another machine sharing the directory). A lock is held only across
	// a check and a rename, so a few seconds is generous. A lock whose
	// holder is a pid on this machine that no longer exists is stale at
	// once, however young.
	lockStale = 5 * time.Second
)

// lockBody is what a Create writes into its lock: pid and host, so a waiter
// can tell a dead holder from a slow one.
func lockBody() []byte {
	host, _ := os.Hostname()
	return []byte(fmt.Sprintf("%d %s", os.Getpid(), host))
}

// lockIsStale reports whether the lock file at lock was left by a process
// that is gone.
func lockIsStale(lock string) bool {
	fi, err := os.Lstat(lock)
	if err != nil {
		return false
	}
	if b, err := os.ReadFile(lock); err == nil {
		var pid int
		var host string
		if n, _ := fmt.Sscanf(string(b), "%d %s", &pid, &host); n >= 1 && pid > 0 {
			here, _ := os.Hostname()
			if n == 1 || host == here {
				return processGone(pid)
			}
		}
	}
	return time.Since(fi.ModTime()) > lockStale
}

// createWithoutLink places the already-written, flushed tmp at path if nothing
// is there, for a filesystem where os.Link fails. A rename would replace an
// existing file, so exclusivity comes from a lock file made with O_EXCL, held
// only across the check-and-rename; the content still arrives whole in one
// rename. It excludes other Creates of the same path, which is every writer of
// such a file.
func createWithoutLink(tmp, path string) error {
	lock := path + ".lock"
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.Write(lockBody())
			f.Close()
			if werr != nil {
				os.Remove(lock)
				return werr
			}
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		if _, serr := os.Lstat(path); serr == nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), fs.ErrExist)
		}
		if lockIsStale(lock) {
			os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: another writer holds %s", filepath.Base(path), filepath.Base(lock))
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer os.Remove(lock)
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeTemp writes data to a new file beside path, under a name nobody else
// is using, flushed and with its mode set, and returns its name.
//
// The name starts with path's own base name, so anything that recognises a
// file by its prefix recognises its temporary too.
func writeTemp(path string, data []byte, perm fs.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, perm); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// syncDir flushes a directory, so a rename or link in it survives a crash.
//
// Not on Windows, where a directory cannot be opened to flush and NTFS
// journals the change itself.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// IsTemp reports whether name is a temporary file one of these writes made
// and, if it is still there, a write that stopped part way left behind: the
// target's name, ".tmp-", and the digits os.CreateTemp chose.
func IsTemp(name string) bool {
	base := filepath.Base(name)
	i := strings.LastIndex(base, ".tmp-")
	if i <= 0 || i+len(".tmp-") == len(base) {
		return false
	}
	for _, c := range base[i+len(".tmp-"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// RemoveStale removes, under root and every directory below it, the
// temporaries that writes which stopped part way left behind, and returns
// what it removed. Only those untouched for olderThan: a write in flight,
// from this process or another sharing the directory, is touching its
// temporary now. Symbolic links are not followed.
//
// A leftover is a complete or partial copy of whatever was being written,
// and some of what is written here is private key material, so leftovers are
// not left to accumulate.
func RemoveStale(root string, olderThan time.Duration) ([]string, error) {
	var removed []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() || !IsTemp(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || time.Since(info.ModTime()) < olderThan {
			return nil
		}
		if err := os.Remove(path); err == nil {
			removed = append(removed, path)
		}
		return nil
	})
	return removed, err
}
