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
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", filepath.Base(path), fs.ErrExist)
		}
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
// and, if it is still there, a write that stopped part way left behind. A
// directory that sweeps its own leftovers can recognise them by it.
func IsTemp(name string) bool {
	return strings.Contains(filepath.Base(name), ".tmp-")
}
