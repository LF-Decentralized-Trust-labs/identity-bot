//go:build !windows

package backup

import "syscall"

// freeBytes is how much room is left where archives are kept.
//
// Split by platform because syscall.Statfs does not exist on Windows, and
// Windows is one of the platforms this runs on. Without the split the whole
// module failed to build there — the failure was invisible on a Unix machine,
// which is where it was written.
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
