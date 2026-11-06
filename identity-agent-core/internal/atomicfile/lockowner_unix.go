//go:build !windows

package atomicfile

import (
	"errors"
	"syscall"
)

// processGone reports whether no process has this pid on this machine.
func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

// linkUnsupportedPlatform is the platform's own "this filesystem has no hard
// links" errors, beyond the shared list.
func linkUnsupportedPlatform(error) bool { return false }
