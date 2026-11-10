//go:build windows

package atomicfile

import (
	"errors"
	"syscall"
)

const (
	errorInvalidFunction = syscall.Errno(1)  // ERROR_INVALID_FUNCTION
	errorNotSupported    = syscall.Errno(50) // ERROR_NOT_SUPPORTED
	errorInvalidParam    = syscall.Errno(87) // ERROR_INVALID_PARAMETER
	errorAccessDenied    = syscall.Errno(5)
	errorInvalidHandle   = syscall.Errno(6)
	stillActive          = 259
	processQueryLimited  = 0x1000
)

// processGone reports whether no process has this pid on this machine.
func processGone(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid))
	if err != nil {
		// Access denied means it exists. Invalid parameter means no such pid.
		return errors.Is(err, errorInvalidParam)
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code != stillActive
}

// linkUnsupportedPlatform is Windows' equivalent of EPERM/ENOTSUP: a
// filesystem (FAT, exFAT, some network shares) that cannot make hard links.
func linkUnsupportedPlatform(err error) bool {
	return errors.Is(err, errorInvalidFunction) || errors.Is(err, errorNotSupported)
}
