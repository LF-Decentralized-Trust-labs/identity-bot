//go:build linux

package agenthost

import "golang.org/x/sys/unix"

// notReadable marks this process as one other processes of its user may not
// read or trace: its environment and memory hold the run's tokens, and the
// commands it runs are of its user.
func notReadable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
