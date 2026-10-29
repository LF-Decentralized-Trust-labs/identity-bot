//go:build linux

package agenthost

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The loop marks itself as a process other processes of its user may not
// read or trace, so a command it runs cannot take the run's tokens from it.
func TestTheLoopCannotBeReadByWhatItRuns(t *testing.T) {
	if err := notReadable(); err != nil {
		t.Fatal(err)
	}
	if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v != 0 {
		t.Fatalf("the process can still be read: %d %v", v, err)
	}
}
