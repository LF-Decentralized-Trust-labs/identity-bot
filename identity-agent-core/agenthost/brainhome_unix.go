//go:build !windows

package agenthost

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// interruptSignals are the signals that end `agent-host brain-home` early,
// after it has taken the sign-in file away.
func interruptSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }

// stopGently makes a cancelled run ask the wrapper to stop, so it removes the
// sign-in file, before it is killed. sudo passes the signal on to it.
func stopGently(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 15 * time.Second
}
