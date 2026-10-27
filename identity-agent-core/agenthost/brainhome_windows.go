//go:build windows

package agenthost

import (
	"os"
	"os/exec"
	"time"
)

// interruptSignals are the signals that end `agent-host brain-home` early.
func interruptSignals() []os.Signal { return []os.Signal{os.Interrupt} }

// stopGently: Windows has no signal to ask a process to stop, so a cancelled
// run's wrapper is ended outright and cannot remove the sign-in file. It stays
// in that AI agent's home (homeName), readable only by the brain's user, until
// the next run of the same AI agent's brain on this machine removes it before
// anything else.
func stopGently(cmd *exec.Cmd) {
	cmd.WaitDelay = 15 * time.Second
}
