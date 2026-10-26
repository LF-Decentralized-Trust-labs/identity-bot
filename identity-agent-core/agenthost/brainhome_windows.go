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
// run's wrapper is ended outright, and the next run removes a sign-in file it
// left behind before anything else.
func stopGently(cmd *exec.Cmd) {
	cmd.WaitDelay = 15 * time.Second
}
