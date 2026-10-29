//go:build !windows

package agenthost

import (
	"os/exec"
	"syscall"
)

// ownGroup starts a command in a process group of its own, so everything it
// starts can be ended with it.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// procGroup is a started command and everything it starts.
type procGroup struct{ pid int }

// groupOf is the group of a command just started.
func groupOf(cmd *exec.Cmd) procGroup { return procGroup{pid: cmd.Process.Pid} }

// end ends the command's group: the command and whatever it started that is
// still running. After the command has been reaped its id names its group
// for as long as anything in the group lives, so it cannot be another's; once
// nothing does, it could only be one that a new process took for its own
// group in the moment since, which is accepted.
func (g procGroup) end() { _ = syscall.Kill(-g.pid, syscall.SIGKILL) }

// close lets go of the group; there is nothing to let go of here.
func (g procGroup) close() {}
