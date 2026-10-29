//go:build windows

package agenthost

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownGroup does nothing before a command starts on Windows: groupOf puts it
// in a job, which ends with everything in it.
func ownGroup(cmd *exec.Cmd) {}

// procGroup is a started command's job: the command and everything it starts.
type procGroup struct{ job windows.Handle }

// groupOf puts a command just started in a job of its own, which ends every
// process in it when it is ended or let go of. A process the command starts
// in the moment before it is put there is not in it.
func groupOf(cmd *exec.Cmd) procGroup {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return procGroup{}
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, _ = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		_ = windows.AssignProcessToJobObject(job, p)
		_ = windows.CloseHandle(p)
	}
	return procGroup{job: job}
}

// end ends every process in the job.
func (g procGroup) end() {
	if g.job != 0 {
		_ = windows.TerminateJobObject(g.job, 1)
	}
}

// close lets go of the job, which ends whatever is still in it.
func (g procGroup) close() {
	if g.job != 0 {
		_ = windows.CloseHandle(g.job)
	}
}
