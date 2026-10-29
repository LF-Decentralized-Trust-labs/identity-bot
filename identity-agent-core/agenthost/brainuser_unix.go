//go:build !windows

package agenthost

import (
	"context"
	"fmt"
	"identity-agent-core/childenv"
	"io"
	"os/exec"
	"path/filepath"
)

// AsUser runs the brain as a dedicated operating-system user, through sudo,
// so a brain talked into misusing a tool still cannot read or write the
// person's own files: the system keeps it to its own home and workspace.
//
// sudo must be allowed to run `agent-host brain-env` for the brain's program
// as that user without a password; `agent-host brain-user` prints the
// one-time setup.
type AsUser struct {
	User string
}

// Command builds the command. sudo writes its command line and every
// variable it passes on to the system log, so the run's variables — its tool
// token, the sign-in and GitHub access it was lent — go on stdin to
// `agent-host brain-env`, which puts them in the brain's environment
// (brainEnvInput). sudo is told to pass nothing on, and nothing secret is on
// its command line.
func (u AsUser) Command(ctx context.Context, dir string, env []string, stdin io.Reader, name string, args ...string) (*exec.Cmd, error) {
	if u.User == "" {
		return nil, fmt.Errorf("no user named to run the brain as")
	}
	// sudo resets PATH, so the program is named by its full path.
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("the brain's program must be named by its full path when it runs as %s", u.User)
	}
	self, err := executable()
	if err != nil {
		return nil, err
	}
	in, err := brainEnvInput(env, stdin)
	if err != nil {
		return nil, err
	}
	full := append([]string{"-n", "-u", u.User, "-H", "--", self, "brain-env", "--", name}, args...)
	// The brain starts in its workspace, which the host can enter (mode 711)
	// but not list, so the host can start it there without reading it.
	cmd := exec.CommandContext(ctx, "sudo", full...)
	cmd.Dir = dir
	cmd.Env = withoutLent(childenv.Environ())
	cmd.Stdin = in
	return cmd, nil
}

// Isolated reports that the brain runs as a user of its own.
func (u AsUser) Isolated() bool { return u.User != "" }
