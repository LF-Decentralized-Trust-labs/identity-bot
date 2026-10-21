//go:build !windows

package agenthost

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AsUser runs the brain as a dedicated operating-system user, through sudo,
// so a brain talked into misusing a tool still cannot read or write the
// person's own files: the system keeps it to its own home and workspace.
//
// sudo must be allowed to run the brain's program as that user without a
// password; `agent-host brain-user` prints the one-time setup.
type AsUser struct {
	User string
}

// Command builds the command.
func (u AsUser) Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	if u.User == "" {
		return nil, fmt.Errorf("no user named to run the brain as")
	}
	// sudo resets PATH, so the program is named by its full path.
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("the brain's program must be named by its full path when it runs as %s", u.User)
	}
	// The tool address and token pass through sudo in the environment, which
	// the sudoers rule allows (SETENV), rather than on the command line, which
	// sudo writes to the system log.
	full := []string{"-n", "-u", u.User, "-H"}
	if len(env) > 0 {
		var names []string
		for _, kv := range env {
			if i := strings.IndexByte(kv, '='); i > 0 {
				names = append(names, kv[:i])
			}
		}
		full = append(full, "--preserve-env="+strings.Join(names, ","))
	}
	full = append(append(full, "--", name), args...)
	cmd := exec.CommandContext(ctx, "sudo", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd, nil
}

// Isolated reports that the brain runs as a user of its own.
func (u AsUser) Isolated() bool { return u.User != "" }
