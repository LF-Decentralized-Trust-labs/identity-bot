//go:build windows

package agenthost

import (
	"context"
	"fmt"
	"os/exec"
)

// AsUser would run the brain as a dedicated Windows user. Starting a process
// as another Windows user needs that user's credentials held by the host,
// which is not built yet; until it is, on a Windows machine a person also
// uses, the brain runs as that person's user.
type AsUser struct {
	User string
}

// Command refuses, saying why.
func (u AsUser) Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("running the brain as a separate Windows user is not available yet; run without --brain-user")
}

// Isolated reports that the brain runs as a user of its own.
func (u AsUser) Isolated() bool { return u.User != "" }
