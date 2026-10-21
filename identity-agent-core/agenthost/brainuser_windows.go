//go:build windows

package agenthost

import (
	"context"
	"fmt"
	"os/exec"
)

// AsUser would run the brain as a dedicated Windows user. Starting a process
// as another Windows user needs that user's credentials held by the host,
// which is not built yet; until it is, the brain runs as the host's own user
// and the tool allow list is what keeps it to the host's tools.
type AsUser struct {
	User string
}

// Command refuses, saying why.
func (u AsUser) Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("running the brain as a separate Windows user is not available yet; run without --brain-user")
}
