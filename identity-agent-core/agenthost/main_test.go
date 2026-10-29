package agenthost

import (
	"os"
	"testing"
)

// TestMain lets this test program stand in for agent-host when a brain is run
// through `agent-host brain-home` or `agent-host brain-env`: executable() names
// the program running.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "brain-home" {
		os.Exit(ServeBrainHome(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "brain-env" {
		os.Exit(ServeBrainEnv(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "github-credential" {
		os.Exit(ServeGitHubCredential(os.Args[2:], os.Stdin, os.Stdout, os.Getenv))
	}
	if len(os.Args) > 1 && os.Args[1] == "loop" {
		os.Exit(ServeLoop(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
