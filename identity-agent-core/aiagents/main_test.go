package aiagents

import (
	"os"
	"testing"

	"identity-agent-core/agenthost"
)

// TestMain lets this test program stand in for agent-host when a body's brain
// runs through `agent-host brain-home`, which names the program running.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "brain-home" {
		os.Exit(agenthost.ServeBrainHome(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "github-credential" {
		os.Exit(agenthost.ServeGitHubCredential(os.Args[2:], os.Stdin, os.Stdout, os.Getenv))
	}
	if len(os.Args) > 1 && os.Args[1] == "loop" {
		os.Exit(agenthost.ServeLoop(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
