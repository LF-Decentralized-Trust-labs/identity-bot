package agenthost

import (
	"os"
	"testing"
)

// TestMain lets this test program stand in for agent-host when a brain is run
// through `agent-host brain-home`: executable() names the program running.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "brain-home" {
		os.Exit(ServeBrainHome(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
