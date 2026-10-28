package agentmachine

import "testing"

func TestOnlyNamesThisPackageMakesAreValid(t *testing.T) {
	for _, agent := range []string{"Web researcher", "Dev worker", "!!!", "A very long name for an AI agent that goes on", "x"} {
		name, err := machineName(agent)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidMachineName(name) {
			t.Errorf("machineName(%q) = %q, which ValidMachineName refuses", agent, name)
		}
	}
	for _, name := range []string{
		"agent-orchestrator", "agent-dev-1", "proof1", "worker2",
		"3f2a9c1e-7b4d-4e8a-9f00-123456789abc", "agent--abcd", "agent-x-ABCD",
		"agent-x-abcd/../y", "agent-x-abcde", "agent-",
	} {
		if ValidMachineName(name) {
			t.Errorf("ValidMachineName(%q) = true; it is not a name this package makes", name)
		}
	}
}
