package drivers

import (
	"strings"
	"testing"
)

// The failure this exists to prevent, and which comparing script paths cannot
// see: an agent running exactly the driver it was configured with, where that
// driver is older than the agent needs. Anchors handed to it are dropped, the
// event comes back well-formed and committing to nothing, and every test passes.
func TestADriverTooOldForThisAgentIsRefused(t *testing.T) {
	err := checkDriverProtocol(&DriverStatus{
		Status: "active", ScriptPath: "/opt/keri-host/server.py", DriverProtocol: 0,
	})
	if err == nil {
		t.Fatal("an agent accepted a driver that cannot do what it will ask of it")
	}
	// The message has to name the file, because the remedy is to update that
	// file and the reader needs to know which one answered.
	if !strings.Contains(err.Error(), "/opt/keri-host/server.py") {
		t.Errorf("the refusal does not say which driver answered: %v", err)
	}
	// And it has to say what goes wrong, or it reads as a version pedantry
	// rather than a correctness problem.
	if !strings.Contains(err.Error(), "commit to nothing") {
		t.Errorf("the refusal does not say what would go wrong: %v", err)
	}
}

func TestADriverAtTheRequiredContractIsAccepted(t *testing.T) {
	if err := checkDriverProtocol(&DriverStatus{
		Status: "active", DriverProtocol: requiredDriverProtocol,
	}); err != nil {
		t.Fatalf("a current driver was refused: %v", err)
	}
}

// A newer driver is fine. The agent states what it needs, not what it expects,
// so a driver ahead of it is not a problem to solve.
func TestANewerDriverIsAccepted(t *testing.T) {
	if err := checkDriverProtocol(&DriverStatus{
		Status: "active", DriverProtocol: requiredDriverProtocol + 5,
	}); err != nil {
		t.Fatalf("a newer driver was refused: %v", err)
	}
}

func TestNoDriverAtAllIsRefused(t *testing.T) {
	if err := checkDriverProtocol(nil); err == nil {
		t.Fatal("a missing driver passed the check")
	}
}
