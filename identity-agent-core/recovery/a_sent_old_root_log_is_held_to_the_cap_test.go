package recovery

import (
	"strings"
	"testing"

	"identity-agent-core/drivers"
)

// The old root's log a continuity proof carries was sent by somebody, so it is
// held to the cap on a sent log; the log of a root this Identity Agent keeps is
// judged at any length.
func TestASentOldRootLogIsHeldToTheCapOnASentLog(t *testing.T) {
	long := make([]drivers.SignedEventBytes, drivers.MaxLogEvents+1)
	if err := verifySentLog("Eold", long); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("a sent log longer than the cap was not refused for it: %v", err)
	}
	if err := verifyLog("Eold", long); err != nil && strings.Contains(err.Error(), "at most") {
		t.Fatalf("a kept log was refused for its length: %v", err)
	}
}
