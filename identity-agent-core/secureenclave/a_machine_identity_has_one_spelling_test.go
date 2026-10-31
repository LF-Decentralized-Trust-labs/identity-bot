package secureenclave

import (
	"strings"
	"testing"
)

// A machine identity is compared as text, so it is read in lowercase hex
// only: in uppercase it would read as a different machine.
func TestAMachineIdentityIsReadInLowercaseOnly(t *testing.T) {
	value := strings.Repeat("ab", 64)
	if _, err := ParseMachineIdentity(string(MachineIDSNPChip), value); err != nil {
		t.Fatalf("a lowercase identity was refused: %v", err)
	}
	if _, err := ParseMachineIdentity(string(MachineIDSNPChip), strings.ToUpper(value)); err == nil {
		t.Fatal("an uppercase identity was accepted")
	}
}
