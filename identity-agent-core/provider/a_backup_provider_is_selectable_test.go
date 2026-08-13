package provider

import "testing"

// Keeping archives for somebody is a service like any other.
//
// A destination is chosen for AVAILABILITY rather than trust — it holds
// ciphertext and never the key — which is why it belongs in the same registry
// as witnessing rather than in a list of its own. A capability the agent does
// not recognise is kept but never selected, so declaring the constant without
// teaching Known() about it would leave every backup provider unselectable
// while looking entirely correct.
func TestABackupProviderIsSelectable(t *testing.T) {
	if !CapabilityBackup.Known() {
		t.Fatal("a registry offering backup would be kept and never selected")
	}
	if CapabilityBackup != "backup" {
		t.Errorf("the wire name is part of the registry format: %q", CapabilityBackup)
	}
}

func TestAnUnknownCapabilityIsStillUnknown(t *testing.T) {
	if Capability("toaster").Known() {
		t.Fatal("Known() now accepts anything, so it protects nothing")
	}
}
