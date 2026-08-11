package server

import (
	"testing"
)

// Mobile runs with the Python driver disabled, because a phone cannot spawn a
// subprocess. Before the engine interface existed that left the core with no
// KERI implementation at all: every call site guarded on the driver being
// present and answered "not available", so a phone could not create an
// identity, rotate a key or issue a credential through the core.
//
// This asserts the arrangement that fixed it, rather than leaving it to be
// re-derived from the configuration. If it fails, mobile has silently lost KERI
// again, and the symptom would otherwise appear as an unexplained "not
// available" on a device.
func TestMobileGetsAKeriEngineEvenWithTheDriverDisabled(t *testing.T) {
	cfg := Config{
		DataDir:          t.TempDir(),
		Port:             0,
		EnableKeriDriver: false, // exactly what mobilecore passes
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("creating the core with the driver disabled failed: %v", err)
	}
	defer s.Stop()

	if s.KeriDriver == nil {
		t.Fatal("the core has no KERI engine with the driver disabled, so every KERI " +
			"operation on mobile would report itself unavailable")
	}
	status, err := s.KeriDriver.GetStatus()
	if err != nil {
		t.Fatalf("the engine does not report a status: %v", err)
	}
	if status.Status != "active" {
		t.Fatalf("the engine is present but reports %q", status.Status)
	}

	// It must actually work, not merely exist.
	pub := "DDRMAuLAoa-uPycYJudpUBVaF8PO4J-GLrCSQD2K3Hqx"
	next := "DL6mIBjSF7hxDPTRnMPQOWnHZQhFPfM5Q3aOAqFqZKD5"
	got, err := s.KeriDriver.CreateInceptionNamed(pub, next, "mobile-test")
	if err != nil {
		t.Fatalf("the engine could not create an identity: %v", err)
	}
	if got.AID == "" {
		t.Fatal("the engine created an identity with no identifier")
	}
}
