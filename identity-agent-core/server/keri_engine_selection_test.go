package server

import (
	"testing"
)

// Every core comes up with a working KERI engine, on every platform.
//
// There is one engine, keri-go, and it runs in-process. A phone cannot spawn a
// subprocess, and before the engine ran in-process that left the core with no
// KERI implementation at all: every call site guarded on a driver being present
// and answered "not available", so a phone could not create an identity, rotate
// a key or issue a credential through the core.
//
// This asserts the arrangement that fixed it, rather than leaving it to be
// re-derived from the configuration. If it fails, the core has silently lost
// KERI, and the symptom would otherwise appear as an unexplained "not
// available" on a device.
func TestEveryCoreGetsAWorkingKeriEngine(t *testing.T) {
	cfg := Config{
		DataDir: t.TempDir(),
		Port:    0,
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
	pub := "DIqI4910CfGV_VLbLTy6XXLKZwm_HZQSG_N0iAG0D29c"
	next := "DIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
	got, err := s.KeriDriver.CreateInceptionNamed(pub, next, "mobile-test")
	if err != nil {
		t.Fatalf("the engine could not create an identity: %v", err)
	}
	if got.AID == "" {
		t.Fatal("the engine created an identity with no identifier")
	}
}
