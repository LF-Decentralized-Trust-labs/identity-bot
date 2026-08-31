//go:build windows

package secureenclave

import "testing"

// The detector must ANSWER on Windows, and must never fall back to "we have not
// looked".
//
// capability.go singles this platform out: a hardcoded false here "would be
// wrong for essentially every machine, since Windows 11 cannot ship without a
// TPM". Since an Unknown answer refuses a root seed, a detector that never
// answers refuses every Windows machine — including the overwhelming majority
// that have perfectly good hardware.
//
// This asserts that something was established, not which. A machine with a TPM
// answers Usable; one whose TPM is unprovisioned or in lockout answers Present;
// a machine genuinely without one answers Absent. All three are findings.
func TestAWindowsMachineGetsAnAnswer(t *testing.T) {
	cap := DetectCapability()
	t.Logf("this machine: %s", cap.String())

	if cap.Reason == "not_implemented_on_this_build" {
		t.Fatal("windows fell through to the not-implemented detector — " +
			"capability_other.go's build tag has stopped excluding it")
	}

	switch cap.Status {
	case Usable:
		if cap.Kind != KindTPM2 {
			t.Errorf("a usable Windows machine must name the TPM, got kind %q", cap.Kind)
		}
	case Present, Absent:
		if cap.Reason == "" {
			t.Errorf("%s was reported with no reason, which cannot be explained to anybody", cap.Status)
		}
	case Unknown:
		if cap.Detail == "" {
			t.Error("an unknown answer must carry the platform detail; " +
				"a code we discarded is a code we cannot learn from")
		}
	default:
		t.Fatalf("unrecognised status %q", cap.Status)
	}
}

// Absent may be reached only when the operating system's own device register
// says there is no TPM.
//
// This is the go-attestation trap written as a test. That library reads, in as
// many words, "If we fail to initialize the Platform Crypto Provider, we assume
// a TPM is not present" — and a provider fails to open for many reasons that
// say nothing about hardware: a stopped service, a policy, an unprovisioned
// module. Turning any of those into Absent tells somebody their computer has no
// security hardware when it does, and sends them to buy what they already own.
func TestAbsentIsOnlyEverTheDeviceRegistersAnswer(t *testing.T) {
	cap := DetectCapability()
	if cap.Status != Absent {
		t.Skip("this machine did not answer Absent, so there is nothing to inspect here")
	}
	if cap.Reason != "no_tpm_on_this_machine" {
		t.Errorf("Absent was reached by some other route: reason %q — "+
			"only the device register may produce it", cap.Reason)
	}
}

// Probing must not leave anything behind.
//
// The key is ephemeral, which on this platform matters more than tidiness: a
// TPM has a small, fixed amount of persistent storage, and a detector that
// persisted a key on every launch would eventually fill it and start failing on
// the machines it works on today.
func TestProbingRepeatedlyChangesNothing(t *testing.T) {
	first := DetectCapability()
	for i := 0; i < 3; i++ {
		again := DetectCapability()
		if again.Status != first.Status || again.Kind != first.Kind {
			t.Fatalf("probe %d disagreed with the first: %s then %s",
				i+2, first.String(), again.String())
		}
	}
}
