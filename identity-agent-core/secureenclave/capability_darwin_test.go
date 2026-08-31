//go:build darwin && cgo

package secureenclave

import "testing"

// The detector must ANSWER on an Apple machine, and never fall back to "we have
// not looked".
//
// That fallback is the defect this whole package exists to end, and on darwin it
// was live: every Mac, iPhone and iPad answered Unknown while the attestation
// signer, on the same build, was creating and using Secure Enclave keys a few
// files away. Since identity-bot PR #205 an Unknown answer refuses a root seed,
// and a root key may now live only on a phone or a sealed machine — so an
// unanswering darwin detector would refuse identity creation on iPhone, which
// is the primary supported path.
//
// This asserts the honest thing rather than a machine-specific one: the answer
// must be established, whatever it is. A 2015 Mac with no enclave may legitimately
// say Absent, and CI in a VM may legitimately say Present or fail to reach the
// keychain — what it may never say is that nobody looked.
func TestAnAppleMachineGetsAnAnswer(t *testing.T) {
	cap := DetectCapability()
	t.Logf("this machine: %s", cap.String())

	if cap.Reason == "not_implemented_on_this_build" {
		t.Fatal("darwin fell through to the not-implemented detector — " +
			"capability_other.go's build tag has stopped excluding it")
	}

	switch cap.Status {
	case Usable:
		if cap.Kind != KindAppleEnclave {
			t.Errorf("a usable Apple machine must name the enclave, got kind %q", cap.Kind)
		}
	case Absent, Present:
		// Both are real findings and both must say why, because the remedies
		// differ and a person is shown this.
		if cap.Reason == "" {
			t.Errorf("%s was reported with no reason, which cannot be explained to anybody", cap.Status)
		}
	case Unknown:
		// Permitted — an unrecognised failure is not evidence of absent
		// hardware — but it has to carry the code, or the next person cannot
		// learn which machines produce it.
		if cap.Detail == "" {
			t.Error("an unknown answer must carry the platform detail; " +
				"a code we discarded is a code we cannot learn from")
		}
	default:
		t.Fatalf("unrecognised status %q", cap.Status)
	}
}

// Probing must not leave anything behind.
//
// The key is created ephemeral so nothing lands in the keychain — which is not
// tidiness. A detector that stored a key would prompt for a keychain password
// on every launch, before the person had asked for anything. Calling it
// repeatedly is the closest thing to a regression test for that: a permanent
// key would make the second call behave differently from the first, and would
// stall waiting on a prompt.
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

// Absent is the one answer that may never be guessed at, so only a code that
// positively establishes it may produce it. This pins the mapping so a later
// edit cannot quietly widen it — the failure mode being prevented is telling
// somebody their Mac has no security hardware when the truth is that a call
// failed for a reason nobody recognised.
func TestOnlyTheUnimplementedTokenMeansAbsent(t *testing.T) {
	cap := DetectCapability()
	if cap.Status != Absent {
		t.Skip("this machine has an enclave, so there is no Absent answer to inspect here")
	}
	if cap.Reason != "no_secure_enclave_on_this_hardware" {
		t.Errorf("Absent was reached by some other route: reason %q", cap.Reason)
	}
}
