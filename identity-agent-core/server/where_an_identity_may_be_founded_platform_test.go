package server

import (
	"runtime"
	"testing"
)

// What THIS platform actually answers, rather than what a test told it to.
//
// Every other test here replaces the decision with one of its own, which is
// necessary — the machines this refuses are the machines it is developed on —
// and it leaves the six per-platform files, which are the entire content of the
// work, untested. Change the macOS file to permit founding and the whole suite
// stays green, including the test named for refusing it.
//
// No build tags, so it compiles everywhere and fires on whichever machine runs
// it. On a Mac, which is where this is developed, it fires immediately.
func TestThisPlatformAnswersWhatItShould(t *testing.T) {
	v := foundingVerdictForThisPlatform()

	switch runtime.GOOS {
	case "darwin", "windows":
		// Neither can prove its software to a stranger. macOS is measured
		// rather than assumed: the service reports itself unsupported, and a
		// build carrying the entitlement is killed at launch.
		if v.Permitted {
			t.Fatalf("%s may not found an identity, and this build says it may: %+v",
				runtime.GOOS, v)
		}
	case "ios", "android":
		if !v.Permitted {
			t.Fatalf("%s attests the running application and may found, and this "+
				"build says it may not: %+v", runtime.GOOS, v)
		}
	case "linux":
		// Decided at runtime here, because a sealed machine and an ordinary
		// desktop are the same GOOS. So the answer is not fixed — but the only
		// thing that may be permitted is a sealed machine.
		if v.Permitted && v.Platform != "amd_sev_snp" {
			t.Fatalf("linux permitted something that is not a sealed machine: %+v", v)
		}
	default:
		// A platform this build was never written for. Being unable to answer
		// is not permission.
		if v.Permitted {
			t.Fatalf("%s is not a platform this build knows, and it was permitted: %+v",
				runtime.GOOS, v)
		}
	}
}

// A refusal has to end somewhere, on every platform.
//
// The message is built by joining the reason to what the machine can do
// instead, so a verdict written without the second half produces a sentence
// trailing off after a dash — and the whole point of it is that somebody
// stopped from doing the obvious thing is told what to do instead. Nothing
// enforced that.
func TestARefusalAlwaysSaysWhyAndWhatInstead(t *testing.T) {
	v := foundingVerdictForThisPlatform()

	if v.Platform == "" {
		t.Error("a verdict that does not say which platform it is about")
	}
	if v.Permitted {
		return
	}
	if v.Why == "" {
		t.Error("a refusal with no reason, which somebody cannot act on")
	}
	if v.Instead == "" {
		t.Error("a refusal that does not say what this computer CAN do — the " +
			"next thing somebody tries is a way around it")
	}
}
