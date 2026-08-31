package authprovider

import (
	"fmt"
	"testing"
	"time"
)

// Controlling an identity and being the person it belongs to are different
// things, and the recovery phrase only answers the first. This package exists
// to keep the second question separate — and to make sure that not having
// asked it never looks like having asked it.

func TestNotHavingMeasuredIsNotAMeasurement(t *testing.T) {
	// The failure this prevents: an agent with no provider used to report a
	// middling band and a score of 60, so a number nobody produced appeared on
	// screen and shortened a waiting period.
	res := Of(nil)
	if res.Measured {
		t.Fatal("an agent with no provider reported a measurement")
	}
	if res.Level != LevelUnknown {
		t.Fatalf("an unmeasured agent reported level %q", res.Level)
	}
	if res.Score != 0 {
		t.Fatalf("a score of %d was invented", res.Score)
	}
	if res.Why == "" {
		t.Fatal("nothing said why there is no answer")
	}

	// And unknown shows red, not amber. Nobody has checked, which is not the
	// same as having checked and found something middling.
	if res.Level.Badge() != "red" {
		t.Fatalf("an unmeasured identity shows %q", res.Level.Badge())
	}
}

func TestUnknownNeverSatisfiesARequirement(t *testing.T) {
	// The important one. If unknown satisfied anything, an agent with no
	// provider would pass gates that an agent WITH a provider fails — the
	// absence of a check would be safer than the check.
	for _, required := range []Level{LevelNone, LevelBasic, LevelAuthenticated, LevelVerified, LevelHigh} {
		if LevelUnknown.AtLeast(required) {
			t.Fatalf("unknown satisfied a requirement of %q", required)
		}
	}
	// Including "none", which is measured-and-found-nothing. Not knowing must
	// not clear even the lowest bar that was actually tested for.
	if LevelUnknown.AtLeast(LevelNone) {
		t.Fatal("not having measured satisfied a requirement of having measured nothing")
	}
}

func TestALevelSatisfiesItselfAndEverythingBelow(t *testing.T) {
	if !LevelVerified.AtLeast(LevelVerified) || !LevelVerified.AtLeast(LevelBasic) {
		t.Fatal("a level does not satisfy itself or something weaker")
	}
	if LevelBasic.AtLeast(LevelVerified) {
		t.Fatal("a weaker level satisfied a stronger requirement")
	}
	if !LevelHigh.AtLeast(LevelNone) {
		t.Fatal("the strongest level failed the weakest requirement")
	}
}

type failing struct{}

func (failing) Name() string { return "failing" }
func (failing) Authenticate() (Result, error) {
	return Result{Level: LevelHigh, Score: 99, Measured: true}, fmt.Errorf("sensor unavailable")
}

func TestAProviderThatErrorsProducesNoLevel(t *testing.T) {
	// A provider that fails must not have its half-filled answer believed. This
	// one returns a high level AND an error, which is the shape of a bug in an
	// implementation somebody else wrote.
	res := Of(failing{})
	if res.Measured || res.Level != LevelUnknown {
		t.Fatalf("a failing provider produced level %q measured=%v", res.Level, res.Measured)
	}
	if res.Level.AtLeast(LevelBasic) {
		t.Fatal("a failing provider satisfied a requirement")
	}
}

type steady struct{ at time.Time }

func (steady) Name() string { return "steady" }
func (s steady) Authenticate() (Result, error) {
	return Result{Level: LevelVerified, Score: 90, Measured: true, At: s.at}, nil
}

func TestAnAuthenticationIsAboutAMomentAndGoesStale(t *testing.T) {
	// A recovery waits days. An authentication from the day it started is not
	// evidence about who is finishing it, which is why the gate is checked at
	// the end rather than the beginning.
	old := Of(steady{at: time.Now().Add(-72 * time.Hour)})
	if old.Fresh(time.Hour) {
		t.Fatal("a three-day-old authentication counts as current")
	}
	if !old.Fresh(96 * time.Hour) {
		t.Fatal("a three-day-old authentication is stale even against a four-day window")
	}

	// And something never measured is never fresh, whatever the window.
	if Of(nil).Fresh(365 * 24 * time.Hour) {
		t.Fatal("an absent measurement counts as a recent one")
	}
}

func TestAProviderThatAnswersIsRecorded(t *testing.T) {
	res := Of(steady{at: time.Now()})
	if res.Provider != "steady" {
		t.Fatalf("nothing recorded who made this claim: %q", res.Provider)
	}
	if res.Level.Badge() != "green" {
		t.Fatalf("a verified identity shows %q", res.Level.Badge())
	}
}
