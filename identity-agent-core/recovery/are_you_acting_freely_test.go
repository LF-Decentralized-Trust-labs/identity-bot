package recovery

import (
	"strings"
	"testing"
	"time"
)

// Neither of the other gates can answer whether somebody is acting freely.
// A person held at knifepoint has the right phrase and authenticates perfectly.

func TestOffByDefaultAndNothingIsHeld(t *testing.T) {
	// Every identity today, and every identity that never opens this setting.
	// A protection that nobody chose must not stand between somebody and their
	// own identity.
	p := DefaultDuressPolicy()
	if p.Protection != DuressNone {
		t.Fatalf("the default protection is %q, which nobody asked for", p.Protection)
	}
	if err := p.Held(time.Now(), nil, time.Now()); err != nil {
		t.Fatalf("a recovery was held by a gate that is off: %v", err)
	}
}

func TestAPolicyNobodyCanSatisfyIsRefusedWhenItIsSet(t *testing.T) {
	// A policy that cannot be met does not protect the owner from an attacker;
	// it protects the identity from its owner. Caught when it is chosen rather
	// than discovered during a recovery, which is the worst possible moment.
	for _, p := range []DuressPolicy{
		{Protection: DuressTrustedContacts, Contacts: []TrustedContact{{AID: "EA"}, {AID: "EB"}}, Approvals: 3},
		{Protection: DuressTrustedContacts, Approvals: 1},
		{Protection: DuressTrustedContacts, Contacts: []TrustedContact{{AID: "EA"}}, Approvals: 0},
		{Protection: DuressWait, WaitHours: 0},
		{Protection: DuressWait, WaitHours: 24 * 365},
		{Protection: DuressTrustedContacts, Contacts: []TrustedContact{{Label: "mum"}}, Approvals: 1},
		{Protection: "something else"},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted a policy nobody can satisfy: %+v", p)
		}
	}

	// The same person named twice would let one approval meet a threshold of
	// two, which is not what the owner asked for.
	dup := DuressPolicy{
		Protection: DuressTrustedContacts,
		Contacts:   []TrustedContact{{AID: "EA"}, {AID: "EA"}},
		Approvals:  2,
	}
	if err := dup.Validate(); err == nil {
		t.Fatal("the same person named twice was accepted as two people")
	}

	good := DuressPolicy{
		Protection: DuressBoth, WaitHours: 24,
		Contacts:  []TrustedContact{{AID: "EA"}, {AID: "EB"}, {AID: "EC"}},
		Approvals: 2,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a sensible policy was refused: %v", err)
	}
}

func TestOnePersonCannotApproveTwice(t *testing.T) {
	// Counted as a set. Otherwise a single trusted contact — or an attacker who
	// compromised one — satisfies a threshold the owner set to two precisely so
	// that one would not be enough.
	p := DuressPolicy{
		Protection: DuressTrustedContacts,
		Contacts:   []TrustedContact{{AID: "EA"}, {AID: "EB"}},
		Approvals:  2,
	}
	err := p.Held(time.Now(), []string{"EA", "EA", "EA"}, time.Now())
	if err == nil {
		t.Fatal("one person approving three times satisfied a threshold of two people")
	}
	if err := p.Held(time.Now(), []string{"EA", "EB"}, time.Now()); err != nil {
		t.Fatalf("two different people did not satisfy a threshold of two: %v", err)
	}

	// Somebody not on the list does not count, however many times they say yes.
	if err := p.Held(time.Now(), []string{"EA", "EStranger"}, time.Now()); err == nil {
		t.Fatal("a stranger's approval counted toward the threshold")
	}
}

func TestWaitingHoldsUntilItHasActuallyElapsed(t *testing.T) {
	p := DuressPolicy{Protection: DuressWait, WaitHours: 24}
	start := time.Now()

	err := p.Held(start, nil, start.Add(time.Hour))
	if err == nil {
		t.Fatal("a recovery completed an hour into a 24-hour hold")
	}
	var held *ErrHeldForDuress
	if h, ok := err.(*ErrHeldForDuress); ok {
		held = h
	} else {
		t.Fatalf("held for the wrong reason: %v", err)
	}
	if held.Until.IsZero() {
		t.Fatal("nothing said when the hold ends")
	}
	if !strings.Contains(err.Error(), "chance to notice") {
		t.Fatalf("the hold does not say what it is for: %v", err)
	}

	if err := p.Held(start, nil, start.Add(25*time.Hour)); err != nil {
		t.Fatalf("the hold did not end: %v", err)
	}
}

func TestBothMeansBoth(t *testing.T) {
	p := DuressPolicy{
		Protection: DuressBoth, WaitHours: 24,
		Contacts:  []TrustedContact{{AID: "EA"}},
		Approvals: 1,
	}
	start := time.Now()

	// Approvals alone do not skip the wait.
	if err := p.Held(start, []string{"EA"}, start.Add(time.Hour)); err == nil {
		t.Fatal("an approval let a recovery skip the waiting period")
	}
	// The wait alone does not skip the approvals.
	if err := p.Held(start, nil, start.Add(48*time.Hour)); err == nil {
		t.Fatal("waiting let a recovery skip the people who were supposed to confirm it")
	}
	// Both.
	if err := p.Held(start, []string{"EA"}, start.Add(48*time.Hour)); err != nil {
		t.Fatalf("both conditions met and the recovery was still held: %v", err)
	}
}

func TestAChosenPolicySurvivesAndABadOneIsNeverStored(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)

	if p := svc.LoadDuressPolicy(); p.Protection != DuressNone {
		t.Fatalf("a fresh identity already has protection %q", p.Protection)
	}

	chosen := DuressPolicy{
		Protection: DuressTrustedContacts,
		Contacts:   []TrustedContact{{AID: "EA", Label: "my brother"}},
		Approvals:  1,
	}
	if err := svc.SaveDuressPolicy(chosen); err != nil {
		t.Fatal(err)
	}
	back := svc.LoadDuressPolicy()
	if back.Protection != DuressTrustedContacts || len(back.Contacts) != 1 ||
		back.Contacts[0].Label != "my brother" {
		t.Fatalf("what came back is not what was chosen: %+v", back)
	}

	// A policy that cannot be met is refused before it is stored, so a bad
	// choice cannot be discovered during a recovery.
	if err := svc.SaveDuressPolicy(DuressPolicy{
		Protection: DuressTrustedContacts, Approvals: 2,
	}); err == nil {
		t.Fatal("a policy nobody can satisfy was stored")
	}
	if svc.LoadDuressPolicy().Protection != DuressTrustedContacts ||
		len(svc.LoadDuressPolicy().Contacts) != 1 {
		t.Fatal("a refused policy overwrote the good one")
	}
}
