package recovery

import (
	"encoding/json"
	"identity-agent-core/backup"
	"identity-agent-core/store"
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

	// A waiting period is satisfiable and is accepted.
	good := DuressPolicy{Protection: DuressWait, WaitHours: 24}
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

	chosen := DuressPolicy{Protection: DuressWait, WaitHours: 48}
	if err := svc.SaveDuressPolicy(chosen); err != nil {
		t.Fatal(err)
	}
	back := svc.LoadDuressPolicy()
	if back.Protection != DuressWait || back.WaitHours != 48 {
		t.Fatalf("what came back is not what was chosen: %+v", back)
	}

	// A policy that cannot be met is refused before it is stored, so a bad
	// choice cannot be discovered during a recovery.
	if err := svc.SaveDuressPolicy(DuressPolicy{
		Protection: DuressWait, WaitHours: 0,
	}); err == nil {
		t.Fatal("a policy nobody can satisfy was stored")
	}
	if svc.LoadDuressPolicy().Protection != DuressWait ||
		svc.LoadDuressPolicy().WaitHours != 48 {
		t.Fatal("a refused policy overwrote the good one")
	}
}

func TestRequiringPeopleWhoCannotAnswerIsRefused(t *testing.T) {
	// The lockout this function exists to catch, which it was green-lighting.
	//
	// Session.DuressApprovals is read when a recovery completes and written by
	// nothing — there is no route a trusted contact can use to say yes. So a
	// policy requiring them can never be satisfied, and somebody who chose it
	// would discover that during a recovery, which is the worst moment there is.
	for _, p := range []DuressPolicy{
		{Protection: DuressTrustedContacts, Contacts: []TrustedContact{{AID: "EA"}}, Approvals: 1},
		{Protection: DuressBoth, WaitHours: 24, Contacts: []TrustedContact{{AID: "EA"}}, Approvals: 1},
	} {
		err := p.Validate()
		if err == nil {
			t.Fatalf("accepted a policy nothing can satisfy: %+v", p)
		}
		if !strings.Contains(err.Error(), "cannot approve a recovery yet") {
			t.Fatalf("refused without saying why it is impossible: %v", err)
		}
	}

	// And it is not stored either, so it cannot arrive by another route.
	svc := NewService(t.TempDir(), nil, nil)
	if err := svc.SaveDuressPolicy(DuressPolicy{
		Protection: DuressTrustedContacts,
		Contacts:   []TrustedContact{{AID: "EA"}},
		Approvals:  1,
	}); err == nil {
		t.Fatal("a policy nothing can satisfy was written to disk")
	}
}

func TestThePolicyTravelsWithTheIdentityNotTheMachine(t *testing.T) {
	// A recovery runs on a device that does not hold this identity's data —
	// that is what makes it a recovery. Reading the policy off local disk meant
	// a fresh machine found none, defaulted to no protection, and let the
	// recovery through: the gate fired only on the owner's own machine, which
	// is the one place it is not needed.
	held := DuressPolicy{Protection: DuressWait, WaitHours: 72}
	body, err := json.Marshal(held)
	if err != nil {
		t.Fatal(err)
	}

	payload := &RestoredPayload{Bundle: &backup.PayloadBundle{
		Sections: map[string][]byte{"file:duress_policy.json": body},
	}}
	got := duressPolicyFrom(payload)
	if got.Protection != DuressWait || got.WaitHours != 72 {
		t.Fatalf("the policy did not travel with the identity: %+v", got)
	}

	// It actually holds, which is the point.
	if err := got.Held(time.Now(), nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a recovery completed an hour into a 72-hour hold carried by the archive")
	}

	// An archive that predates the setting yields the default, because an
	// identity that never chose a policy does not have one.
	for _, empty := range []*RestoredPayload{
		nil,
		{},
		{Bundle: &backup.PayloadBundle{Sections: map[string][]byte{}}},
		{Bundle: &backup.PayloadBundle{Sections: map[string][]byte{"file:duress_policy.json": []byte("not json")}}},
	} {
		if p := duressPolicyFrom(empty); p.Protection != DuressNone {
			t.Fatalf("an archive with no policy produced %q", p.Protection)
		}
	}
}

func TestTheChosenPolicyActuallyReachesAnArchive(t *testing.T) {
	// Every test of this gate injected the section into a hand-built bundle, so
	// they proved the gate READS it and nothing proved it is ever there.
	//
	// It was not. The section came only from the tier-3 sweep, which nothing
	// requests — the default tiers are tier1 and tier2 in Go and hardcoded
	// twice in the Dart client, and no screen can select tier 3. So somebody
	// set a duress policy, the agent stored it and read it back and confirmed
	// it, and it was absent from every archive: the one place a recovering
	// device can learn it.
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	if err := svc.SaveDuressPolicy(DuressPolicy{
		Protection: DuressWait, WaitHours: 72,
	}); err != nil {
		t.Fatal(err)
	}

	st, serr := store.NewSQLiteStore(dir)
	if serr != nil {
		t.Fatal(serr)
	}
	defer st.Close()
	c := &backup.Collector{DataDir: dir, Store: st}
	bundle, _, err := c.Collect(backup.CollectOptions{Tiers: []string{backup.TierCritical}})
	if err != nil {
		t.Fatal(err)
	}

	raw, ok := bundle.Sections["file:duress_policy.json"]
	if !ok || len(raw) == 0 {
		t.Fatal("the duress policy is not in a default archive, so the gate has " +
			"nothing to read on the device that is recovering")
	}

	// And it survives the trip as what was chosen.
	got := duressPolicyFrom(&RestoredPayload{Bundle: bundle})
	if got.Protection != DuressWait || got.WaitHours != 72 {
		t.Fatalf("the policy did not survive collection: %+v", got)
	}
}
