package server

import (
	"testing"
	"time"
)

func aStore(t *testing.T) *controllerGrants {
	t.Helper()
	return &controllerGrants{dataDir: t.TempDir()}
}

func aGrant(grade ControllerGrade) ControllerGrant {
	return ControllerGrant{
		ControllerAID: "EController123",
		PublicKey:     "DKey456",
		Label:         "the laptop in the study",
		Grade:         grade,
	}
}

// A machine somebody keeps has no expiry, and stands until it is removed.
func TestAMachineSomebodyKeepsLastsUntilRemoved(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	g, err := c.Grant(aGrant(GradeEnrolled), now)
	if err != nil {
		t.Fatalf("granting: %v", err)
	}
	if !g.ExpiresAt.IsZero() {
		t.Fatalf("a machine somebody keeps should not expire, got %v", g.ExpiresAt)
	}

	// A year on, still theirs.
	if _, ok := c.Live(g.ControllerAID, now.AddDate(1, 0, 0)); !ok {
		t.Fatal("an enrolled controller stopped standing on its own")
	}

	if err := c.Revoke(g.ControllerAID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, ok := c.Live(g.ControllerAID, now); ok {
		t.Fatal("a revoked controller still stands, which is the whole failure")
	}
}

// A borrowed machine stops on its own. This is the check that stands between a
// computer in a hotel lobby and somebody's identity.
func TestABorrowedMachineStopsOnItsOwn(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	g, err := c.Grant(aGrant(GradeScoped), now)
	if err != nil {
		t.Fatalf("granting: %v", err)
	}
	if g.ExpiresAt.IsZero() {
		t.Fatal("a borrowed machine was granted forever")
	}

	if _, ok := c.Live(g.ControllerAID, now.Add(time.Hour)); !ok {
		t.Fatal("a borrowed machine stopped standing within its window")
	}
	if _, ok := c.Live(g.ControllerAID, g.ExpiresAt.Add(time.Second)); ok {
		t.Fatal("an expired grant still stands")
	}

	// Expired is reported as absent to a caller asking whether it may act, and
	// still shown to the owner — those are different questions.
	if len(c.All()) != 1 {
		t.Fatal("an expired grant vanished from what the owner is shown")
	}
}

// What a grant must carry to mean anything.
func TestAGrantThatNamesNothingIsRefused(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		g    ControllerGrant
	}{
		{"no identity", ControllerGrant{PublicKey: "D1", Label: "l", Grade: GradeEnrolled}},
		{"no key to check it by", ControllerGrant{ControllerAID: "E1", Label: "l", Grade: GradeEnrolled}},
		{"nothing the owner could recognise", ControllerGrant{ControllerAID: "E1", PublicKey: "D1", Grade: GradeEnrolled}},
		{"neither grade", ControllerGrant{ControllerAID: "E1", PublicKey: "D1", Label: "l", Grade: "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aStore(t).Grant(tc.g, now); err == nil {
				t.Fatal("accepted a grant that cannot be acted on or revoked")
			}
		})
	}
}

// Granting the same machine twice replaces rather than accumulates, or an owner
// would revoke one grant and find the machine still has another.
func TestGrantingTheSameMachineTwiceReplacesIt(t *testing.T) {
	c := aStore(t)
	now := time.Now().UTC()

	first := aGrant(GradeScoped)
	if _, err := c.Grant(first, now); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	second := aGrant(GradeEnrolled)
	second.Label = "the laptop, kept this time"
	if _, err := c.Grant(second, now); err != nil {
		t.Fatalf("second grant: %v", err)
	}

	all := c.All()
	if len(all) != 1 {
		t.Fatalf("one machine ended up with %d grants; revoking one would leave the other", len(all))
	}
	if all[0].Grade != GradeEnrolled || all[0].Label != second.Label {
		t.Fatalf("the later grant did not win: %+v", all[0])
	}
	if !all[0].ExpiresAt.IsZero() {
		t.Fatal("regrading to a machine somebody keeps left the borrowed expiry behind")
	}
}

// Grants survive restart — the store is the record, not a cache. Revocation
// likewise: one that took effect only in memory is not a revocation.
func TestGrantsAndRevocationsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	if _, err := (&controllerGrants{dataDir: dir}).Grant(aGrant(GradeEnrolled), now); err != nil {
		t.Fatalf("granting: %v", err)
	}
	if _, ok := (&controllerGrants{dataDir: dir}).Live("EController123", now); !ok {
		t.Fatal("a grant did not survive restart")
	}

	if err := (&controllerGrants{dataDir: dir}).Revoke("EController123"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, ok := (&controllerGrants{dataDir: dir}).Live("EController123", now); ok {
		t.Fatal("a revocation did not survive restart, so the machine is still in")
	}
}

// Revoking something that is not there is what the caller wanted, not an error.
func TestRevokingAMachineThatIsNotThereSucceeds(t *testing.T) {
	if err := aStore(t).Revoke("ENeverGranted"); err != nil {
		t.Fatalf("revoking an absent grant errored: %v", err)
	}
}

// The routes are owner-only, and this is the property everything else rests on:
// a controller that could reach these could grant itself, which is not an
// authorisation. They are owner-only by being unlisted, so what this actually
// guards is somebody later adding them to publicRoutes or scopedRoutes.
func TestGrantingAControllerIsOwnerOnly(t *testing.T) {
	for _, r := range []struct{ method, pattern string }{
		{"POST", "/api/controllers"},
		{"GET", "/api/controllers"},
		{"DELETE", "/api/controllers/{aid}"},
	} {
		if got := classify(r.method, r.pattern); got != accessOwner {
			t.Fatalf("%s %s is %q — anybody who can reach this agent could authorise "+
				"their own machine to act as its owner", r.method, r.pattern, got)
		}
	}
}
