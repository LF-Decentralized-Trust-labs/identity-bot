package backup

import (
	"strings"
	"testing"
	"time"
)

// Two machines in one room read as protected, and a fire takes both.
//
// This is the gap the second axis exists for. Reach asks whether a destination
// outlives the DEVICE and answers it well — a phone backing up to the laptop
// on the same desk satisfies it completely, because the phone can be dropped in
// a river and everything survives. A house fire takes both, because they were
// in the same room the whole time.
func TestAPairedMachineIsNotSomewhereElse(t *testing.T) {
	dests := []Destination{
		{ID: "1", Type: DestPairedAgent, Enabled: true, Label: "the laptop"},
		{ID: "2", Type: DestPairedAgent, Enabled: true, Label: "the desktop"},
	}
	// It passes the device question, which is the point: this is not a
	// destination anybody configured badly.
	if ProtectionOf(dests, t.TempDir()) != "" {
		t.Fatal("this test no longer starts from a configuration that looks fine")
	}
	// And fails the place question.
	said := WhatALocalDisasterWouldTake(dests, t.TempDir())
	if said == "" {
		t.Fatal("two machines that may share a room were reported as protected against " +
			"losing that room")
	}
	if !strings.Contains(said, "same room") {
		t.Fatalf("it does not say what the risk is: %q", said)
	}
}

// A remote service is somewhere else, whatever else is wrong.
func TestACloudDestinationIsSomewhereElse(t *testing.T) {
	dests := []Destination{
		{ID: "1", Type: DestPairedAgent, Enabled: true},
		{ID: "2", Type: DestCloudUser, Enabled: true},
	}
	if said := WhatALocalDisasterWouldTake(dests, t.TempDir()); said != "" {
		t.Fatalf("a remote destination was not counted as somewhere else: %q", said)
	}
}

// Everything on this machine is definitely one place.
func TestEverythingOnThisMachineIsOnePlace(t *testing.T) {
	dir := t.TempDir()
	dests := []Destination{
		{ID: "1", Type: DestLocalPath, LocalPath: dir + "/backups", Enabled: true},
	}
	said := WhatALocalDisasterWouldTake(dests, dir)
	if said == "" {
		t.Fatal("a copy inside the agent's own directory was counted as somewhere else")
	}
	if !strings.Contains(said, "one place") {
		t.Fatalf("it does not say what the risk is: %q", said)
	}
}

// The owner can say a destination is elsewhere, and that outranks the guess.
//
// Software knows what kind of thing a destination is and never where it
// physically sits, so a paired machine at a relative's house and one on the
// same desk are identical from here. The message asks; this is the answer
// being possible.
func TestTheOwnerCanSayADestinationIsElsewhere(t *testing.T) {
	dir := t.TempDir()
	atTheOffice := Destination{
		ID: "1", Type: DestPairedAgent, Enabled: true,
		Label: "the machine at the office", Elsewhere: true,
	}
	if said := WhatALocalDisasterWouldTake([]Destination{atTheOffice}, dir); said != "" {
		t.Fatalf("the owner said this is elsewhere and was not believed: %q", said)
	}

	// Including a drive, which is how one kept at an office gets counted.
	drive := Destination{
		ID: "2", Type: DestLocalPath, LocalPath: dir + "/inside", Enabled: true,
		Elsewhere: true,
	}
	if said := WhatALocalDisasterWouldTake([]Destination{drive}, dir); said != "" {
		t.Fatalf("a path the owner called elsewhere was not counted: %q", said)
	}
}

// A destination turned off protects nothing.
func TestADestinationTurnedOffIsNotProtection(t *testing.T) {
	dests := []Destination{
		{ID: "1", Type: DestPairedAgent, Enabled: true},
		{ID: "2", Type: DestCloudUser, Enabled: false},
	}
	if said := WhatALocalDisasterWouldTake(dests, t.TempDir()); said == "" {
		t.Fatal("a destination that is switched off was counted as somewhere else")
	}
}

// With no destinations at all this says nothing, because something louder
// already has.
//
// Two sentences about the same problem in different words read as two
// problems, and the one that matters gets half the attention.
func TestNoDestinationsIsSaidOnceNotTwice(t *testing.T) {
	if said := WhatALocalDisasterWouldTake(nil, t.TempDir()); said != "" {
		t.Fatalf("this repeats what ProtectionOf already says: %q", said)
	}
	if ProtectionOf(nil, t.TempDir()) == "" {
		t.Fatal("and the thing that was supposed to say it does not")
	}
}

// The screen is told about it, and it changes the colour.
//
// A function nobody calls is not a warning, and neither is a fact that stops
// at the edge of the process. An earlier version of this test asserted only on
// FactsFrom — which computed the answer correctly while BuildStatus dropped it,
// so the wire carried a yellow health with nothing explaining it. The
// assertion on StatusResponse below is the one that matters.
func TestTheScreenIsToldWhatALocalDisasterWouldTake(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339)
	hist := []HistoryEntry{{
		Timestamp: now, Success: true, Verified: true,
		OffDevice: true, SelfSufficient: true, SnapshotType: SnapshotFull,
	}}
	// Everything a backup could want, except that it is all in one room.
	oneRoom := []Destination{{ID: "1", Type: DestPairedAgent, Enabled: true}}

	f := FactsFrom(hist, oneRoom, dir, 0)
	if f.LocalDisaster == "" {
		t.Fatal("the screen is told nothing about every copy being in one place")
	}
	if f.Health == "green" {
		t.Fatal("a backup one house fire would take entirely was reported as green")
	}
	if f.Health != "yellow" {
		t.Fatalf("expected yellow — there IS a working backup — got %q", f.Health)
	}

	// And the same backup with somewhere else is green.
	elsewhere := append(oneRoom, Destination{ID: "2", Type: DestCloudUser, Enabled: true})
	if g := FactsFrom(hist, elsewhere, dir, 0); g.Health != "green" || g.LocalDisaster != "" {
		t.Fatalf("adding somewhere else did not settle it: health=%q said=%q",
			g.Health, g.LocalDisaster)
	}
}

// And it reaches the wire, not just the struct it is computed in.
func TestWhatALocalDisasterWouldTakeReachesTheStatus(t *testing.T) {
	dir := t.TempDir()
	cs := NewConfigStore(dir)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Destinations = []Destination{{ID: "1", Type: DestPairedAgent, Enabled: true}}

	status := cs.BuildStatus(cfg, nil, 0)
	if status.LocalDisaster == "" {
		t.Fatal("the status says nothing about every copy being in one place, so a screen " +
			"showing yellow has no reason to show with it")
	}
	if !strings.Contains(status.LocalDisaster, "same room") {
		t.Fatalf("it does not say what the risk is: %q", status.LocalDisaster)
	}
}

// A house fire is not the most urgent thing wrong with a backup nobody has
// taken in a week.
func TestAStalerProblemStillWins(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339)
	hist := []HistoryEntry{{
		Timestamp: old, Success: true, Verified: true,
		OffDevice: true, SelfSufficient: true, SnapshotType: SnapshotFull,
	}}
	oneRoom := []Destination{{ID: "1", Type: DestPairedAgent, Enabled: true}}

	if f := FactsFrom(hist, oneRoom, dir, 0); f.Health != "red" {
		t.Fatalf("nothing has left this device in five days and the answer was %q", f.Health)
	}
}
