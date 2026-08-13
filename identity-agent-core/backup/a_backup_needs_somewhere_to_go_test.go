package backup

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A device that backs up to nowhere must say so.
//
// This was the one case the old warnings stayed silent on: AntiDeadlockWarning
// returned early when there were no destinations, and the redundancy line
// phrased it as a recommendation to add a second. So the agent with zero said
// less than the agent with one.
func TestADeviceWithNowhereToPutItSaysSo(t *testing.T) {
	msg := ProtectionOf(nil, t.TempDir())
	if msg == "" {
		t.Fatal("a device with no destinations said nothing at all")
	}
	if !strings.Contains(msg, "nowhere") {
		t.Errorf("the message should say plainly that there is nowhere: %q", msg)
	}
}

// A copy beside the original is not a backup. Rob, 2026-08-13.
func TestACopyOnThisDeviceDoesNotCount(t *testing.T) {
	dataDir := t.TempDir()

	onDevice := Destination{
		ID: "d1", Type: DestLocalPath, Enabled: true,
		LocalPath: filepath.Join(dataDir, "backups"),
	}
	if got := ReachOf(onDevice, dataDir); got != ReachThisDeviceOnly {
		t.Errorf("a path inside the agent's own data directory should not survive the device, got %v", got)
	}

	msg := ProtectionOf([]Destination{onDevice}, dataDir)
	if msg == "" {
		t.Fatal("an agent whose only destination is its own disk was told nothing")
	}
	if !strings.Contains(msg, "on this device") {
		t.Errorf("the message should name the problem, got %q", msg)
	}
}

// A path we cannot classify is counted and said out loud, rather than guessed
// at. An external drive and a second folder on the same disk look identical.
func TestAPathWeCannotClassifyIsNotGuessedAt(t *testing.T) {
	dataDir := t.TempDir()
	elsewhere := Destination{ID: "d1", Type: DestLocalPath, Enabled: true, LocalPath: t.TempDir()}

	if got := ReachOf(elsewhere, dataDir); got != ReachUnknown {
		t.Errorf("a path outside the data directory cannot be classified, got %v", got)
	}
}

func TestAPairedMachineSurvivesThisDevice(t *testing.T) {
	d := Destination{ID: "d1", Type: DestPairedAgent, Enabled: true, PairedURL: "https://elsewhere.example"}
	if got := ReachOf(d, t.TempDir()); got != ReachSurvivesThisDevice {
		t.Errorf("another machine should survive losing this one, got %v", got)
	}
}

// A disabled destination protects nothing.
func TestADisabledDestinationProtectsNothing(t *testing.T) {
	dataDir := t.TempDir()
	off := Destination{ID: "d1", Type: DestPairedAgent, Enabled: false, PairedURL: "https://elsewhere.example"}

	msg := ProtectionOf([]Destination{off}, dataDir)
	if !strings.Contains(msg, "nowhere") {
		t.Errorf("a single disabled destination should read as nowhere, got %q", msg)
	}
}

// The machine a person already paired becomes a destination without them
// having to know that backup is a separate thing to configure.
func TestAPairedMachineBecomesADestination(t *testing.T) {
	machines := []machineDestination{
		{AID: "EMachineOne", URL: "https://one.example", Label: "The computer in the study"},
	}
	got := destinationsForPairedMachines(machines, nil)
	if len(got) != 1 {
		t.Fatalf("expected one destination, got %d", len(got))
	}
	if got[0].PairedURL != "https://one.example" || got[0].Type != DestPairedAgent {
		t.Errorf("wrong destination: %+v", got[0])
	}
	if !got[0].Enabled {
		t.Error("a destination that is added and left off protects nothing")
	}
}

// Somebody who turned a destination off stays turned off. Re-adding it on the
// next run would silently overrule a decision they made on purpose.
func TestAMachineAlreadyConfiguredIsNotAddedAgain(t *testing.T) {
	machines := []machineDestination{{AID: "EMachineOne", URL: "https://one.example"}}
	existing := []Destination{
		{ID: "paired:EMachineOne", Type: DestPairedAgent, PairedURL: "https://one.example", Enabled: false},
	}
	if got := destinationsForPairedMachines(machines, existing); len(got) != 0 {
		t.Fatalf("a machine that already has a destination was added again: %+v", got)
	}
}

func TestAMachineWithNoAddressIsSkipped(t *testing.T) {
	machines := []machineDestination{{AID: "EMachineOne", URL: ""}}
	if got := destinationsForPairedMachines(machines, nil); len(got) != 0 {
		t.Fatalf("a machine with no address cannot be a destination: %+v", got)
	}
}

// --- what the agent can tell you ---

func recently(d time.Duration) string {
	return time.Now().UTC().Add(-d).Format(time.RFC3339)
}

// The three facts are separate, and reporting only the first is what let an
// agent with failing destinations and unopened archives read green.
func TestTheAgentReportsRanVerifiedAndOffDeviceSeparately(t *testing.T) {
	dataDir := t.TempDir()
	dests := []Destination{{ID: "d", Type: DestPairedAgent, Enabled: true, PairedURL: "https://x.example"}}

	hist := []HistoryEntry{
		{Timestamp: recently(1 * time.Hour), Success: true, Verified: false, OffDevice: false},
		{Timestamp: recently(30 * time.Hour), Success: true, Verified: true, OffDevice: true},
	}

	f := FactsFrom(hist, dests, dataDir, 0)
	if f.LastBackupAt != hist[0].Timestamp {
		t.Errorf("last backup should be the most recent successful run, got %q", f.LastBackupAt)
	}
	if f.LastVerifiedAt != hist[1].Timestamp {
		t.Errorf("last verified should skip the unverified run, got %q", f.LastVerifiedAt)
	}
	if f.LastOffDeviceAt != hist[1].Timestamp {
		t.Errorf("last off-device should skip the run that stayed here, got %q", f.LastOffDeviceAt)
	}
}

// The failure this whole area exists to stop: everything looks fine and nothing
// is recoverable.
func TestAnAgentThatNeverGotAnArchiveOffTheDeviceIsNotGreen(t *testing.T) {
	dataDir := t.TempDir()
	hist := []HistoryEntry{
		{Timestamp: recently(10 * time.Minute), Success: true, Verified: true, OffDevice: false},
	}
	f := FactsFrom(hist, []Destination{
		{ID: "d", Type: DestLocalPath, Enabled: true, LocalPath: filepath.Join(dataDir, "b")},
	}, dataDir, 0)

	if f.Health == "green" {
		t.Fatal("an agent whose archives never left the device reported green")
	}
}

// An archive nobody has ever opened is not a proven backup.
func TestAnArchiveNobodyHasOpenedIsNotGreen(t *testing.T) {
	dataDir := t.TempDir()
	hist := []HistoryEntry{
		{Timestamp: recently(10 * time.Minute), Success: true, Verified: false, OffDevice: true},
	}
	f := FactsFrom(hist, []Destination{
		{ID: "d", Type: DestPairedAgent, Enabled: true, PairedURL: "https://x.example"},
	}, dataDir, 0)

	if f.Health == "green" {
		t.Fatal("an agent that has never verified an archive reported green")
	}
	if f.Health != "yellow" {
		t.Errorf("expected yellow — there IS an archive off-device — got %q", f.Health)
	}
}

func TestAHealthyAgentIsGreen(t *testing.T) {
	dataDir := t.TempDir()
	hist := []HistoryEntry{
		{Timestamp: recently(10 * time.Minute), Success: true, Verified: true, OffDevice: true},
	}
	f := FactsFrom(hist, []Destination{
		{ID: "d1", Type: DestPairedAgent, Enabled: true, PairedURL: "https://x.example"},
		{ID: "d2", Type: DestCloudUser, Enabled: true, CloudProvider: "s3", CredentialID: "c"},
	}, dataDir, 0)

	if f.Health != "green" {
		t.Fatalf("a verified, off-device, recent, redundant backup should be green, got %q (%s)",
			f.Health, f.Protection)
	}
	if f.Protection != "" {
		t.Errorf("nothing should be missing, said: %q", f.Protection)
	}
}

// A failed run at the top of the history used to hide every success beneath it,
// because the old reading looked only at hist[0].
func TestOneFailedRunDoesNotHideTheBackupsThatWorked(t *testing.T) {
	dataDir := t.TempDir()
	hist := []HistoryEntry{
		{Timestamp: recently(5 * time.Minute), Success: false},
		{Timestamp: recently(20 * time.Minute), Success: true, Verified: true, OffDevice: true},
	}
	f := FactsFrom(hist, []Destination{
		{ID: "d", Type: DestPairedAgent, Enabled: true, PairedURL: "https://x.example"},
	}, dataDir, 1)

	if f.LastBackupAt != hist[1].Timestamp {
		t.Errorf("a failed run at the top hid the successful one beneath it, got %q", f.LastBackupAt)
	}
}

func TestRepeatedFailuresAreRed(t *testing.T) {
	dataDir := t.TempDir()
	hist := []HistoryEntry{{Timestamp: recently(time.Minute), Success: true, Verified: true, OffDevice: true}}
	if f := FactsFrom(hist, nil, dataDir, 3); f.Health != "red" {
		t.Errorf("three consecutive failures should be red, got %q", f.Health)
	}
}
