package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/backup"
)

// What a person can actually be shown about their backups.
//
// The point of recording whether an archive was verified, and whether it ever
// left the device, is that somebody can see it. So this asks the endpoint the
// screen asks, and reads the fields off the wire — a field that exists on the
// struct and never reaches the JSON is not surfaced.

func backupStatusJSON(t *testing.T, s *CoreServer) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleBackupStatus(w, httptest.NewRequest(http.MethodGet, "/api/backup/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("status was not readable JSON: %v", err)
	}
	return out
}

// An agent that has never backed up says so plainly, rather than showing an
// empty screen that reads as "nothing to worry about".
func TestTheScreenTellsYouWhenThereIsNoBackupAtAll(t *testing.T) {
	dir := t.TempDir()
	s := exportServer(t, dir)

	got := backupStatusJSON(t, s)

	if got["health"] != "red" {
		t.Errorf("an agent that has never backed up should be red, got %v", got["health"])
	}
	protection, _ := got["protection"].(string)
	if protection == "" {
		t.Fatal("the screen was given nothing to say about a device with no destinations")
	}
	t.Logf("shown to the person: %s", protection)
}

// The three facts reach the wire under names the screen can read.
func TestTheScreenCanShowLastBackupLastVerifiedAndLastOffDevice(t *testing.T) {
	dir := t.TempDir()
	s := exportServer(t, dir)
	svc := s.backupService()

	cfg, err := svc.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	backup.UpsertDestination(&cfg, backup.Destination{
		ID: "elsewhere", Type: backup.DestPairedAgent, Label: "Another machine",
		PairedURL: "https://elsewhere.example", Enabled: true,
	})
	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// Old enough that it no longer protects anything.
	verifiedAt := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339)
	unverifiedAt := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)

	// Newest first: a recent run that was neither verified nor sent anywhere,
	// over an older one that was both.
	for _, h := range []backup.HistoryEntry{
		{ID: "older", Timestamp: verifiedAt, Success: true, Verified: true, OffDevice: true},
		{ID: "newer", Timestamp: unverifiedAt, Success: true, Verified: false, OffDevice: false},
	} {
		if err := svc.ConfigStore.AppendHistory(h); err != nil {
			t.Fatal(err)
		}
	}

	got := backupStatusJSON(t, s)

	if got["last_backup_at"] != unverifiedAt {
		t.Errorf("last_backup_at should be the most recent run (%s), got %v", unverifiedAt, got["last_backup_at"])
	}
	if got["last_verified_at"] != verifiedAt {
		t.Errorf("last_verified_at should skip the unverified run and report %s, got %v",
			verifiedAt, got["last_verified_at"])
	}
	if got["last_off_device_at"] != verifiedAt {
		t.Errorf("last_off_device_at should skip the run that stayed here and report %s, got %v",
			verifiedAt, got["last_off_device_at"])
	}

	// The most recent backup is minutes old, so a screen reading only "when did
	// a backup last run" would say green. Nothing has left the device or been
	// checked in five days, which is the fact that matters.
	if got["health"] != "red" {
		t.Errorf("nothing has left this device in five days; expected red, got %v", got["health"])
	}
}
