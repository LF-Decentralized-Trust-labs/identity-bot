package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/backup"
)

// The owner's answer about where a destination is must not move to another one.
//
// Elsewhere is the one field whose own comment says only a person can answer
// it, and it decides whether the agent tells somebody a fire would take
// everything. Go decodes a JSON array onto an existing slice POSITIONALLY,
// reusing each element in place — so a client that removes a destination and
// sends the rest hands destination two the answer that belonged to destination
// one, and the warning flips with nothing said.
func TestAnOwnersAnswerAboutWhereADestinationIsStaysWithIt(t *testing.T) {
	s := agentWithNoIdentity(t)

	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Destinations = []backup.Destination{
		{ID: "d1", Type: backup.DestPairedAgent, Label: "Same desk", Enabled: true},
		{ID: "d2", Type: backup.DestPairedAgent, Label: "Sister's house",
			Enabled: true, Elsewhere: true},
	}
	if err := s.backupService().SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// What the app sends when somebody removes the first destination: the
	// remaining list, without the field it has no control for.
	body, _ := json.Marshal(map[string]interface{}{
		"destinations": []map[string]interface{}{
			{"id": "d2", "type": "paired_agent", "label": "Sister's house", "enabled": true},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/config", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleBackupPutConfig(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("saving the settings answered %d: %s", rec.Code, rec.Body.String())
	}

	after, err := s.backupService().LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Destinations) != 1 {
		t.Fatalf("expected one destination, got %d", len(after.Destinations))
	}
	if after.Destinations[0].ID != "d2" {
		t.Fatalf("the wrong destination survived: %s", after.Destinations[0].ID)
	}
	if !after.Destinations[0].Elsewhere {
		t.Fatal("the owner said this destination is somewhere else, and removing a " +
			"different one silently took that answer away")
	}
}

// And a client that genuinely changes the answer is believed.
func TestAnOwnerCanChangeTheAnswer(t *testing.T) {
	s := agentWithNoIdentity(t)
	cfg, _ := s.backupService().LoadConfig()
	cfg.Destinations = []backup.Destination{
		{ID: "d1", Type: backup.DestPairedAgent, Enabled: true, Elsewhere: true},
	}
	if err := s.backupService().SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"destinations": []map[string]interface{}{
			{"id": "d1", "type": "paired_agent", "enabled": true, "elsewhere": false},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/config", bytes.NewReader(body))
	s.handleBackupPutConfig(httptest.NewRecorder(), req)

	after, _ := s.backupService().LoadConfig()
	if after.Destinations[0].Elsewhere {
		t.Fatal("the owner said this is no longer elsewhere and was not believed")
	}
}
