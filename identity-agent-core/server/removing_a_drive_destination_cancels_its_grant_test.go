package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/backup"
	"identity-agent-core/backup/remote/fakedrive"
)

// Removing Google Drive as a destination takes the app out of the person's
// Google account and deletes the sign-in it was holding. Forgetting it here
// alone would leave a live grant to their Drive app-data folder that nothing on
// this machine knows about any more.
func TestRemovingADriveDestinationCancelsTheGrantAndDeletesTheSignIn(t *testing.T) {
	d := fakedrive.New("agent-app.apps.example")
	defer d.Close()
	refresh := d.GrantRefreshToken()

	dir := t.TempDir()
	s := &CoreServer{DataDir: dir}
	svc := s.backupService()
	svc.Google = &backup.GoogleSignIn{ClientID: "agent-app.apps.example", Endpoints: d.Endpoints()}
	credID, err := svc.SaveDestinationCredentials(backup.RemoteCredentialSecrets{
		OAuthRefreshToken: refresh, OAuthClientID: "agent-app.apps.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveConfig(backup.Config{Destinations: []backup.Destination{
		{ID: "google-drive", Type: backup.DestCloudUser, CloudProvider: backup.GoogleProviderName, CredentialID: credID},
		{ID: "other", Type: backup.DestCloudUser, CloudProvider: "s3", CredentialID: "keep-me"},
	}}); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(dir, "backup", "credentials_"+credID+".enc")
	if _, err := os.Stat(credFile); err != nil {
		t.Fatalf("test set-up: %v", err)
	}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "google-drive")
	r := httptest.NewRequest(http.MethodDelete, "/api/backup/destinations/google-drive", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	s.handleBackupDeleteDestination(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	if len(d.Revoked) != 1 || d.Revoked[0] != refresh {
		t.Fatalf("the sign-in must be cancelled at Google, revoked %v", d.Revoked)
	}
	if _, err := os.Stat(credFile); !os.IsNotExist(err) {
		t.Fatalf("the credential file is still on disk: %v", err)
	}
	cfg, _ := svc.LoadConfig()
	if len(cfg.Destinations) != 1 || cfg.Destinations[0].ID != "other" {
		t.Fatalf("the other destination must be left alone: %+v", cfg.Destinations)
	}
}
