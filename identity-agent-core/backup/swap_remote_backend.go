package backup

import (
	"context"
	"fmt"
	"strings"

	"identity-agent-core/backup/remote"
)

// PointGoogleDriveAt sends every Google Drive destination to the given
// endpoints instead of Google, and returns what puts the original back. The
// running core never calls it: it exists so a harness can stand a stand-in
// Google (backup/remote/fakedrive) behind a real core and drive an app against
// that when the Google OAuth client for a build is not available.
func PointGoogleDriveAt(ep remote.GoogleEndpoints) (restore func()) {
	orig := remoteBackendFactory
	remoteBackendFactory = func(dest Destination, creds RemoteCredentialSecrets) (remoteBackend, error) {
		if dest.CloudProvider == GoogleProviderName {
			return remote.NewGoogleDriveBackend(toRemoteDestination(dest), toRemoteCredentials(creds), ep, nil)
		}
		return orig(dest, creds)
	}
	return func() { remoteBackendFactory = orig }
}

// PutArchiveInDrive files an archive in the Drive destination under the given
// file name, in the identity's own folder, as another machine of the person's
// would have. For a harness: it is how an archive that is already in the
// person's Drive (older, or renamed) is set up for a restore to find.
func (s *Service) PutArchiveInDrive(destID, name string, data []byte) error {
	cfg, err := s.LoadConfig()
	if err != nil {
		return err
	}
	for _, d := range cfg.Destinations {
		if d.ID != destID {
			continue
		}
		creds, err := s.CredentialStore.Load(d.CredentialID)
		if err != nil {
			return err
		}
		b, err := remoteBackendFactory(d, creds)
		if err != nil {
			return err
		}
		d = s.withOwnPrefix(d)
		key := name
		if p := strings.Trim(d.CloudPrefix, "/"); p != "" {
			key = p + "/" + name
		}
		return b.Push(context.Background(), key, data)
	}
	return fmt.Errorf("no destination %q", destID)
}
