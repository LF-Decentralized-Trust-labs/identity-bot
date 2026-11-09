package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// aMachinesWrapper stands one processor's secure element: it opens only what it
// wrapped itself, and says so when handed another machine's, as hardware does.
type aMachinesWrapper struct{ id byte }

func (aMachinesWrapper) Available() bool { return true }
func (aMachinesWrapper) Scheme() string  { return "test-wrap" }
func (w aMachinesWrapper) Wrap(p []byte) ([]byte, error) {
	out := []byte{w.id}
	for _, b := range p {
		out = append(out, b^0xA5^w.id)
	}
	return out, nil
}
func (w aMachinesWrapper) Unwrap(b []byte) ([]byte, error) {
	if len(b) == 0 || b[0] != w.id {
		return nil, errors.New("this key was wrapped by another machine's hardware")
	}
	out := make([]byte, 0, len(b)-1)
	for _, c := range b[1:] {
		out = append(out, c^0xA5^w.id)
	}
	return out, nil
}

// Restoring an identity onto a new machine must not take that machine's
// ability to back up with it. The old machine's credential key is wrapped under
// its own hardware, so carried across it cannot be opened, a new one is refused
// beside files that cannot be read, and the credential store fails for good.
func TestARestoreOntoANewMachineLeavesItsOwnBackupsWorking(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	use := func(id byte) {
		restore := secureenclave.UseSeedWrapper(aMachinesWrapper{id: id})
		t.Cleanup(restore)
	}

	// Machine A backs up to Drive.
	dirA := t.TempDir()
	use(1)
	csA, err := backup.NewCredentialStore(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if err := csA.Save("drive", backup.RemoteCredentialSecrets{OAuthRefreshToken: "1//A", OAuthClientID: "id"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "backup_config.json"), []byte(`{"destinations":[{"id":"drive-A"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "kept.json"), []byte(`{"kept":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// What an archive made on A holds: its own files, and A's backup files as
	// an archive made before they were excluded would carry them.
	extra := map[string][]byte{}
	for _, rel := range []string{"kept.json", "backup/credentials_master.key", "backup/credentials_drive.enc", "backup_config.json"} {
		raw, err := os.ReadFile(filepath.Join(dirA, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		extra[backup.FileSectionPrefix+rel] = raw
	}

	// Machine B has its own hardware, its own sign-in and its own destination.
	dirB := t.TempDir()
	use(2)
	csB, err := backup.NewCredentialStore(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if err := csB.Save("drive", backup.RemoteCredentialSecrets{OAuthRefreshToken: "1//B", OAuthClientID: "id"}); err != nil {
		t.Fatal(err)
	}
	configB := []byte(`{"destinations":[{"id":"drive-B"}]}`)
	if err := os.WriteFile(filepath.Join(dirB, "backup_config.json"), configB, 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := RestoreFromArchive(buildTestArchiveWith(t, testMnemonic, nil, extra), OpenRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(dirB, nil, nil).applyPayload(payload); err != nil {
		t.Fatal(err)
	}

	if b, _ := os.ReadFile(filepath.Join(dirB, "kept.json")); string(b) != `{"kept":true}` {
		t.Fatalf("the identity's own files did not come back: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dirB, "backup_config.json")); !bytes.Equal(b, configB) {
		t.Fatalf("the new machine lost its own destinations: %s", b)
	}
	reopened, err := backup.NewCredentialStore(dirB)
	if err != nil {
		t.Fatalf("after the restore the new machine cannot open its credential store: %v", err)
	}
	got, err := reopened.Load("drive")
	if err != nil || got.OAuthRefreshToken != "1//B" {
		t.Fatalf("the new machine's own sign-in did not survive the restore: %+v %v", got, err)
	}
	if err := reopened.Save("again", backup.RemoteCredentialSecrets{OAuthRefreshToken: "1//B2"}); err != nil {
		t.Fatalf("signing in to Drive again on the new machine: %v", err)
	}
}
