package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"os"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

func readFileForTest(path string) ([]byte, error) { return os.ReadFile(path) }

// exportServer is an agent with somewhere to keep its data, which is what a
// real one always has — collecting a backup reads through the store.
func exportServer(t *testing.T, dir string) *CoreServer {
	t.Helper()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	t.Cleanup(func() { ds.Close() })
	return &CoreServer{DataDir: dir, DataStore: ds}
}

// Taking a backup must not require anybody to hand over their recovery phrase.
//
// It used to: the client loaded the words and posted them with every export,
// which meant the phrase had to stay on the device forever, and somebody who
// had written it down and wanted it gone could no longer back up. Both of those
// are consequences of a secret being the price of a routine operation.

func exportRequest(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/backup/export", strings.NewReader(body))
	s.handleBackupExport(w, r)
	return w
}

// A root device holds its own seed. Asking its owner to type the words again
// only creates a second copy in flight; the key derived is the same one.
func TestARootDeviceBacksUpWithoutBeingGivenAPhrase(t *testing.T) {
	dir := t.TempDir()
	seed, err := backup.MnemonicToBIP39Seed(sealTestMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatalf("store root seed: %v", err)
	}
	s := exportServer(t, dir)

	w := exportRequest(t, s, `{"dest_path":"out.iab"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a root device could not back up without a phrase: %d %s", w.Code, w.Body)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if body["success"] != true {
		t.Fatalf("export did not report success: %v", body)
	}
}

// And what it wrote must open with the owner's words, or the backup is a file
// that only looks like one.
func TestWhatItWroteOpensWithTheOwnersPhrase(t *testing.T) {
	dir := t.TempDir()
	seed, _ := backup.MnemonicToBIP39Seed(sealTestMnemonic, "")
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	s := exportServer(t, dir)

	// dest_path chooses the NAME, not the place. It used to be taken as given
	// and passed to WriteFile, so a caller picked any path on the machine — the
	// identity store included — and could also push this identity's sealed
	// archive into a synced folder.
	if w := exportRequest(t, s, `{"dest_path":"out.iab"}`); w.Code != http.StatusOK {
		t.Fatalf("export failed: %d %s", w.Code, w.Body)
	}

	dest := filepath.Join(dir, "exports", "out.iab")
	raw, err := readFileForTest(dest)
	if err != nil {
		t.Fatalf("archive not written: %v", err)
	}
	if _, _, err := backup.OpenArchive(raw, backup.OpenRequest{Mnemonic: sealTestMnemonic}); err != nil {
		t.Fatalf("the owner's phrase did not open what the agent wrote: %v", err)
	}
}

// A device with neither a seed nor recovery keys must refuse rather than write
// something nobody could ever open. The error has to say which of the two is
// missing, because the remedies are completely different.
func TestADeviceWithNoWayInRefusesToWriteAnArchive(t *testing.T) {
	s := exportServer(t, t.TempDir())

	w := exportRequest(t, s, `{}`)
	if w.Code == http.StatusOK {
		t.Fatal("an archive nobody could open was written")
	}
	if !strings.Contains(w.Body.String(), "no way to unlock") {
		t.Fatalf("the refusal does not say what is wrong: %s", w.Body)
	}
}

// A mnemonic is still accepted, because recovery flows pass one deliberately.
// Removing the requirement must not remove the capability.
func TestAPhraseIsStillHonouredWhenOneIsGiven(t *testing.T) {
	dir := t.TempDir()
	s := exportServer(t, dir)

	body := `{"mnemonic":"` + sealTestMnemonic + `","dest_path":"out.iab"}`
	if w := exportRequest(t, s, body); w.Code != http.StatusOK {
		t.Fatalf("an explicit phrase was rejected: %d %s", w.Code, w.Body)
	}
}
