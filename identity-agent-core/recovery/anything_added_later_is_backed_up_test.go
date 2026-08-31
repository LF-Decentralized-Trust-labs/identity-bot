package recovery

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/store"

	_ "modernc.org/sqlite"
)

// Does something added to this agent tomorrow get backed up, without anybody
// remembering to add it here?
//
// This is the test the whole of backup was missing, and its absence is why a
// promise the product already made was quietly untrue. Everything else proves
// that what IS collected survives the round trip. Nothing asked whether what
// is on the device is collected in the first place.
//
// The failure it guards against has happened twice. The duress policy sat in a
// tier nothing requested and was absent from every archive while the agent
// stored it, read it back and confirmed it. Then the sweep that would have
// caught that turned out to be in the same unrequested tier — proven correct
// by tests that passed tier3 explicitly, and never run by anything real.
//
// So this writes files and a database that this package has never heard of,
// exactly as a build on top of this core would, and fails if they do not come
// back. Nobody has to update it when something new is added. That is the point
// of it.
func TestAnythingAddedToTheAgentLaterIsBackedUpAndComesBack(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EFutureProof")

	// A file nobody named, in a directory nobody named.
	nested := filepath.Join(oldDir, "something-built-later", "config")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "settings.json"),
		[]byte(`{"written_by":"a build on top of this core"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Key material at the top level, the shape didcomm_keys.json has.
	if err := os.WriteFile(filepath.Join(oldDir, "some_new_keys.json"),
		[]byte(`{"key":"irreplaceable"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// And a database nobody registered, with a write that has NOT been
	// checkpointed — which is the state a live database is normally in, and
	// the one that reading it as bytes gets wrong.
	newDB := filepath.Join(oldDir, "something_built_later.db")
	extra, err := sql.Open("sqlite", newDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extra.Exec(`PRAGMA journal_mode=WAL;
		CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
		INSERT INTO notes (body) VALUES ('committed and not checkpointed')`); err != nil {
		t.Fatal(err)
	}
	// Left OPEN across the backup, as a running agent would have it.
	defer extra.Close()

	// Taken exactly as the agent takes one — the configured default, not tiers
	// chosen by this test. A test that names its own tiers is how the sweep
	// came to be proven and disconnected at the same time.
	archive := archiveWithTheDefaultTiers(t, oldDir, oldStore)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatalf("the restore failed: %v", err)
	}

	// The files.
	for path, want := range map[string]string{
		filepath.Join(newDir, "something-built-later", "config", "settings.json"): `{"written_by":"a build on top of this core"}`,
		filepath.Join(newDir, "some_new_keys.json"):                               `{"key":"irreplaceable"}`,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("a file nobody named did not come back: %s: %v", filepath.Base(path), err)
		}
		if string(got) != want {
			t.Fatalf("%s came back wrong: %q", filepath.Base(path), got)
		}
	}

	// The database — and its uncheckpointed row, which is the part reading it
	// as a file loses.
	restoredDB, err := sql.Open("sqlite", filepath.Join(newDir, "something_built_later.db"))
	if err != nil {
		t.Fatalf("a database nobody registered did not come back: %v", err)
	}
	defer restoredDB.Close()
	var body string
	if err := restoredDB.QueryRow(`SELECT body FROM notes`).Scan(&body); err != nil {
		t.Fatalf("the restored database is empty or unreadable: %v", err)
	}
	if body != "committed and not checkpointed" {
		t.Fatalf("the database came back missing its most recent write: %q", body)
	}
}

// archiveWithTheDefaultTiers takes a backup the way the agent does, with
// whatever tiers are configured rather than tiers a test chose.
func archiveWithTheDefaultTiers(t *testing.T, dir string, st store.Store) []byte {
	t.Helper()
	tiers := backup.DefaultConfig().DefaultTiers
	c := &backup.Collector{DataDir: dir, Store: st}
	opts := backup.DefaultCollectOptions(tiers)
	bundle, pointers, err := c.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.CreateArchive(opts, backup.ExportRequest{
		Mnemonic: testPhrase, Tiers: tiers,
		Bundle: bundle, ExternalPointers: pointers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Bytes
}

// A backup taken with the configured default must include the sweep.
//
// Stated as its own assertion because it is the single line that made all of
// the above untrue, and it is one edit away from being untrue again. If
// somebody narrows the default tiers, this says so directly rather than
// leaving the test above to fail for a reason that looks like something else.
func TestTheConfiguredDefaultTakesEverythingOnTheDevice(t *testing.T) {
	tiers := backup.DefaultConfig().DefaultTiers
	for _, want := range []string{backup.TierCritical, backup.TierImportant, backup.TierFull} {
		found := false
		for _, t := range tiers {
			if t == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("the default tiers are %v, which leaves out %q — "+
				"%q is the sweep, and without it a backup carries only the files "+
				"somebody remembered to name", tiers, want, backup.TierFull)
		}
	}
}
