package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

// PUT /api/backup/config decoded a whole config and saved it verbatim, so every
// field the sender left out was reset. The client sends six fields and omits
// the rest, so saving any backup setting from a screen wiped things nobody
// touched — including who is able to open this identity's archives.

func putConfig(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/api/backup/config", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	s.handleBackupPutConfig(w, r)
	return w
}

func TestSavingOneSettingDoesNotWipeTheOthers(t *testing.T) {
	dir := t.TempDir()
	s := exportServer(t, dir)

	// A machine that has volunteered to hold archives for other identities, and
	// an owner who can open this one's archives.
	svc := s.backupService()
	cfg, err := svc.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Offer = backup.Offer{Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 4096}
	cfg.SealToPublicKeysB64 = []string{"a-recipient-key"}
	if err := svc.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// What the client actually sends when somebody changes a backup setting:
	// six fields, and not these two.
	w := putConfig(t, s, `{"enabled":true,"default_tiers":["tier1"],"destinations":[],`+
		`"schedule_daily":true,"wifi_only_tier23":true,"recovery_preset":"seed"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("saving a setting failed: %d %s", w.Code, w.Body)
	}

	after, err := svc.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !after.Offer.Accepting || !after.Offer.AcceptingNewIdentities {
		t.Fatal("saving a backup setting stopped this machine holding archives for others, " +
			"so somebody else's destination silently began refusing everything")
	}
	if after.Offer.ReserveBytes != 4096 {
		t.Fatalf("the disk reserve was reset to %d", after.Offer.ReserveBytes)
	}
	if len(after.SealToPublicKeysB64) != 1 || after.SealToPublicKeysB64[0] != "a-recipient-key" {
		t.Fatalf("the owners able to open this identity's archives were wiped: %v",
			after.SealToPublicKeysB64)
	}
	// And what WAS sent did change.
	if !after.Enabled {
		t.Fatal("the setting that was actually sent did not take effect")
	}
}

func TestConfigCannotAddAReaderOfEveryFutureArchive(t *testing.T) {
	// A seal recipient is a standing key to every archive written from now on,
	// openable by that recipient alone. Archives carry no recipient names by
	// design, so a planted slot cannot be told from a legitimate one by looking.
	dir := t.TempDir()
	s := exportServer(t, dir)

	w := putConfig(t, s, `{"seal_to_public_keys_b64":["an-attackers-key"]}`)
	if w.Code == http.StatusOK {
		t.Fatal("configuration added somebody able to open every future archive")
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("refused with %d, which is not the refusal a caller can act on", w.Code)
	}

	after, err := s.backupService().LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.SealToPublicKeysB64) != 0 {
		t.Fatalf("the key was stored anyway: %v", after.SealToPublicKeysB64)
	}
}

func TestAnExportCannotChooseWhereOnTheMachineItLands(t *testing.T) {
	// dest_path was taken as given and passed to MkdirAll and WriteFile, so a
	// caller chose any path on the machine and the archive replaced whatever
	// was there — the identity store included. It pointed outward too: an
	// archive written into a synced folder is this identity's sealed backup
	// leaving the machine on somebody else's instruction, which is the same
	// hole this package closed on the read side with the arrow reversed.
	dir := t.TempDir()
	seed, _ := backup.MnemonicToBIP39Seed(sealTestMnemonic, "")
	if err := secureenclave.StoreRootSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	s := exportServer(t, dir)

	victim := filepath.Join(t.TempDir(), "important.txt")
	if err := os.WriteFile(victim, []byte("not an archive"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, dest := range []string{
		victim,
		filepath.Join(dir, "identity.db"),
		"../../escaped.iab",
		filepath.Join(dir, "exports", "..", "..", "escaped.iab"),
		"/tmp/somewhere-else.iab",
	} {
		w := exportRequest(t, s, `{"dest_path":"`+dest+`"}`)
		if w.Code == http.StatusOK {
			// It may have been accepted after being reduced to a bare name,
			// which is fine — what must not happen is the file being written
			// where the caller asked.
			if _, err := os.Stat(dest); err == nil && dest == victim {
				body, _ := os.ReadFile(victim)
				if string(body) != "not an archive" {
					t.Fatalf("an export overwrote a file outside the data directory: %s", dest)
				}
			}
			continue
		}
	}

	// The file the caller pointed at is untouched.
	body, err := os.ReadFile(victim)
	if err != nil || string(body) != "not an archive" {
		t.Fatalf("a file outside the data directory was overwritten: %v %q", err, body)
	}

	// And a plain name still works, landing where this agent keeps archives.
	if w := exportRequest(t, s, `{"dest_path":"chosen-name.iab"}`); w.Code != http.StatusOK {
		t.Fatalf("choosing a name was refused: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "exports", "chosen-name.iab")); err != nil {
		t.Fatalf("the archive did not land where this agent keeps them: %v", err)
	}
}
