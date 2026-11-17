package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file of accepted ownership-change invitations decides which identity this
// device reveals a key for, so a write to the folder it sits in must not change
// what it says. Each case fails if the file is read without checking its tag.
func TestAKeptCeremonyInviteThatWasRewrittenIsNotBelieved(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)
	path := filepath.Join(s.DataDir, ceremonyInvitesFile)

	read := func() map[string]json.RawMessage {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var f map[string]json.RawMessage
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	write := func(f map[string]json.RawMessage) {
		b, _ := json.Marshal(f)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	original, _ := os.ReadFile(path)
	recalled := func() bool {
		s.redeemedInvites = redeemedInviteBook{} // a restart: only the disk is left
		_, ok := s.recallRedeemedInvite("tok")
		return ok
	}
	if !recalled() {
		t.Fatal("the invitation this device kept was not recalled after a restart")
	}

	// Another identity named in place of the organisation that invited this device.
	f := read()
	f["invites"] = json.RawMessage(strings.Replace(string(f["invites"]), "EORGAID", "EEVILAID", 1))
	write(f)
	if recalled() {
		t.Error("an entry rewritten to name another identity was believed")
	}

	// What this device signed at a place dropped, with the tag the file had: the
	// pin is what stops it signing a second, different event there.
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ceremonyInvitesMu.Lock()
	kept := s.readCeremonyInvites()
	k, ok := kept["tok"]
	if !ok {
		ceremonyInvitesMu.Unlock()
		t.Fatal("the invitation this device kept was not read back")
	}
	k.Signed = map[string]string{"1": "EFIRSTROTATION"}
	kept["tok"] = k
	if err := s.writeCeremonyInvites(kept); err != nil {
		ceremonyInvitesMu.Unlock()
		t.Fatal(err)
	}
	ceremonyInvitesMu.Unlock()
	pinned, _ := os.ReadFile(path)
	f = read()
	f["invites"] = json.RawMessage(strings.Replace(string(f["invites"]), `"signed":{"1":"EFIRSTROTATION"}`, `"signed":{}`, 1))
	if !strings.Contains(string(f["invites"]), `"signed":{}`) {
		t.Fatal("the test did not find the pin it means to drop")
	}
	write(f)
	if recalled() {
		t.Error("an entry whose pin was dropped, with its tag kept, was believed")
	}
	if err := os.WriteFile(path, pinned, 0o600); err != nil {
		t.Fatal(err)
	}
	if !recalled() {
		t.Error("the pinned file as this Identity Agent wrote it was refused")
	}

	// A file with no tag at all, as one written by anything but this Identity Agent.
	if err := os.WriteFile(path, []byte(`{"tok":{"base":"http://x","site_aid":"EEVILAID","site_oobi":"","at":"2099-01-01T00:00:00Z"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if recalled() {
		t.Error("an untagged file was believed")
	}

	// What this Identity Agent itself wrote is believed again.
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if !recalled() {
		t.Error("the file as this Identity Agent wrote it was refused")
	}
}
