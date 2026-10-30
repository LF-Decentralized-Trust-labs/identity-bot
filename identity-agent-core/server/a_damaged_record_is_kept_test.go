package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
)

// damage writes a cut-short JSON record at path and returns its bytes, so a
// test can check afterwards that nothing was written over them.
func damage(t *testing.T, path string) []byte {
	t.Helper()
	b := []byte(`{"cut short`)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func leftAlone(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the damaged %s was written over: %q", filepath.Base(path), got)
	}
	if left, _ := filepath.Glob(path + ".tmp*"); len(left) > 0 {
		t.Fatalf("a replacement for %s was begun beside it: %v", filepath.Base(path), left)
	}
}

// A damaged peers file is refused by everything that reads or adds to it, and
// kept for restoring. Read as empty, the next peer added was saved over it and
// every other peer was gone.
func TestADamagedPeersFileIsNeverReplaced(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	damaged := damage(t, s.didcommPeersPath())

	if _, _, err := s.peerFor("Esomeone"); !errors.Is(err, errRecordUnreadable) {
		t.Errorf("looking up a peer: %v, want the record unreadable", err)
	}
	ks, err := didcomm.GenerateKeySet("Eowner")
	if err != nil {
		t.Fatal(err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rememberPeerFromAdoption(did, "https://owner.example"); !errors.Is(err, errRecordUnreadable) {
		t.Errorf("adding a peer: %v, want the record unreadable", err)
	}
	leftAlone(t, s.didcommPeersPath(), damaged)

	// And a message arriving meanwhile is this Identity Agent's fault, not the
	// sender's: 503, rather than "not a registered peer".
	env, _ := json.Marshal(didcomm.Envelope{Protected: didcomm.ProtectedHeader{Skid: "Esomeone"}})
	w := httptest.NewRecorder()
	s.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(env)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a message arriving answered %d %s, want 503", w.Code, w.Body.String())
	}
	leftAlone(t, s.didcommPeersPath(), damaged)
}

// With no peers file yet there are no peers, and the first is kept.
func TestAMissingPeersFileMeansNoPeersYet(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if _, known, err := s.peerFor("Eowner"); err != nil || known {
		t.Fatalf("before any peers: known=%v err=%v", known, err)
	}
	ks, _ := didcomm.GenerateKeySet("Eowner")
	did, _ := ks.DID()
	if err := s.rememberPeerFromAdoption(did, "https://owner.example"); err != nil {
		t.Fatal(err)
	}
	if _, known, err := s.peerFor("Eowner"); err != nil || !known {
		t.Fatalf("after adding one: known=%v err=%v", known, err)
	}
}

// A damaged record of which branch the messaging keys came from is refused
// rather than replaced with a new branch, which would lose the one number a
// restore needs to bring the keys back.
func TestADamagedMessagingKeyRecordIsNeverReplaced(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	damaged := damage(t, s.messagingKeyPath())
	if _, _, err := s.deriveMessagingKeys(""); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("%v, want the keys unavailable", err)
	}
	leftAlone(t, s.messagingKeyPath(), damaged)
}

// A damaged record of the witnessing key is refused rather than replaced with
// a new key, which would retire every receipt already issued.
func TestADamagedWitnessKeyRecordIsNeverReplaced(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	damaged := damage(t, s.witnessKeyPath())
	if _, _, err := s.witnessSigningKey(); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("%v, want the keys unavailable", err)
	}
	leftAlone(t, s.witnessKeyPath(), damaged)
}

// A damaged record identity is refused rather than replaced with a new one,
// which would abandon the record identity this identity's key log approved.
func TestADamagedRecordIdentityIsNeverReplaced(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	damaged := damage(t, s.recordIdentityPath())
	if _, _, err := s.recordIdentity(); !errors.Is(err, errRecordUnreadable) {
		t.Fatalf("%v, want the record unreadable", err)
	}
	s.reloadRecordIdentity()
	// An add-on holding the record is told it cannot be read, not that there
	// is none, and the hold is let go either way.
	_, _, found, release, err := s.holdTheRecord()
	release()
	if !errors.Is(err, errRecordUnreadable) || found {
		t.Fatalf("holding the record: found=%v err=%v, want the record unreadable", found, err)
	}
	if !s.record.mu.TryLock() {
		t.Fatal("the record is still held after refusing")
	}
	s.record.mu.Unlock()
	leftAlone(t, s.recordIdentityPath(), damaged)
}

// A damaged list of interactions whose anchors are not held is not added to,
// which would save one entry over all the others.
func TestADamagedAnchorsNotHeldListIsNeverReplaced(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	path := filepath.Join(s.DataDir, anchoredNotHeldFile)
	damaged := damage(t, path)
	s.noteAnchoredNotHeld("Einteraction", []json.RawMessage{json.RawMessage(`{}`)})
	if _, err := s.anchoredNotHeld(); !errors.Is(err, errRecordUnreadable) {
		t.Fatalf("%v, want the record unreadable", err)
	}
	leftAlone(t, path, damaged)
}

// The log says what was refused and how to recover.
func TestADamagedRecordSaysToRestoreIt(t *testing.T) {
	var v map[string]any
	path := filepath.Join(t.TempDir(), "record.json")
	damage(t, path)
	_, err := readKeptRecord(path, "a record", "nothing works", errRecordUnreadable, &v)
	if err == nil || !strings.Contains(err.Error(), "restore it from a backup") {
		t.Fatalf("the error does not say how to recover: %v", err)
	}
	if got := statusForUnreadable(err, http.StatusBadGateway); got != http.StatusServiceUnavailable {
		t.Fatalf("answered %d, want 503", got)
	}
}

// The error names no path, so it can travel to any reply. Where the data
// lives, and so the account it runs under, is said only in the log.
func TestAnUnreadableRecordsErrorNamesNoPath(t *testing.T) {
	var v map[string]any
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	breakRecord(t, path)
	_, err := readKeptRecord(path, "a record", "nothing works", errRecordUnreadable, &v)
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "record.json") {
		t.Fatalf("the error names where the data lives: %v", err)
	}
}
