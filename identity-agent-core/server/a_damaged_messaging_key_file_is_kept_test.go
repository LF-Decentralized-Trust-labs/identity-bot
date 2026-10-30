package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/coretypes"
)

// The messaging key file is read as empty only when it is not there. When it
// is there and cannot be used, every way in refuses, says the keys are
// unavailable, and leaves the file exactly as it was, so it can be restored
// from a backup. Reading it as empty instead made new keys over it, and every
// contact that knew the old ones could no longer reach this identity.
func TestADamagedMessagingKeyFileIsNeverReplaced(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if _, err := s.keySetFor("Eheld"); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(s.didcommKeysPath())
	if err != nil {
		t.Fatal(err)
	}
	// Cut short, the way an interrupted copy or a failing disk leaves it.
	damaged := good[:len(good)/2]
	if err := os.WriteFile(s.didcommKeysPath(), damaged, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.keySetFor("Eheld"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Errorf("a held identifier's keys: %v, want the keys unavailable", err)
	}
	if _, err := s.keySetFor("Enew"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Errorf("first use of a new identifier: %v, want the keys unavailable", err)
	}
	ks, _ := didcomm.GenerateKeySet("")
	if err := s.storeKeySetFor("Efounded", ks); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Errorf("filing keys at inception: %v, want the keys unavailable", err)
	}
	if _, err := s.hasKeySet("Eheld"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Errorf("asking whether keys exist: %v, want the keys unavailable", err)
	}
	if err := s.fileMessagingKeysFor("Efounded"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Errorf("filing derived keys: %v, want the keys unavailable", err)
	}

	after, err := os.ReadFile(s.didcommKeysPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, damaged) {
		t.Fatal("the damaged key file was written over")
	}
	if _, err := os.Stat(s.didcommKeysPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("a replacement was begun beside the damaged file: %v", err)
	}
}

// A file that parses but holds no key set at all is damaged too. Nothing here
// writes it; an empty set is written as {}.
func TestAKeyFileHoldingNullIsDamaged(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if err := os.WriteFile(s.didcommKeysPath(), []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.keySetFor("Enew"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("%v, want the keys unavailable", err)
	}
	if b, _ := os.ReadFile(s.didcommKeysPath()); string(b) != "null" {
		t.Fatalf("the file was written over: %q", b)
	}
}

// A key file that is there and cannot be read at all is refused the same way.
// A directory in its place cannot be read on any platform, whoever runs it.
func TestAnUnreadableMessagingKeyFileIsRefused(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if err := os.Mkdir(s.didcommKeysPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.keySetFor("Enew"); !errors.Is(err, coretypes.ErrKeysUnavailable) {
		t.Fatalf("%v, want the keys unavailable", err)
	}
	if fi, err := os.Stat(s.didcommKeysPath()); err != nil || !fi.IsDir() {
		t.Fatalf("what stood in the key file's place was replaced: %v", err)
	}
}

// With no key file yet, an identifier's keys are made once and kept.
func TestAMissingKeyFileMeansNoKeysYet(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if has, err := s.hasKeySet("Enew"); err != nil || has {
		t.Fatalf("before any keys: has=%v err=%v", has, err)
	}
	first, err := s.keySetFor("Enew")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.keySetFor("Enew")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.EdPub, again.EdPub) {
		t.Fatal("the keys were made a second time")
	}
}

// Many first uses at once make one keyset, not one each with the last saved.
func TestAConcurrentFirstUseMakesOneKeySet(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	const n = 16
	got := make([]*didcomm.KeySet, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = s.keySetFor("Enew")
		}(i)
	}
	wg.Wait()
	kept, err := s.keySetFor("Enew")
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if !bytes.Equal(got[i].EdPub, kept.EdPub) {
			t.Fatalf("caller %d was handed keys other than the ones kept", i)
		}
	}
}

// Over HTTP an unusable key file is this Identity Agent's fault, so it
// answers 503, and still writes nothing.
func TestADamagedKeyFileAnswers503(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if err := os.WriteFile(s.didcommKeysPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleGetDIDCommDID(w, httptest.NewRequest(http.MethodGet, "/api/didcomm/did?aid=Enew", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("answered %d %s, want 503", w.Code, w.Body.String())
	}
	if b, _ := os.ReadFile(s.didcommKeysPath()); string(b) != "{" {
		t.Fatalf("the file was written over: %q", b)
	}
}

// peersInTest is the peers list, for tests that set one up or look at it.
// A damaged file reads as none here; the tests above check that case.
func (s *CoreServer) peersInTest() map[string]peerRecord {
	m, err := s.loadPeers()
	if err != nil {
		return map[string]peerRecord{}
	}
	return m
}
