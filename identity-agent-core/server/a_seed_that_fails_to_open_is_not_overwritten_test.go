package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"identity-agent-core/secureenclave"
)

// flakyWrapper is a hardware stand-in whose next Unwrap can be made to fail and
// every later one to work, as a brief hardware or service hiccup would. Only the
// first open fails, so a handler that goes on to store a new seed would get past
// the store-time round-trip check and really overwrite the old one.
type flakyWrapper struct{ failNext atomic.Int32 }

func (*flakyWrapper) Available() bool { return true }
func (*flakyWrapper) Scheme() string  { return "flaky-hw" }
func (*flakyWrapper) Wrap(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0x5a
	}
	return out, nil
}
func (f *flakyWrapper) Unwrap(b []byte) ([]byte, error) {
	if f.failNext.Add(-1) >= 0 {
		return nil, errors.New("the hardware key did not answer")
	}
	return f.Wrap(b)
}

// handleSetRootSeed writes over the stored seed only when there is none. A stored
// seed that could not be read (anything but ErrNoRootSeed) is refused, because a
// different phrase written over it would destroy the only copy.
func TestSetRootSeedDoesNotOverwriteASeedThatFailedToOpen(t *testing.T) {
	s := rootSeedServer(t)
	fw := &flakyWrapper{}
	defer secureenclave.UseSeedWrapper(fw)()

	original := bytes.Repeat([]byte{7}, 64)
	if w := postSeed(s, base64.StdEncoding.EncodeToString(original), false); w.Code != http.StatusCreated {
		t.Fatalf("first store: %d %s", w.Code, w.Body)
	}
	path := filepath.Join(s.DataDir, "secureenclave", "root_seed.key")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fw.failNext.Store(1)
	different := bytes.Repeat([]byte{9}, 64)
	w := postSeed(s, base64.StdEncoding.EncodeToString(different), false)
	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Fatalf("a seed that could not be read was answered with a write: %d %s", w.Code, w.Body)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("the stored seed was overwritten after a failed read")
	}

	// It opens again and is the original.
	fw.failNext.Store(0)
	got, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("the original seed is not intact: %v", err)
	}
}
