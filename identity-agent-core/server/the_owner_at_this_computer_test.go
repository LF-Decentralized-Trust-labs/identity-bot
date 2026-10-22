package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A program on this computer is not the owner by being here. It takes the
// secret the core was started with, on an owner-only route as on any other.
func TestARequestFromThisComputerNeedsTheSecretToBeTheOwner(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.LocalOwnerSecret = testOwnerSecret
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	router := s.buildRouter("")

	ask := func(secret string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/didcomm/send", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:52100"
		r.Header.Set("Content-Type", "application/json")
		if secret != "" {
			r.Header.Set(LocalOwnerSecretHeader, secret)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if code := ask(""); code != http.StatusForbidden {
		t.Fatalf("a program on this computer without the secret: %d, want 403", code)
	}
	if code := ask(strings.Repeat("x", len(testOwnerSecret))); code != http.StatusForbidden {
		t.Fatalf("a program on this computer with the wrong secret: %d, want 403", code)
	}
	if code := ask(testOwnerSecret); code == http.StatusForbidden {
		t.Fatalf("the owner at this computer, carrying the secret, was refused")
	}
}

// The secret is not the owner from anywhere else: a request through a tunnel
// or from the network carrying it is still not local.
func TestTheSecretDoesNotMakeARemoteRequestTheOwners(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	for _, c := range []struct {
		name, remote string
		headers      map[string]string
	}{
		{"from the network", "203.0.113.9:51000", nil},
		{"through a tunnel", "127.0.0.1:51000", map[string]string{"X-Forwarded-For": "203.0.113.9"}},
		{"from a web page", "127.0.0.1:51000", map[string]string{"Origin": "https://elsewhere.test"}},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/identity", nil)
		r.RemoteAddr = c.remote
		r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		if s.isLocalOwnerRequest(r) {
			t.Errorf("%s, carrying the secret: taken for the owner", c.name)
		}
	}
}

// Without the secret, a program on this computer is resolved as remote and
// nameless, not as the local owner.
func TestAProgramHereWithoutTheSecretIsNotTheLocalOwner(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	r := httptest.NewRequest(http.MethodGet, "/api/identity", nil)
	r.RemoteAddr = "127.0.0.1:51000"
	if cc := (tokenAwareResolver{s: s}).Resolve(r); !cc.Remote || cc.CallerAID == "local-owner" {
		t.Fatalf("without the secret: %+v", cc)
	}
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	if cc := (tokenAwareResolver{s: s}).Resolve(r); cc.Remote || cc.CallerAID != "local-owner" {
		t.Fatalf("with the secret: %+v", cc)
	}
}

// The code shown on this computer's screen is only handed to the owner here.
func TestTheOnScreenCodeIsNotHandedToAnyProgramHere(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	r := httptest.NewRequest(http.MethodPost, "/api/this-computer/offer", nil)
	r.RemoteAddr = "127.0.0.1:51000"
	w := httptest.NewRecorder()
	s.handleOfferThisComputer(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a program here without the secret was handed the code: %d", w.Code)
	}
}

// A core started by hand mints a secret, and a given one is used; either is
// written for local tools, readable by this user alone. A secret too short to
// guess-proof is refused rather than used.
func TestTheSecretIsSettledAndWrittenForThisUserAlone(t *testing.T) {
	dir := t.TempDir()
	minted, err := establishLocalOwnerSecret(dir, "")
	if err != nil || len(minted) < minLocalOwnerSecretLen {
		t.Fatalf("minted %q, %v", minted, err)
	}
	again, _ := establishLocalOwnerSecret(t.TempDir(), "")
	if again == minted {
		t.Fatal("two starts minted the same secret")
	}
	path := filepath.Join(dir, LocalOwnerSecretFile)
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) != minted {
		t.Fatalf("written %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	got, err := establishLocalOwnerSecret(dir, testOwnerSecret)
	if err != nil || got != testOwnerSecret {
		t.Fatalf("given secret: %q, %v", got, err)
	}
	if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != testOwnerSecret {
		t.Fatalf("the given secret was not written: %q", b)
	}
	if _, err := establishLocalOwnerSecret(dir, "short"); err == nil {
		t.Fatal("a short secret was accepted")
	}
}
