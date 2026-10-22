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

// The core proves it holds the secret, bound to the port it is listening on,
// without sending the secret; a program on another port relaying the question
// to the real core hands back a proof for the wrong port.
func TestTheCoreProvesItHoldsTheSecretOnItsOwnPort(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, Port: 8643}
	router := s.buildRouter("")
	nonce := "a-fresh-nonce-0123456789"
	r := httptest.NewRequest(http.MethodGet, "/api/local-owner/proof?nonce="+nonce, nil)
	r.RemoteAddr = "203.0.113.9:51000" // answered to anyone: no secret needed to ask
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, testOwnerSecret) {
		t.Fatal("the proof carried the secret")
	}
	if !strings.Contains(body, LocalOwnerProof(testOwnerSecret, nonce, 8643)) {
		t.Fatalf("not the proof for this core's port: %s", body)
	}
	if LocalOwnerProof(testOwnerSecret, nonce, 8642) == LocalOwnerProof(testOwnerSecret, nonce, 8643) {
		t.Fatal("a proof made on one port passes for another")
	}
	if LocalOwnerProof("another-secret-0123456789abcdefghij", nonce, 8643) == LocalOwnerProof(testOwnerSecret, nonce, 8643) {
		t.Fatal("a proof does not depend on the secret")
	}
	short := httptest.NewRequest(http.MethodGet, "/api/local-owner/proof?nonce=x", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, short)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a short nonce was answered: %d", w.Code)
	}
}

// The secret handed over in the environment is read once and removed, so no
// process started afterwards inherits it.
func TestTheSecretIsTakenOutOfTheEnvironment(t *testing.T) {
	t.Setenv(LocalOwnerSecretEnv, testOwnerSecret)
	cfg := DefaultConfig()
	if cfg.LocalOwnerSecret != testOwnerSecret {
		t.Fatalf("not read: %q", cfg.LocalOwnerSecret)
	}
	if v, ok := os.LookupEnv(LocalOwnerSecretEnv); ok {
		t.Fatalf("still in the environment: %q", v)
	}
}

// On Windows, a data directory outside the user's profile is called out,
// because the folder, not the file's mode, decides who may read the secret.
func TestAWindowsDataDirectoryOutsideTheProfileIsCalledOut(t *testing.T) {
	env := func(home string) func(string) string {
		return func(k string) string {
			if k == "USERPROFILE" {
				return home
			}
			return ""
		}
	}
	home := t.TempDir()
	if msg := windowsSecretExposure("windows", filepath.Join(home, "AppData", "agent"), env(home)); msg != "" {
		t.Fatalf("a directory in the profile was called out: %s", msg)
	}
	if msg := windowsSecretExposure("windows", t.TempDir(), env(home)); msg == "" {
		t.Fatal("a directory outside the profile was not called out")
	}
	if msg := windowsSecretExposure("darwin", "/shared", env(home)); msg != "" {
		t.Fatal("only Windows relies on the folder for this")
	}
}

// The proof is computed the same way by every client; this vector is also
// asserted by agent_client (the_owner_at_this_computer_test.dart).
func TestTheLocalOwnerProofMatchesTheSharedVector(t *testing.T) {
	got := LocalOwnerProof("a-local-owner-secret-for-these-tests-0123456789", "nonce-0123456789abcdef", 8642)
	if got != "v4KtBBsqnFrVNMHOCMoDC4LK5nUKJW5J-k_5dHCW0U0" {
		t.Fatalf("proof %s", got)
	}
}
