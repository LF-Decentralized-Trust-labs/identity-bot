package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/lockgate"
)

// The same kill-and-reopen as scripts/probe-a-killed-core-reopens.sh, in Go so
// it runs on Windows too: a real process, ended with the operating system's own
// kill (SIGKILL; TerminateProcess on Windows), not a clean Stop. The script
// additionally builds the production entry point; this runs the core in the test
// binary. Neither says anything about a hardware key.

const theChildEnv = "IA_TEST_KILLABLE_CORE_DIR"

// TestTheKillableCoreProcess is the child, not a test: it serves a core on a
// loopback port until it is killed.
func TestTheKillableCoreProcess(t *testing.T) {
	dir := os.Getenv(theChildEnv)
	if dir == "" {
		t.Skip("only run as the child of TestAKilledCoreReopensWhenLoggedInAndStaysLockedWhenNot")
	}
	thisPlatformGOOS = "ios" // a phone-role core on any machine; this process is the child only
	cfg := DefaultConfig()
	cfg.DataDir = filepath.Join(dir, "profile-a")
	cfg.LocalOwnerSecret = testOwnerSecret
	cfg.ProfileID = "profile-a"
	cfg.GateMode = lockgate.ModePhone
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.buildRouter())
	if err := os.WriteFile(filepath.Join(dir, "addr.tmp"), []byte(srv.URL), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "addr.tmp"), filepath.Join(dir, "addr")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Minute) // killed long before this
}

func TestAKilledCoreReopensWhenLoggedInAndStaysLockedWhenNot(t *testing.T) {
	if os.Getenv(theChildEnv) != "" {
		t.Skip("the child")
	}
	dir := t.TempDir()
	start := func() (*exec.Cmd, string) {
		os.Remove(filepath.Join(dir, "addr"))
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheKillableCoreProcess$", "-test.timeout=15m")
		cmd.Env = append(os.Environ(), theChildEnv+"="+dir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		for i := 0; i < 150; i++ {
			if b, err := os.ReadFile(filepath.Join(dir, "addr")); err == nil {
				return cmd, string(b)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("the core process did not come up")
		return nil, ""
	}
	call := func(base, method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, base+path, nil)
		if body != "" {
			req, _ = http.NewRequest(method, base+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf [4096]byte
		n, _ := resp.Body.Read(buf[:])
		return resp.StatusCode, buf[:n]
	}
	state := func(base string) string {
		_, b := call(base, http.MethodGet, "/api/lock/state", "")
		var st lockStateReply
		_ = json.Unmarshal(b, &st)
		return st.State
	}
	kill := func(c *exec.Cmd) { _ = c.Process.Kill(); _, _ = c.Process.Wait() }

	c, base := start()
	if got := state(base); got != "open" {
		t.Fatalf("a new identity: %s", got)
	}
	kill(c)
	c, base = start()
	if got := state(base); got != "open" {
		t.Fatalf("killed while logged in it must reopen with nobody present: %s", got)
	}
	if code, _ := call(base, http.MethodPost, "/api/lock/lock", ""); code != 200 {
		t.Fatalf("log out: %d", code)
	}
	kill(c)
	c, base = start()
	if got := state(base); got != "locked" {
		t.Fatalf("killed while logged out it must stay locked: %s", got)
	}
	if code, _ := call(base, http.MethodGet, "/api/identity", ""); code != http.StatusLocked {
		t.Fatalf("a locked core served an ordinary route: %d", code)
	}
	kill(c)
}
