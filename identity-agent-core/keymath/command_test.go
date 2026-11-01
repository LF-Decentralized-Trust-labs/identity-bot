package keymath

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The command answers on standard output and refuses on standard error
// without repeating what it was sent.
func TestTheCommandAnswersAndRefusesWithoutRepeatingItsInput(t *testing.T) {
	seed := hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
	var out, errOut bytes.Buffer
	if code := Command([]string{"pq_next"}, strings.NewReader(`{"seed_hex":"`+seed+`"}`), &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "2AAE") {
		t.Fatalf("pq_next: %d %q %q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	bad := seed[:60] + "zzzz"
	if code := Command([]string{"pq_next"}, strings.NewReader(`{"seed_hex":"`+bad+`"}`), &out, &errOut); code == 0 ||
		strings.Contains(errOut.String(), bad[:16]) || out.Len() != 0 {
		t.Fatalf("a malformed seed: %d %q %q", code, out.String(), errOut.String())
	}
	if code := Command([]string{"pq_next", seed}, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatal("a seed on the command line was accepted")
	}
}

// Run as the core binary's command, keymath writes no file anywhere it could
// (its working directory, the home directory), and ends.
func TestTheCoreBinaryRunsKeymathAndWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the core binary")
	}
	work := t.TempDir()
	bin := filepath.Join(t.TempDir(), "core")
	build := exec.Command("go", "build", "-o", bin, "..")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("the core binary could not be built here: %v %s", err, out)
	}
	seed := hex.EncodeToString(bytes.Repeat([]byte{3}, 32))
	cmd := exec.Command(bin, "keymath", "messaging_keyset")
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "HOME="+work, "IDENTITY_AGENT_DATA_DIR="+filepath.Join(work, "data"))
	cmd.Stdin = strings.NewReader(`{"seed_hex":"` + seed + `"}`)
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), "IA-HYBRID-1") {
		t.Fatalf("the core's keymath command: %v %s", err, out)
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatalf("the keymath command wrote %d entries where it ran", len(entries))
	}
}
