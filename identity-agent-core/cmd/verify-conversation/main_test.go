package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"identity-agent-core/conversationbundle"
)

const vector = "../../contracts/conversation-bundle/genuine-bundle.json"

// The command says VERIFIED for the published genuine bundle, checked
// against its own organisation, and NOT VERIFIED, exiting 1, for one with a
// word of a message changed.
func TestTheCommandChecksABundleFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the command")
	}
	raw, err := os.ReadFile(vector)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conversationbundle.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b.Entries[0].Body = base64.StdEncoding.EncodeToString([]byte("something else"))
	edited, _ := json.Marshal(b)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	bin := filepath.Join(dir, "verify-conversation")
	if out, err := exec.Command(goBin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building the command: %v\n%s", err, out)
	}
	genuine, _ := conversationbundle.Read(raw)
	out, err := exec.Command(bin, "--root", genuine.Root, vector).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "VERIFIED") || !strings.Contains(string(out), "This result trusts") {
		t.Fatalf("the genuine bundle: %v\n%s", err, out)
	}
	out, err = exec.Command(bin, bad).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.HasPrefix(string(out), "NOT VERIFIED") {
		t.Fatalf("the edited bundle: %v\n%s", err, out)
	}
}
