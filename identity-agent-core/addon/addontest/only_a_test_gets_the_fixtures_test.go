package addontest_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"identity-agent-core/addon/addontest"
)

// Inside a test, the fixtures are handed over.
func TestATestGetsTheFixtures(t *testing.T) {
	if addontest.New() == nil {
		t.Fatal("a test was given no fixtures")
	}
}

// In a program they are refused: a program that calls New panics rather than
// being given a way to seal an owner whose key is published.
func TestAProgramIsRefusedTheFixtures(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a program")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	core, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(core, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	// A module of its own, as an app built on the core is.
	dir := t.TempDir()
	mod := "module outsider\n\ngo 1.25.0\n\nrequire identity-agent-core v0.0.0\n\nreplace identity-agent-core => " + core + "\n"
	for _, sub := range []string{"relayproto", "witnessproto"} {
		mod += "replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/" + sub + " => " + filepath.Join(core, sub) + "\n"
	}
	src := "package main\n\nimport \"identity-agent-core/addon/addontest\"\n\nfunc main() { _ = addontest.New() }\n"
	for name, body := range map[string]string{"go.mod": mod, "go.sum": string(sum), "main.go": src} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "probe")
	build := exec.Command(goBin, "build", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the program: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "this is not one") {
		t.Fatalf("a program was given the fixtures: %v\n%s", err, out)
	}
}
