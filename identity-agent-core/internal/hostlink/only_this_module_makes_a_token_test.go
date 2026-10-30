package hostlink_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Code in another module cannot reach the server's add-on handle: it cannot
// name hostlink.Token, and no value it can write converts to one. This builds
// a module of its own that depends on this one, as an app built on the core
// would, and checks that every way of conjuring a token fails to compile,
// while the same module calling the core's public API compiles.
func TestAnotherModuleCannotMakeAToken(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module of its own")
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
	build := func(t *testing.T, body string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		mod := "module outsider\n\ngo 1.25.0\n\nrequire identity-agent-core v0.0.0\n\nreplace identity-agent-core => " + core + "\n"
		for _, sub := range []string{"relayproto", "witnessproto"} {
			mod += "replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/" + sub + " => " + filepath.Join(core, sub) + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o644); err != nil {
			t.Fatal(err)
		}
		src := "package main\n\nimport \"identity-agent-core/server\"\n\nfunc main() {\n" + body + "\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(goBin, "build", "-mod=mod", "-o", os.DevNull, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// The control: an outside module that uses the core's public API builds,
	// so a failure below is the token's doing and not the setup's.
	if out, err := build(t, "_ = server.DefaultConfig()"); err != nil {
		t.Fatalf("an outside module could not build against the core at all: %v\n%s", err, out)
	}
	for _, conjured := range []string{"struct{}{}", "struct{ _ byte }{}"} {
		for _, call := range []string{
			"_ = server.AddonHost(nil, " + conjured + ")",
			"_ = server.AddonFixtures(" + conjured + ")",
		} {
			out, err := build(t, call)
			if err == nil {
				t.Errorf("an outside module reached the add-on handle with %s", call)
				continue
			}
			if !strings.Contains(out, "cannot use") {
				t.Errorf("%s failed for another reason than the token: %s", call, out)
			}
		}
	}
}
