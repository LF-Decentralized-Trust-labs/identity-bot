package addon_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The AI-agent and sandboxed-app add-ons are not kept in this repository.
// What another party checks or builds against stays: the formats and their
// test vectors, the checkers, the sandboxed-app contract (appmanifest,
// appcall) and this plug-in point. The code that runs them is an add-on, and
// an add-on lives with whoever makes it, outside this repository.
//
// These are the paths that code was kept at. A package or file reappearing at
// one is that code coming back, so this fails rather than letting it be
// rebuilt here by mistake.
var removedRuntime = []string{
	"identity-agent-core/aiagents",
	"identity-agent-core/sandboxedapps",
	"identity-agent-core/sandbox",
	"identity-agent-core/agenthost",
	"identity-agent-core/cmd/agent-host",
	"identity-agent-core/agentmachine",
	"identity-agent-core/lending",
	"identity-agent-core/screenview",
	"identity-agent-core/brainsignin",
	"identity-agent-core/githubapp",
	"identity-agent-core/conversation",
	"scripts/build-agent-host.sh",
	"scripts/build-agent-host.ps1",
}

func TestNoAddOnRuntimeIsKeptHere(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range removedRuntime {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(p))); err == nil {
			t.Errorf("%s is back; an add-on's runtime is kept by whoever makes the add-on, and only its contract is kept here", p)
		}
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "list", "-f", "{{.ImportPath}} {{join .Imports \" \"}} {{join .TestImports \" \"}} {{join .XTestImports \" \"}}", "./...")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for _, path := range fields {
			for _, p := range removedRuntime {
				if path == p || strings.HasPrefix(path, p+"/") {
					t.Errorf("%s names %s, an add-on's runtime that is not kept here", fields[0], path)
				}
			}
		}
	}
}
