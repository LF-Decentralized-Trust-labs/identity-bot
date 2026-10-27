//go:build !windows

package agenthost

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// A brain run as its own user is started through sudo, which passes on only
// the variables it is told to. Every variable a run is lent — its sign-in, the
// GitHub tokens and the repositories each is for, and the git settings that
// point git at this program — is named to sudo's --preserve-env, which the
// sudoers rule allows (SETENV), and none of them goes on the command line.
func TestABrainRunAsItsOwnUserIsPassedEverythingItWasLent(t *testing.T) {
	g := lent()
	env := append([]string{"ANTHROPIC_API_KEY=sk-test"}, g.Env("/usr/local/bin/agent-host")...)
	cmd, err := AsUser{User: "agent"}.Command(context.Background(), t.TempDir(), env, "/usr/local/bin/claude", "-p")
	if err != nil {
		t.Fatal(err)
	}
	var preserved []string
	for _, a := range cmd.Args {
		if v, ok := strings.CutPrefix(a, "--preserve-env="); ok {
			preserved = strings.Split(v, ",")
		}
		if strings.Contains(a, "ghs_") || strings.Contains(a, "sk-test") {
			t.Fatalf("a secret went on sudo's command line: %q", a)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(preserved, name) {
			t.Errorf("%s is not passed through sudo", name)
		}
	}
	for _, name := range []string{"GH_TOKEN", "AGENT_HOST_GITHUB_WRITE_TOKEN", "AGENT_HOST_GITHUB_WRITE_REPOS",
		"AGENT_HOST_GITHUB_READ_TOKEN", "AGENT_HOST_GITHUB_READ_REPOS", "AGENT_HOST_GITHUB_HOST",
		"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_AUTHOR_NAME", "GIT_TERMINAL_PROMPT"} {
		if !slices.Contains(preserved, name) {
			t.Errorf("%s is not passed through sudo", name)
		}
	}
	// And the values are in sudo's own environment, for it to pass on.
	for _, kv := range env {
		if !slices.Contains(cmd.Env, kv) {
			t.Errorf("%s is not in the environment sudo is started with", strings.SplitN(kv, "=", 2)[0])
		}
	}
}
