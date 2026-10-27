package agenthost

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func lent() *LentGitHub {
	return &LentGitHub{LendID: "gl_1", GitHost: "github.com", AuthorName: "Dev worker",
		AuthorEmail: "9+acme-agents[bot]@users.noreply.github.com", tokens: []lentToken{
			{Access: "write", Repositories: []string{"acme/sandbox"}, Token: "ghs_WRITE"},
			{Access: "read", Repositories: []string{"acme/docs", "acme/sandbox"}, Token: "ghs_READ"},
		}}
}

func envOf(list []string) map[string]string {
	m := map[string]string{}
	for _, kv := range list {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// git asks this program for a token per repository: the write token for one
// the AI agent may write, the read token for one it may only read, and
// nothing for any other repository or host.
func TestGitIsGivenTheTokenForEachRepository(t *testing.T) {
	env := envOf(lent().Env("/usr/local/bin/agent-host"))
	ask := func(q string) string {
		var out bytes.Buffer
		ServeGitHubCredential([]string{"get"}, strings.NewReader(q), &out, func(k string) string { return env[k] })
		return out.String()
	}
	for q, want := range map[string]string{
		"protocol=https\nhost=github.com\npath=acme/sandbox.git\n\n": "password=ghs_WRITE",
		"protocol=https\nhost=github.com\npath=Acme/Sandbox\n\n":     "password=ghs_WRITE",
		"protocol=https\nhost=github.com\npath=acme/docs.git\n\n":    "password=ghs_READ",
		"protocol=https\nhost=github.com\npath=acme/secret.git\n\n":  "",
		"protocol=https\nhost=github.com\n\n":                        "",
		"protocol=https\nhost=evil.example\npath=acme/sandbox\n\n":   "",
		"protocol=http\nhost=github.com\npath=acme/sandbox\n\n":      "",
	} {
		got := ask(q)
		if want == "" && got != "" || want != "" && !strings.Contains(got, want+"\n") {
			t.Errorf("asked %q, answered %q", q, got)
		}
	}
	var out bytes.Buffer
	ServeGitHubCredential([]string{"store"}, strings.NewReader("password=x\n\n"), &out, func(k string) string { return env[k] })
	if out.Len() != 0 {
		t.Fatal("store answered")
	}
}

// The helper git runs names this program and no token; gh is given the token
// that reads every repository — or, when every repository may be written, the
// write token; every helper configured before is set aside; commits name the
// AI agent.
func TestTheBrainsEnvironmentCarriesGitHubAccessAndNothingElseDoes(t *testing.T) {
	list := lent().Env(filepath.FromSlash("/opt/it's/agent-host"))
	env := envOf(list)
	if env["GH_TOKEN"] != "ghs_READ" {
		t.Fatalf("gh is given %q", env["GH_TOKEN"])
	}
	// The read token is lent beside the write one even when every repository
	// may be written; gh is still given the write token then.
	writesAll := lent()
	writesAll.tokens[1].Repositories = []string{"acme/sandbox"}
	if gh := envOf(writesAll.Env("/x"))["GH_TOKEN"]; gh != "ghs_WRITE" {
		t.Fatalf("gh, for an AI agent that may write everything it uses, is given %q", gh)
	}
	writeOnly := lent()
	writeOnly.tokens = writeOnly.tokens[:1]
	if gh := envOf(writeOnly.Env("/x"))["GH_TOKEN"]; gh != "ghs_WRITE" {
		t.Fatalf("gh, given only a write token, is given %q", gh)
	}
	if env["GIT_CONFIG_KEY_0"] != "credential.helper" || env["GIT_CONFIG_VALUE_0"] != "" {
		t.Fatal("the helpers configured before are not set aside")
	}
	if h := env["GIT_CONFIG_VALUE_1"]; h != `!'/opt/it'\''s/agent-host' github-credential` {
		t.Fatalf("helper %q", h)
	}
	for k, v := range env {
		if strings.HasPrefix(k, "GIT_CONFIG_") && strings.Contains(v, "ghs_") {
			t.Fatalf("%s carries a token", k)
		}
	}
	if env["GIT_AUTHOR_NAME"] != "Dev worker" || env["GIT_COMMITTER_EMAIL"] != "9+acme-agents[bot]@users.noreply.github.com" {
		t.Fatalf("commits do not name the AI agent: %v", env)
	}
	// What the machine had set up for GitHub is withheld from the brain.
	base := []string{"PATH=/bin", "GH_TOKEN=a-machine-token", "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper", "GIT_CONFIG_VALUE_0=osxkeychain", "GIT_ASKPASS=/x"}
	got := withCredentials(base, list)
	for _, kv := range got {
		if kv == "GH_TOKEN=a-machine-token" || kv == "GIT_CONFIG_VALUE_0=osxkeychain" || kv == "GIT_ASKPASS=/x" {
			t.Fatalf("the machine's own %s reached the brain", kv)
		}
	}
	if got[0] != "PATH=/bin" {
		t.Fatal("the rest of the machine's environment was not passed on")
	}
	// Without GitHub access, the machine's own is left as it was.
	if got := withCredentials(base, []string{"ANTHROPIC_API_KEY=k"}); !strings.Contains(strings.Join(got, "\n"), "GH_TOKEN=a-machine-token") {
		t.Fatal("a run lent no GitHub access lost the machine's own")
	}
}

// An SSH address on GitHub is used over HTTPS, with what was lent, for
// fetching and for pushing: a key in ~/.ssh is not used for GitHub instead.
func TestAnSSHAddressOnGitHubUsesWhatWasLent(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	env := append(withCredentials(os.Environ(), lent().Env("/usr/local/bin/agent-host")), "HOME="+dir)
	run := func(args ...string) string {
		cmd := exec.Command(git, args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	for remote, url := range map[string]string{"a": "git@github.com:acme/sandbox.git", "b": "ssh://git@github.com/acme/docs.git",
		"c": "git@gitlab.example:acme/other.git"} {
		run("remote", "add", remote, url)
	}
	for _, c := range []struct{ remote, push, want string }{
		{"a", "", "https://github.com/acme/sandbox.git"}, {"a", "--push", "https://github.com/acme/sandbox.git"},
		{"b", "", "https://github.com/acme/docs.git"}, {"b", "--push", "https://github.com/acme/docs.git"},
		{"c", "", "git@gitlab.example:acme/other.git"},
	} {
		args := []string{"remote", "get-url"}
		if c.push != "" {
			args = append(args, c.push)
		}
		if got := run(append(args, c.remote)...); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.remote, c.push, got, c.want)
		}
	}
}
