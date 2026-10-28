//go:build !windows

package agenthost

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// sudo writes its command line, and the value of every variable it is told to
// pass on, to the system log. So a brain run as its own user is started with
// nothing it was lent — its sign-in, the GitHub tokens and the repositories
// each is for, the git settings that point git at this program, the tool
// token — on sudo's command line or in sudo's environment, and sudo is told to
// pass nothing on. All of it goes on stdin, ahead of the brain's input, to
// `agent-host brain-env`.
func TestNothingARunIsLentCrossesSudo(t *testing.T) {
	g := lent()
	env := append([]string{"ANTHROPIC_API_KEY=sk-test", envToolsToken + "=turn-token",
		envBrainHome + `={"var":"GROK_HOME","files":{"auth.json":"{\"key\":\"xai-SIGNIN\"}"}}`},
		g.Env("/usr/local/bin/agent-host")...)
	cmd, err := AsUser{User: "agent"}.Command(context.Background(), t.TempDir(), env,
		strings.NewReader(secretWords), "/usr/local/bin/claude", "-p")
	if err != nil {
		t.Fatal(err)
	}
	self, _ := executable()
	want := []string{"sudo", "-n", "-u", "agent", "-H", "--", self, "brain-env", "--", "/usr/local/bin/claude", "-p"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatalf("sudo was started as %q, not %q", cmd.Args, want)
	}
	for _, kv := range env {
		_, v, _ := strings.Cut(kv, "=")
		if len(v) < 6 {
			continue
		}
		for _, a := range cmd.Args {
			if strings.Contains(a, v) {
				t.Fatalf("a lent value went on sudo's command line: %q", a)
			}
		}
		for _, e := range cmd.Env {
			if strings.Contains(e, v) {
				t.Fatalf("a lent value is in the environment sudo is started with: %s", strings.SplitN(e, "=", 2)[0])
			}
		}
	}
	// What it was lent is on stdin, every variable of it, and then the words.
	in := bufio.NewReader(cmd.Stdin)
	first, err := in.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var h brainEnvHeader
	if err := json.Unmarshal([]byte(first), &h); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.Env, env) {
		t.Fatalf("the run's variables did not all go on stdin: %q", h.Env)
	}
	if rest, _ := io.ReadAll(in); string(rest) != secretWords {
		t.Fatalf("the brain's input did not follow its variables: %q", rest)
	}
}

// fakeSudo puts a stand-in for sudo first on PATH. It writes down what it was
// started with and the environment it was given, then runs the command as the
// real one would: after the options, with its environment reset. Where the
// system allows it, it also makes its own stdin unopenable by name, as a pipe
// made by another user is for the brain's user — so a brain that reopens
// /dev/stdin, as Grok does, fails unless it was handed a pipe of its own.
func fakeSudo(t *testing.T) (record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(dir, "sudo-record")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\" >> " + record + "; done\n" +
		"env | sed 's/^/ENV:/' >> " + record + "\n" +
		"while [ \"$1\" != -- ]; do shift; done; shift\n" +
		"chmod 000 /proc/self/fd/0 2>/dev/null\n" +
		"exec env -i HOME=\"$HOME\" PATH=/usr/bin:/bin \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return record
}

// fakeGrok stands in for Grok: it reads its prompt by opening the file it is
// named with --prompt-file, as Grok does, and writes down the prompt, the tool
// token and the sign-in it found.
func fakeGrok(t *testing.T) (path, record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "grok")
	script := "#!/bin/sh\n[ \"$1\" = mcp ] && exit 0\nprev=\nfor a in \"$@\"; do [ \"$prev\" = --prompt-file ] && pf=$a; prev=$a; done\n" +
		"p=$(cat \"$pf\") || { echo \"Failed to read '$pf'\" >&2; exit 1; }\n" +
		"printf 'PROMPT:%s\\n' \"$p\" >> " + record + "\n" +
		"printf 'TOKEN:%s\\n' \"$" + envToolsToken + "\" >> " + record + "\n" +
		"printf 'FILE:%s\\n' \"$(cat \"$GROK_HOME/auth.json\" 2>/dev/null)\" >> " + record + "\n" +
		"echo '{\"text\":\"done\",\"stopReason\":\"end_turn\",\"sessionId\":\"s-9\"}'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

// Grok run as its own user, with a sign-in it was lent, reads its prompt from
// /dev/stdin and finds its sign-in and tool token — while sudo is given none
// of them. Before, Grok could not open its prompt (its stdin was the host's
// pipe), and sudo wrote the sign-in into the system log.
func TestGrokRunAsItsOwnUserReadsItsPromptAndSudoSeesNoSecret(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open any pipe, so the stand-in for sudo cannot show a brain failing to")
	}
	sudoRecord := fakeSudo(t)
	t.Setenv("HOME", t.TempDir())
	path, record := fakeGrok(t)
	const signIn = `{"key":"xai-SIGNIN-VALUE"}`
	b := Borrowed{Kind: "subscription", Provider: "grok", secret: signIn}
	creds, err := b.Env("grok")
	if err != nil {
		t.Fatal(err)
	}
	turn := Turn{Session: "s-9", Prompt: secretWords, Workspace: t.TempDir(),
		ToolsURL: "http://127.0.0.1:1", ToolsToken: "turn-token-value", Credentials: creds}
	out, err := GrokCLI{Path: path, Runner: AsUser{User: "agentbrain"}}.Run(context.Background(), turn)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "done" {
		t.Fatalf("Grok's answer was not read: %+v", out)
	}
	got, _ := os.ReadFile(record)
	rec := string(got)
	for _, want := range []string{"PROMPT:" + secretWords + "\n", "TOKEN:turn-token-value\n", "FILE:" + signIn + "\n"} {
		if !strings.Contains(rec, want) {
			t.Fatalf("Grok did not get %q:\n%s", strings.SplitN(want, ":", 2)[0], rec)
		}
	}
	sudo, _ := os.ReadFile(sudoRecord)
	for _, secret := range []string{"xai-SIGNIN-VALUE", "turn-token-value", secretWords} {
		if strings.Contains(string(sudo), secret) {
			t.Fatalf("sudo was given %q, which it would write to the system log", secret)
		}
	}
	if strings.Contains(string(sudo), "--preserve-env") {
		t.Fatal("sudo was told to pass variables on")
	}
	if runtime.GOOS != "linux" {
		t.Log("only Linux lets the stand-in for sudo make its stdin unopenable; elsewhere this checks the rest")
	}
}

// `agent-host brain-env` refuses to run without the run's variables, a
// program named by its full path, or with a variable that has no name.
func TestBrainEnvRefusesWhatItWasNotMeantToBeGiven(t *testing.T) {
	for _, c := range []struct {
		args  []string
		stdin string
	}{
		{[]string{"/bin/true"}, "{\"env\":[]}\n"},
		{[]string{"--", "true"}, "{\"env\":[]}\n"},
		{[]string{"--", "/bin/true"}, "no line of variables"},
		{[]string{"--", "/bin/true"}, "{\"env\":[\"=x\"]}\n"},
	} {
		if code := ServeBrainEnv(c.args, strings.NewReader(c.stdin), io.Discard, io.Discard); code != 2 {
			t.Errorf("%q with %q: exit %d, not refused", c.args, c.stdin, code)
		}
	}
	if code := ServeBrainEnv([]string{"--", "/bin/sh", "-c", "exit 4"}, strings.NewReader("{\"env\":[]}\n"),
		io.Discard, io.Discard); code != 4 {
		t.Errorf("the program's exit status was not passed on: %d", code)
	}
}
