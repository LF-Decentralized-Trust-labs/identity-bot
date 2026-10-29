package agenthost

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCLI is a stand-in for a brain's program: it records the arguments it was
// started with, what it was given on stdin, and the tool token in its
// environment, and prints what the real one prints.
func fakeCLI(t *testing.T, output string) (path, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "brain")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + record + "; done\n" +
		"printf 'STDIN:%s\\n' \"$(cat | tr '\\n' ' ')\" >> " + record + "\n" +
		"printf 'TOKEN:%s\\n' \"$" + envToolsToken + "\" >> " + record + "\n" +
		"echo '---' >> " + record + "\ncat <<'OUT'\n" + output + "\nOUT\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

func runs(t *testing.T, file string) [][]string {
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, run := range strings.Split(strings.TrimSuffix(string(b), "---\n"), "---\n") {
		out = append(out, strings.Split(strings.TrimSuffix(run, "\n"), "\n"))
	}
	return out
}

func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func line(args []string, prefix string) string {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

const secretWords = "the quarterly numbers are 42"

// Claude Code is started with the full use of its machine and the host's
// MCP server as its only one — so it reaches the Identity Agent only as its AI
// agent — and nothing secret on its command line: the words on stdin, the
// token in its environment.
func TestClaudeCodeIsStartedWithOnlyTheHostsTools(t *testing.T) {
	path, record := fakeCLI(t, `{"type":"result","subtype":"success","is_error":false,"result":"I run macOS.","session_id":"s-1","modelUsage":{"claude-opus-5-5":{}}}`)
	brain := ClaudeCode{Path: path}
	turn := Turn{Session: "s-1", Prompt: "A person asks you: " + secretWords, Instructions: "You are the desk assistant.",
		Workspace: t.TempDir(), ToolsURL: "http://127.0.0.1:1", ToolsToken: "turn-token"}
	out, err := brain.Run(context.Background(), turn)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "I run macOS." || out.Brain.Model != "claude-opus-5-5" || out.Brain.RunHash == "" {
		t.Fatalf("the brain's answer was not read: %+v", out)
	}
	turn.Resume = true
	if _, err := brain.Run(context.Background(), turn); err != nil {
		t.Fatal(err)
	}
	all := runs(t, record)
	first, second := all[0], all[1]
	// The machine is the brain's to use: its own tools stay, and it is never
	// stopped to ask. Its only route to the Identity Agent is the host's.
	if v, _ := flagValue(first, "--permission-mode"); v != "bypassPermissions" {
		t.Fatalf("not started with the full use of its machine: %v", first)
	}
	if contains(first, "--tools") || contains(first, "--allowedTools") {
		t.Fatalf("the brain's own tools were cut down: %v", first)
	}
	if !contains(first, "--strict-mcp-config") {
		t.Fatal("other MCP servers — a person's own connections to the Identity Agent — were not shut out")
	}
	if v, _ := flagValue(first, "--session-id"); v != "s-1" {
		t.Fatal("the first turn did not start the conversation's session")
	}
	if v, _ := flagValue(second, "--resume"); v != "s-1" {
		t.Fatal("the second turn did not resume the conversation's session")
	}
	if !strings.HasPrefix(line(first, "STDIN:"), "You are the desk assistant.") ||
		!strings.Contains(line(first, "STDIN:"), secretWords) || line(first, "TOKEN:") != "turn-token" {
		t.Fatalf("the instructions, the words or the token did not reach the brain: %v", first)
	}
	if strings.Contains(line(second, "STDIN:"), "You are the desk assistant.") {
		t.Fatal("the instructions were repeated on a resumed turn")
	}
	for _, a := range first {
		if strings.Contains(a, secretWords) || strings.Contains(a, "turn-token") || strings.Contains(a, "desk assistant") {
			if !strings.HasPrefix(a, "STDIN:") && !strings.HasPrefix(a, "TOKEN:") {
				t.Fatalf("something private is on the command line: %q", a)
			}
		}
	}
	if contains(first, "--append-system-prompt-file") || contains(first, "--append-system-prompt") {
		t.Fatal("the instructions were given some way other than stdin")
	}
}

// Claude Code is told, on every run, to add no credit line of its own to what
// the brain commits or opens: no Co-Authored-By trailer, no "Generated with"
// line in a pull request, no session link.
func TestClaudeCodeAddsNoAttributionToCommitsOrPullRequests(t *testing.T) {
	path, record := fakeCLI(t, `{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"s-1"}`)
	brain := ClaudeCode{Path: path}
	turn := Turn{Session: "s-1", Prompt: "commit the fix", Workspace: t.TempDir(),
		ToolsURL: "http://127.0.0.1:1", ToolsToken: "turn-token"}
	if _, err := brain.Run(context.Background(), turn); err != nil {
		t.Fatal(err)
	}
	turn.Resume = true
	if _, err := brain.Run(context.Background(), turn); err != nil {
		t.Fatal(err)
	}
	for i, run := range runs(t, record) {
		raw, ok := flagValue(run, "--settings")
		if !ok {
			t.Fatalf("run %d was not given settings, so Claude Code adds its own attribution: %v", i+1, run)
		}
		var settings struct {
			Attribution *struct {
				Commit     *string `json:"commit"`
				PR         *string `json:"pr"`
				SessionURL *bool   `json:"sessionUrl"`
			} `json:"attribution"`
			IncludeCoAuthoredBy *bool `json:"includeCoAuthoredBy"`
		}
		if err := json.Unmarshal([]byte(raw), &settings); err != nil {
			t.Fatalf("run %d: the settings are not JSON Claude Code can read: %v", i+1, err)
		}
		a := settings.Attribution
		if a == nil || a.Commit == nil || *a.Commit != "" || a.PR == nil || *a.PR != "" ||
			a.SessionURL == nil || *a.SessionURL {
			t.Fatalf("run %d: commit, pull-request and session-link attribution are not all off: %s", i+1, raw)
		}
		if settings.IncludeCoAuthoredBy == nil || *settings.IncludeCoAuthoredBy {
			t.Fatalf("run %d: the older setting an earlier Claude Code reads is not off: %s", i+1, raw)
		}
	}
}

// isolatedRunner stands in for a brain running as its own user.
type isolatedRunner struct{}

func (isolatedRunner) Isolated() bool { return true }
func (isolatedRunner) Command(ctx context.Context, dir string, env []string, stdin io.Reader, name string, args ...string) (*exec.Cmd, error) {
	return SameUser{}.Command(ctx, dir, env, stdin, name, args...)
}

// Grok CLI runs only as the brain's own user — it loads the MCP servers of
// whoever runs it, and nothing turns that off — with the full use of its
// machine, and nothing secret on the command line.
func TestGrokRunsOnlyAsItsOwnUserWithOnlyTheHostsTools(t *testing.T) {
	path, record := fakeCLI(t, `{"text":"I run macOS.","stopReason":"end_turn","sessionId":"s-2","modelUsage":{"grok-4.7-build":{}}}`)
	turn := Turn{Session: "s-2", Prompt: secretWords, Instructions: "You are the build server.",
		Workspace: t.TempDir(), ToolsURL: "http://127.0.0.1:1", ToolsToken: "turn-token"}
	if _, err := (GrokCLI{Path: path}).Run(context.Background(), turn); err == nil {
		t.Fatal("Grok ran as the host's own user")
	}
	out, err := GrokCLI{Path: path, Runner: isolatedRunner{}}.Run(context.Background(), turn)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "I run macOS." || out.Brain.Model != "grok-4.7-build" || out.Brain.Session != "s-2" {
		t.Fatalf("the brain's answer was not read: %+v", out)
	}
	all := runs(t, record)
	add, run := all[0], all[1]
	if add[0] != "mcp" || add[1] != "add" || contains(add, "-e") {
		t.Fatalf("the host's tools were not configured, or the token was written into the config: %v", add)
	}
	if !contains(run, "--always-approve") || contains(run, "--tools") {
		t.Fatalf("not started with the full use of its machine: %v", run)
	}
	if line(run, "TOKEN:") != "turn-token" {
		t.Fatal("the token did not reach the brain's environment")
	}
	if v, _ := flagValue(run, "--prompt-file"); v != "/dev/stdin" || !strings.Contains(line(run, "STDIN:"), secretWords) {
		t.Fatalf("the words did not go on stdin: %v", run)
	}
	for _, a := range run {
		if strings.Contains(a, secretWords) && !strings.HasPrefix(a, "STDIN:") {
			t.Fatalf("the words are on the command line: %q", a)
		}
	}
	// A run Grok stopped before it finished is not an answer.
	path2, _ := fakeCLI(t, `{"text":"I'll look that up.","stopReason":"cancelled","sessionId":"s-3"}`)
	if _, err := (GrokCLI{Path: path2, Runner: isolatedRunner{}}).Run(context.Background(), turn); err == nil {
		t.Fatal("a cancelled run was taken as an answer")
	}
}
