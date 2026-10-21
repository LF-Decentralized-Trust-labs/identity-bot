package agenthost

import (
	"context"
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
		"printf 'STDIN:%s\\n' \"$(cat)\" >> " + record + "\n" +
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

// Claude Code is started with no built-in tools, ignoring its runner's own
// settings, with the host's tools as its only tools and nothing else loaded —
// and nothing secret on its command line: the words on stdin, the token in
// its environment.
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
	if v, _ := flagValue(first, "--permission-mode"); v != "dontAsk" {
		t.Fatalf("not started in dontAsk mode: %v", first)
	}
	// Permission mode alone let a read-only shell command run; the built-in
	// tools are removed outright, and the runner's own settings ignored.
	if v, ok := flagValue(first, "--tools"); !ok || v != "" {
		t.Fatalf("the built-in tools were not removed: %v", first)
	}
	if v, ok := flagValue(first, "--setting-sources"); !ok || v != "" {
		t.Fatalf("the settings of whoever runs it were not ignored: %v", first)
	}
	if !contains(first, "--strict-mcp-config") {
		t.Fatal("other MCP servers were not shut out")
	}
	if v, _ := flagValue(first, "--allowedTools"); v != strings.Join(qualifiedTools(), ",") {
		t.Fatalf("allowed tools: %q", v)
	}
	if v, _ := flagValue(first, "--session-id"); v != "s-1" {
		t.Fatal("the first turn did not start the conversation's session")
	}
	if v, _ := flagValue(second, "--resume"); v != "s-1" {
		t.Fatal("the second turn did not resume the conversation's session")
	}
	if line(first, "STDIN:") != turn.Prompt || line(first, "TOKEN:") != "turn-token" {
		t.Fatalf("the words or the token did not reach the brain: %v", first)
	}
	for _, a := range first {
		if strings.Contains(a, secretWords) || strings.Contains(a, "turn-token") || strings.Contains(a, "desk assistant") {
			if !strings.HasPrefix(a, "STDIN:") && !strings.HasPrefix(a, "TOKEN:") {
				t.Fatalf("something private is on the command line: %q", a)
			}
		}
	}
	if f, ok := flagValue(first, "--append-system-prompt-file"); !ok || f == "" {
		t.Fatal("the instructions were not given from a file")
	} else if _, err := os.Stat(f); err == nil {
		t.Fatal("the instructions file was left behind")
	}
}

// isolatedRunner stands in for a brain running as its own user.
type isolatedRunner struct{}

func (isolatedRunner) Isolated() bool { return true }
func (isolatedRunner) Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	return SameUser{}.Command(ctx, dir, env, name, args...)
}

// Grok CLI runs only as the brain's own user — it loads the MCP servers of
// whoever runs it, and nothing turns that off — with its built-in tools cut
// to one harmless one, subagents refused, and nothing secret on the command
// line.
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
	if v, _ := flagValue(run, "--tools"); v != "todo_write" {
		t.Fatalf("built-in tools were not cut down: %v", run)
	}
	if v, _ := flagValue(run, "--disallowed-tools"); v != "Agent" || !contains(run, "--no-subagents") {
		t.Fatalf("subagents were not refused: %v", run)
	}
	if line(run, "TOKEN:") != "turn-token" {
		t.Fatal("the token did not reach the brain's environment")
	}
	for _, a := range run {
		if strings.Contains(a, secretWords) {
			t.Fatalf("the words are on the command line: %q", a)
		}
	}
	// A run Grok stopped before it finished is not an answer.
	path2, _ := fakeCLI(t, `{"text":"I'll look that up.","stopReason":"cancelled","sessionId":"s-3"}`)
	if _, err := (GrokCLI{Path: path2, Runner: isolatedRunner{}}).Run(context.Background(), turn); err == nil {
		t.Fatal("a cancelled run was taken as an answer")
	}
}
