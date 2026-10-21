package agenthost

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCLI is a stand-in for a brain's program: it records the arguments it was
// started with and prints what the real one prints.
func fakeCLI(t *testing.T, output string) (path, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "brain")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argsFile + "; done\necho '---' >> " + argsFile +
		"\ncat <<'OUT'\n" + output + "\nOUT\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func argRuns(t *testing.T, file string) [][]string {
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var runs [][]string
	for _, run := range strings.Split(strings.TrimSuffix(string(b), "---\n"), "---\n") {
		runs = append(runs, strings.Split(strings.TrimSpace(run), "\n"))
	}
	return runs
}

func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// Claude Code is started with the host's tools as its only tools, refusing
// everything else without asking, with no MCP server but the host's, in the
// conversation's session — new on the first turn, resumed after.
func TestClaudeCodeIsStartedWithOnlyTheHostsTools(t *testing.T) {
	path, argsFile := fakeCLI(t, `{"type":"result","subtype":"success","is_error":false,"result":"I run macOS.","session_id":"s-1","modelUsage":{"claude-opus-5-5":{}}}`)
	brain := ClaudeCode{Path: path}
	turn := Turn{Session: "s-1", Prompt: "Rob asks you: what do you run?", Instructions: "You are Mac Mini.",
		Workspace: t.TempDir(), ToolsURL: "http://127.0.0.1:1", ToolsToken: "tok"}
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
	runs := argRuns(t, argsFile)
	first, second := runs[0], runs[1]
	if v, _ := flagValue(first, "--permission-mode"); v != "dontAsk" {
		t.Fatalf("not started in dontAsk mode: %v", first)
	}
	if v, _ := flagValue(first, "--allowedTools"); v != strings.Join(qualifiedTools(), ",") {
		t.Fatalf("allowed tools: %q", v)
	}
	if _, ok := flagValue(first, "--strict-mcp-config"); !ok && !contains(first, "--strict-mcp-config") {
		t.Fatal("other MCP servers were not shut out")
	}
	if cfg, _ := flagValue(first, "--mcp-config"); !strings.Contains(cfg, `"AGENT_HOST_TOOLS_TOKEN":"tok"`) {
		t.Fatalf("the host's tools were not given with the turn's token: %s", cfg)
	}
	if v, _ := flagValue(first, "--session-id"); v != "s-1" {
		t.Fatal("the first turn did not start the conversation's session")
	}
	if v, _ := flagValue(second, "--resume"); v != "s-1" {
		t.Fatal("the second turn did not resume the conversation's session")
	}
}

// Grok CLI is given the same: the host's tools only, built-in tools removed,
// dontAsk, and the instructions on the first turn.
func TestGrokIsStartedWithOnlyTheHostsTools(t *testing.T) {
	path, argsFile := fakeCLI(t, `{"result":"I run macOS.","session_id":"s-2","model":"grok-4"}`)
	out, err := GrokCLI{Path: path}.Run(context.Background(), Turn{Session: "s-2", Prompt: "what do you run?",
		Instructions: "You are MacBook Pro.", Workspace: t.TempDir(), ToolsURL: "http://127.0.0.1:1", ToolsToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "I run macOS." || out.Brain.Model != "grok-4" {
		t.Fatalf("the brain's answer was not read: %+v", out)
	}
	runs := argRuns(t, argsFile)
	add, turn := runs[0], runs[1]
	if add[0] != "mcp" || add[1] != "add" || !contains(add, envToolsToken+"=tok") {
		t.Fatalf("the host's tools were not configured for the turn: %v", add)
	}
	if v, _ := flagValue(turn, "--permission-mode"); v != "dontAsk" {
		t.Fatalf("not started in dontAsk mode: %v", turn)
	}
	if v, ok := flagValue(turn, "--tools"); !ok || v != "" && !strings.HasPrefix(v, "--") {
		t.Fatalf("built-in tools were not removed: %v", turn)
	}
	if p, _ := flagValue(turn, "-p"); !strings.HasPrefix(p, "You are MacBook Pro.") {
		t.Fatal("the instructions did not lead the first turn")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
