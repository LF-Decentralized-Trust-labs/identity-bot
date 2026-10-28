package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/agenthost"
)

// brainsOwnUser stands in for running the brain as its own user (AsUser),
// which a test cannot: it runs as this user and says it is isolated.
type brainsOwnUser struct{ agenthost.SameUser }

func (brainsOwnUser) Isolated() bool { return true }

// A body given a directory of brains runs the brain its AI agent was created
// with from that directory, by its full path, with nothing found on PATH.
func TestABodyRunsItsAIAgentsBrainFromTheDirectoryOfBrains(t *testing.T) {
	w := signInWorld(t)
	path, record := fakeClaude(t, false)
	dir := filepath.Dir(path)
	// Nothing on PATH: a brain found anywhere but the directory would fail.
	t.Setenv("PATH", t.TempDir())
	w.openedWith(t)
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{
		BrainDir: dir, Runner: brainsOwnUser{}, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the brain in the directory never ran: %v", err)
	}

	// A directory of brains is only for a brain run as its own user, and runs
	// the AI agent's own brain rather than a named one.
	err := w.hostA.Run(context.Background(), agenthost.RunOptions{BrainDir: dir, Once: true})
	if err == nil || !strings.Contains(err.Error(), "own user") {
		t.Fatalf("a directory of brains with the brain as this user: %v", err)
	}
	err = w.hostA.Run(context.Background(), agenthost.RunOptions{BrainDir: dir, Runner: brainsOwnUser{},
		Brain: agenthost.ClaudeCode{Path: path}, Once: true, Workspace: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "not a named one") {
		t.Fatalf("a directory of brains with a named brain: %v", err)
	}
}
