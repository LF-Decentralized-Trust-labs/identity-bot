package main

import (
	"strings"
	"testing"
)

// The brain flags that cannot work together are refused before anything
// starts, each saying why.
func TestBrainFlagsThatCannotWorkAreRefused(t *testing.T) {
	for _, c := range []struct {
		name, path, user, dir, goos string
		refused                     string // "" is accepted
	}{
		{goos: "linux"},
		{name: "codex", path: "/opt/codex", goos: "linux"},
		{name: "claude-code", path: "/home/b/.local/bin/claude", user: "b", goos: "linux"},
		{user: "b", dir: "/home/b/.local/bin", goos: "linux"},
		{user: "b", dir: "/Users/b/.local/bin", goos: "darwin"},
		{dir: "/home/b/.local/bin", goos: "linux", refused: "needs --brain-user"},
		{user: "b", dir: "bin", goos: "linux", refused: "full path"},
		{name: "grok", user: "b", dir: "/home/b/.local/bin", goos: "linux", refused: "does not go with"},
		{path: "/home/b/.local/bin/grok", user: "b", dir: "/home/b/.local/bin", goos: "linux", refused: "does not go with"},
		{name: "claude-code", user: "b", goos: "linux", refused: "needs --brain-path"},
		{user: "b", goos: "linux", refused: "needs --brain-path"},
		{user: "b", dir: `C:\brains`, goos: "windows", refused: "not available yet"},
		{name: "claude-code", path: `C:\claude.exe`, user: "b", goos: "windows", refused: "not available yet"},
		{name: "claude-code", path: `C:\claude.exe`, goos: "windows"},
	} {
		err := checkBrainFlags(c.name, c.path, c.user, c.dir, c.goos)
		switch {
		case c.refused == "" && err != nil:
			t.Errorf("%+v was refused: %v", c, err)
		case c.refused != "" && (err == nil || !strings.Contains(err.Error(), c.refused)):
			t.Errorf("%+v: got %v, want a refusal saying %q", c, err, c.refused)
		}
	}
}
