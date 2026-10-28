package agenthost

import (
	"path/filepath"
	"testing"
)

// A machine with every brain installed in one directory runs the one its AI
// agent was created with, by that program's full path there: what a brain
// run as its own user needs, since sudo looks nothing up on a PATH.
func TestTheAIAgentsBrainIsFoundInTheBrainDirectory(t *testing.T) {
	dir := "/home/agentbrain/.local/bin"
	runner := AsUser{User: "agentbrain"}
	for provider, want := range map[string]string{
		"claude-code": "claude", "anthropic": "claude",
		"codex": "codex", "openai": "codex",
		"grok": "grok", "xai": "grok", "openrouter": "grok",
	} {
		b, err := BrainFor(provider, runner)
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		var got string
		switch v := programIn(b, dir).(type) {
		case ClaudeCode:
			got = v.path()
		case Codex:
			got = v.path()
		case GrokCLI:
			got = v.path()
		}
		if got != filepath.Join(dir, want) {
			t.Fatalf("%s runs %q, want %q", provider, got, filepath.Join(dir, want))
		}
	}
}
