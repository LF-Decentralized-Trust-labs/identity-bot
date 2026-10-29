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
		"grok": "grok", "xai": "grok",
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
	// agent-host's own loop is this program, wherever the others are.
	b, err := BrainFor("openrouter", runner)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := programIn(b, dir).(BuiltIn); !ok || v.Path != "" {
		t.Fatalf("an OpenRouter key runs %#v, not agent-host's own loop", programIn(b, dir))
	}
}

// A conversation's session belongs to one brain: when the AI agent's brain
// changes, the conversation starts a new session rather than asking the new
// brain to resume one it never had. A session from before brains were
// recorded is kept.
func TestASessionIsNotResumedByAnotherBrain(t *testing.T) {
	cs := &convState{Session: "claude-session", Started: true, Brain: "claude-code"}
	freshIfBrainChanged(cs, ClaudeCode{})
	if cs.Session != "claude-session" || !cs.Started {
		t.Fatalf("the same brain lost its session: %+v", cs)
	}
	freshIfBrainChanged(cs, Codex{})
	if cs.Session == "claude-session" || cs.Started || cs.Brain != "" {
		t.Fatalf("another brain was handed Claude's session: %+v", cs)
	}
	old := &convState{Session: "s", Started: true}
	freshIfBrainChanged(old, Codex{})
	if old.Session != "s" || !old.Started {
		t.Fatalf("a session from before brains were recorded was dropped: %+v", old)
	}
}
