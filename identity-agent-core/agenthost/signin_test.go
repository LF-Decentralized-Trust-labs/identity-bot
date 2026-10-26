package agenthost

import (
	"strings"
	"testing"

	"identity-agent-core/brainsignin"
)

// The names a screen shows, and the providers a sign-in is for, start the
// program that runs them.
func TestBrainForTakesDisplayNamesAndProviders(t *testing.T) {
	for name, want := range map[string]string{"Claude Code": "claude-code", "claude-code": "claude-code", "": "claude-code",
		"anthropic": "claude-code", "local": "claude-code", "Grok CLI": "grok", "grok": "grok", "xai": "grok"} {
		b, err := BrainFor(name, nil)
		if err != nil || b.Name() != want {
			t.Errorf("%q: %v %v, want %s", name, b, err, want)
		}
	}
	for _, name := range []string{"codex", "openai", "google", "something"} {
		if _, err := BrainFor(name, nil); err == nil {
			t.Errorf("%q: a brain this host cannot run was accepted", name)
		}
	}
}

// Each sign-in reaches its brain as the variable that brain reads.
func TestABorrowedSignInIsTheVariableItsBrainReads(t *testing.T) {
	for _, c := range []struct {
		b     Borrowed
		brain string
		want  []string
	}{
		{Borrowed{Kind: brainsignin.KindSubscription, Provider: brainsignin.ClaudeCode, secret: "tok"}, "claude-code",
			[]string{"CLAUDE_CODE_OAUTH_TOKEN=tok"}},
		{Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.Anthropic, secret: "key"}, "claude-code",
			[]string{"ANTHROPIC_API_KEY=key"}},
		{Borrowed{Kind: brainsignin.KindLocal, Provider: brainsignin.Local, Endpoint: "http://127.0.0.1:11434/"}, "claude-code",
			[]string{"ANTHROPIC_BASE_URL=http://127.0.0.1:11434", "ANTHROPIC_AUTH_TOKEN=" + localModelNoKey}},
		{Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.XAI, secret: "xk"}, "grok", []string{"XAI_API_KEY=xk"}},
	} {
		got, err := c.b.Env(c.brain)
		if err != nil || strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s/%s: %v %v, want %v", c.b.Kind, c.b.Provider, got, err, c.want)
		}
	}
	// A sign-in its brain cannot use is refused rather than handed over.
	if _, err := (&Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.XAI, secret: "x"}).Env("claude-code"); err == nil {
		t.Error("an xAI key was given to Claude Code")
	}
	if _, err := (&Borrowed{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok, secret: "x"}).Env("grok"); err == nil {
		t.Error("a Grok subscription, which this host cannot yet run from a borrowed sign-in, was handed over")
	}
}

// A borrowed sign-in replaces every sign-in in the machine's own environment;
// without one, the machine's own environment is passed on as it was.
func TestABorrowedSignInIsTheOnlyOneTheBrainSees(t *testing.T) {
	base := []string{"PATH=/bin", "ANTHROPIC_API_KEY=machine", "XAI_API_KEY=machine"}
	got := strings.Join(withCredentials(base, []string{"T=1", "CLAUDE_CODE_OAUTH_TOKEN=lent"}), " ")
	if got != "PATH=/bin T=1 CLAUDE_CODE_OAUTH_TOKEN=lent" {
		t.Fatalf("got %s", got)
	}
	if got := strings.Join(withCredentials(base, []string{"T=1"}), " "); got != strings.Join(append(base, "T=1"), " ") {
		t.Fatalf("with nothing borrowed the machine's own sign-in was withheld: %s", got)
	}
}
