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
		"anthropic": "claude-code", "local": "claude-code", "Grok CLI": "grok", "grok": "grok", "xai": "grok",
		"codex": "codex", "openai": "codex", "openrouter": "built-in", "built-in": "built-in", "openai-compatible": "grok"} {
		b, err := BrainFor(name, nil)
		if err != nil || b.Name() != want {
			t.Errorf("%q: %v %v, want %s", name, b, err, want)
		}
	}
	for _, name := range []string{"google", "something"} {
		if _, err := BrainFor(name, nil); err == nil {
			t.Errorf("%q: a brain this host cannot run was accepted", name)
		}
	}
}

// Each sign-in reaches its brain as the variable that brain reads.
func TestABorrowedSignInIsTheVariableItsBrainReads(t *testing.T) {
	// The home is the AI agent's own: these sign-ins name no AI agent.
	H := homeName("x", "")[2:]
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
		// Grok runs in a home of the host's making, so a session from its own
		// sign-in on this machine does not outrank the key.
		{Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.XAI, secret: "xk"}, "grok",
			[]string{"XAI_API_KEY=xk", envBrainHome + `={"var":"GROK_HOME","name":"grok-` + H + `","legacy":"grok"}`}},
		{Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.OpenAI, secret: "ok"}, "codex",
			[]string{"CODEX_API_KEY=ok", envBrainHome + `={"var":"CODEX_HOME","name":"codex-` + H + `","legacy":"codex"}`}},
		{Borrowed{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, secret: "{}"}, "codex",
			[]string{envBrainHome + `={"var":"CODEX_HOME","name":"codex-` + H + `","legacy":"codex","files":{"auth.json":"{}"},"return":"auth.json"}`}},
		{Borrowed{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok, secret: "{}"}, "grok",
			[]string{envBrainHome + `={"var":"GROK_HOME","name":"grok-` + H + `","legacy":"grok","files":{"auth.json":"{}"},"return":"auth.json"}`}},
		{Borrowed{Kind: brainsignin.KindLocal, Provider: brainsignin.OpenAICompatible, Endpoint: "https://vllm.example/v1/"}, "grok",
			[]string{envModelKey + "=" + localModelNoKey, envBrainHome + `={"var":"GROK_HOME","name":"grok-` + H + `","legacy":"grok","model_base_url":"https://vllm.example/v1"}`}},
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
	if _, err := (&Borrowed{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, secret: "x"}).Env("claude-code"); err == nil {
		t.Error("a Codex sign-in was given to Claude Code")
	}
	// agent-host's own loop is never handed a key: it calls through the
	// Identity Agent, or not at all.
	if env, err := (&Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.OpenRouter, secret: "or"}).Env("built-in"); err == nil {
		t.Errorf("an OpenRouter key was lent to agent-host's own loop: %v", env)
	}
}

// Every brain a screen may offer is one a body can run from a borrowed
// sign-in. Before, a Codex sign-in, a Grok subscription and OpenAI and
// OpenRouter keys were kept but could not be lent to any brain.
func TestEveryBrainOfferedCanBeRunFromABorrowedSignIn(t *testing.T) {
	for _, c := range brainsignin.Runnable() {
		b := Borrowed{Kind: c.Kind, Provider: c.Provider, secret: "s", Endpoint: "http://127.0.0.1:1"}
		if c.StaysWithIdentityAgent {
			b = Borrowed{Kind: c.Kind, Provider: c.Provider, throughIdentityAgent: true,
				modelURL: "http://127.0.0.1:2/model", modelToken: "ahm-t"}
		}
		if _, err := b.Env(c.Harness); err != nil {
			t.Errorf("%s/%s on %s: %v", c.Kind, c.Provider, c.Harness, err)
		}
		if _, err := BrainFor(c.Provider, nil); err != nil {
			t.Errorf("%s: %v", c.Provider, err)
		}
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
