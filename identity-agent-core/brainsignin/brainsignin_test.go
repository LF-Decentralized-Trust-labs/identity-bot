package brainsignin

import (
	"testing"
)

func TestNamesAreNormalised(t *testing.T) {
	for in, want := range map[string]string{"Claude Code": ClaudeCode, "Grok CLI": Grok, "xAI": XAI,
		"OpenRouter": OpenRouter, "Anthropic": Anthropic, "Codex": Codex, "claude-code": ClaudeCode} {
		if got := NormaliseProvider(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if NormaliseKind("cli", "Claude Code") != KindSubscription || NormaliseKind("remote", "xai") != KindAPIKey ||
		NormaliseKind("", "codex") != KindSubscription || NormaliseKind("local", "") != KindLocal {
		t.Error("kinds are not normalised")
	}
	if DefaultMaxConcurrentRuns(KindSubscription, ClaudeCode) != 5 || DefaultMaxConcurrentRuns(KindSubscription, Codex) != 1 ||
		DefaultMaxConcurrentRuns(KindAPIKey, Anthropic) != 0 || DefaultMaxConcurrentRuns(KindLocal, Local) != 0 {
		t.Error("the default caps are not 5 for a subscription, 1 for Codex and none for a key or a local model")
	}
	if Harness("Claude Code") != HarnessClaudeCode || Harness("anthropic") != HarnessClaudeCode ||
		Harness("local") != HarnessClaudeCode || Harness("xai") != HarnessGrok || Harness("Grok CLI") != HarnessGrok {
		t.Error("a provider does not name the program that runs it")
	}
}

func TestARecordThatCannotBeUsedIsRefused(t *testing.T) {
	for _, r := range []Record{
		{Kind: KindAPIKey, Provider: Anthropic},
		{Kind: KindSubscription, Provider: Anthropic, Secret: "x"},
		{Kind: KindLocal, Provider: Local},
		{Kind: KindAPIKey, Provider: XAI, Secret: "x", MaxConcurrentRuns: -1},
	} {
		if r.Check() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if (Record{Kind: KindLocal, Provider: Local, Endpoint: "http://127.0.0.1:11434"}).Check() != nil {
		t.Error("a local model with no key was refused")
	}
}
