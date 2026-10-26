package brainsignin_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"identity-agent-core/brainsignin"
	"identity-agent-core/brainsignin/brainsignintest"
)

// The cap counts the account, not the AI agent: two AI agents signed in to
// one subscription share its places. Before, each AI agent's sign-in had a cap
// of its own, so ten AI agents on one plan could hold fifty runs at once.
func TestTwoAIAgentsOnOneAccountShareOneCap(t *testing.T) {
	l := brainsignin.LeasesIn(t.TempDir())
	now := time.Now()
	const pool = "claude-code/secret/abc"
	if _, _, err := l.Lend("agent-a", pool, "fp", "h1", 2, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Lend("agent-b", pool, "fp", "h2", 2, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Lend("agent-c", pool, "fp", "h3", 2, now); !errors.Is(err, brainsignin.ErrInUse) {
		t.Fatalf("a third AI agent on the same account ran past its cap of 2: %v", err)
	}
	if _, _, err := l.Lend("agent-c", "claude-code/secret/other", "fp2", "h3", 2, now); err != nil {
		t.Fatalf("another account's runs counted against this one: %v", err)
	}
	if n := l.InUseByAccount(pool, "agent-a", now); n != 2 {
		t.Fatalf("%d runs of the account in use, want 2", n)
	}
	if n := l.InUse("agent-a", now); n != 1 {
		t.Fatalf("%d runs of agent-a in use, want 1", n)
	}
}

// A brainsignin.Codex or brainsignin.Grok sign-in names its account, so two sign-ins of one account
// pool together even when their tokens differ; a Claude token or a key pools by
// the token itself.
func TestASignInIsPooledByTheAccountItNames(t *testing.T) {
	a := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, Secret: brainsignintest.CodexSignIn("acct-1", "alex@example.org", "r1")}
	b := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, Secret: brainsignintest.CodexSignIn("acct-1", "alex@example.org", "r2")}
	c := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, Secret: brainsignintest.CodexSignIn("acct-2", "sam@example.org", "r3")}
	for _, r := range []*brainsignin.Record{&a, &b, &c} {
		if err := r.Check(); err != nil {
			t.Fatal(err)
		}
		r.Identify()
	}
	if a.Pool() != b.Pool() || a.Pool() == c.Pool() {
		t.Fatalf("pools: %q %q %q", a.Pool(), b.Pool(), c.Pool())
	}
	if a.Account != "alex@example.org" {
		t.Fatalf("the account was not named from the sign-in: %q", a.Account)
	}
	g1 := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok, Secret: brainsignintest.GrokSignIn("u-1", "x@example.org", "k1")}
	g2 := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok, Secret: brainsignintest.GrokSignIn("u-1", "x@example.org", "k2")}
	g1.Identify()
	g2.Identify()
	if g1.Pool() != g2.Pool() || g1.AccountID != "u-1" {
		t.Fatalf("grok pools: %q %q", g1.Pool(), g2.Pool())
	}
	t1 := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.ClaudeCode, Secret: "sk-ant-oat01-ONE"}
	t2 := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.ClaudeCode, Secret: "sk-ant-oat01-ONE"}
	t3 := brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.ClaudeCode, Secret: "sk-ant-oat01-TWO"}
	t1.Identify()
	if t1.Pool() != t2.Pool() || t1.Pool() == t3.Pool() || strings.Contains(t1.Pool(), "ONE") {
		t.Fatalf("claude pools: %q %q %q", t1.Pool(), t2.Pool(), t3.Pool())
	}
	if (brainsignin.Record{Kind: brainsignin.KindLocal, Provider: brainsignin.Local, Endpoint: "http://x"}).Pool() != "" {
		t.Fatal("a keyless model server was pooled")
	}
}

// A pasted token where a sign-in file belongs is refused when it is set.
func TestASignInFileMustBeOne(t *testing.T) {
	for _, r := range []brainsignin.Record{
		{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, Secret: "sk-proj-a-key"},
		{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok, Secret: `{"x":{}}`},
		{Kind: brainsignin.KindSubscription, Provider: brainsignin.Codex, Secret: `{"tokens":{}}`},
	} {
		if r.Check() == nil {
			t.Errorf("accepted %s", r.Secret)
		}
	}
	if (brainsignin.Record{Kind: brainsignin.KindLocal, Provider: brainsignin.OpenAICompatible, Endpoint: "https://vllm.example/v1"}).Check() != nil {
		t.Error("an OpenAI-shaped server was refused")
	}
	if brainsignin.Harness(brainsignin.OpenAICompatible) != brainsignin.HarnessGrok || brainsignin.Harness("openai") != brainsignin.HarnessCodex || brainsignin.Harness("codex") != brainsignin.HarnessCodex {
		t.Error("a provider does not name the program that runs it")
	}
}
