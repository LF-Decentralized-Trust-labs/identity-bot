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
		r.MaxConcurrentRuns = 1
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

// A Grok sign-in that holds tokens for more than one account is refused, so
// which account runs never depends on the order the file was read in.
func TestAGrokSignInHoldingTwoAccountsIsRefused(t *testing.T) {
	one := brainsignintest.GrokSignIn("u-1", "x@example.org", "k1")
	two := `{"https://auth.x.ai::client":{"key":"k1","user_id":"u-1","email":"x@example.org"},` +
		`"https://auth.x.ai::other":{"key":"k2","user_id":"u-2","email":"y@example.org"},"version":2}`
	if f, err := brainsignin.ReadSignInFile(brainsignin.Grok, one); err != nil || f.AccountID != "u-1" {
		t.Fatalf("one account: %+v %v", f, err)
	}
	for i := 0; i < 20; i++ {
		if _, err := brainsignin.ReadSignInFile(brainsignin.Grok, two); err == nil || !strings.Contains(err.Error(), "more than one account") {
			t.Fatalf("two accounts: %v", err)
		}
	}
}

// A refreshed sign-in file is taken only for the account and the person it was
// lent for.
func TestARefreshedSignInMustBeForTheSamePersonAndAccount(t *testing.T) {
	lent := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "R1")
	if err := brainsignin.SameSignInAs(brainsignin.Codex, lent, brainsignintest.CodexSignIn("acct-1", "alex@example.org", "R2")); err != nil {
		t.Fatalf("a refresh of the same sign-in: %v", err)
	}
	if err := brainsignin.SameSignInAs(brainsignin.Codex, lent, brainsignintest.CodexSignIn("acct-2", "alex@example.org", "R2")); err == nil {
		t.Fatal("a refresh for another account was taken")
	}
	if err := brainsignin.SameSignInAs(brainsignin.Codex, lent, brainsignintest.CodexSignIn("acct-1", "eve@example.org", "R2")); err == nil {
		t.Fatal("a refresh for another person on the account was taken")
	}
	noAccount := `{"tokens":{"access_token":"a","refresh_token":"r"}}`
	if err := brainsignin.SameSignInAs(brainsignin.Codex, noAccount, noAccount+" "); err == nil {
		t.Fatal("a refresh of a sign-in that names no account was taken")
	}
}

// A subscription's runs are always capped; a key's may be uncapped.
func TestASubscriptionIsAlwaysCapped(t *testing.T) {
	if (brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.ClaudeCode, Secret: "t"}).Check() == nil {
		t.Fatal("a subscription with no cap was accepted")
	}
	if (brainsignin.Record{Kind: brainsignin.KindAPIKey, Provider: brainsignin.Anthropic, Secret: "k"}).Check() != nil {
		t.Fatal("a key with no cap was refused")
	}
	for _, p := range []string{brainsignin.Codex, brainsignin.Grok} {
		if n := brainsignin.DefaultMaxConcurrentRuns(brainsignin.KindSubscription, p); n != 1 {
			t.Errorf("%s: a sign-in that renews itself runs %d at a time by default, want 1", p, n)
		}
	}
}

// A lapsed lease holds no place, but can still be given back, so what its run
// sends back with it is not lost. Before, a lease that lapsed was forgotten at
// once, and a body that had been out of reach could not return it.
func TestALapsedLeaseCanStillBeGivenBack(t *testing.T) {
	l := brainsignin.LeasesIn(t.TempDir())
	now := time.Now()
	lease, _, err := l.Lend("agent-a", "pool", "fp", "h1", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(brainsignin.LeaseTTL + time.Minute)
	if lapsed, err := l.Lapsed(later); err != nil || len(lapsed) != 1 {
		t.Fatalf("lapsed: %v %v", lapsed, err)
	}
	if lapsed, _ := l.Lapsed(later); len(lapsed) != 0 {
		t.Fatal("a lapse was reported twice")
	}
	if _, _, err := l.Lend("agent-b", "pool", "fp", "h2", 1, later); err != nil {
		t.Fatalf("a lapsed lease still held its place: %v", err)
	}
	if _, err := l.Renew(lease.ID, "h1", "agent-a", later); !errors.Is(err, brainsignin.ErrNoLease) {
		t.Fatalf("a lapsed lease was renewed: %v", err)
	}
	got, err := l.Return(lease.ID, "h1", "agent-a", later)
	if got.ID != lease.ID || got.Lent != "fp" || !errors.Is(err, brainsignin.ErrNoLease) {
		t.Fatalf("returning a lapsed lease: %+v %v", got, err)
	}
	if got, _ := l.Return(lease.ID, "h1", "agent-a", later); got.ID != "" {
		t.Fatal("a lease was returned twice")
	}
	old, _, _ := l.Lend("agent-c", "pool-c", "fp", "h3", 0, now)
	_, _ = l.Lapsed(later)
	if got, _ := l.Return(old.ID, "h3", "agent-c", later.Add(brainsignin.LapsedKept)); got.ID != "" {
		t.Fatal("a lease that lapsed long ago was still remembered")
	}
}

// An account's cap is one number, whichever of its AI agents set it.
func TestAnAccountHasOneCap(t *testing.T) {
	l := brainsignin.LeasesIn(t.TempDir())
	if _, ok := l.Cap("codex/account/a", "agent-a"); ok {
		t.Fatal("a cap before any was set")
	}
	if err := l.SetCap("codex/account/a", "agent-a", 2); err != nil {
		t.Fatal(err)
	}
	if n, ok := l.Cap("codex/account/a", "agent-b"); !ok || n != 2 {
		t.Fatalf("another AI agent on the account sees cap %d %v", n, ok)
	}
	if _, ok := l.Cap("", "agent-b"); ok {
		t.Fatal("a sign-in that names no account took another's cap")
	}
}
