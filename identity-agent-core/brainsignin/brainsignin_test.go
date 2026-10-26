package brainsignin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A sign-in capped at one run lends to one run at a time, and a run that
// never returns it frees its place when its lease lapses unrenewed.
func TestACappedSignInFreesAPlaceWhenALeaseLapses(t *testing.T) {
	l := LeasesIn(t.TempDir())
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	first, _, err := l.Lend("agent", "host-1", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Lend("agent", "host-2", 1, now.Add(time.Minute)); !errors.Is(err, ErrInUse) {
		t.Fatalf("a second run was lent a sign-in capped at one: %v", err)
	}
	// Renewed, it holds past its first expiry.
	if _, err := l.Renew(first.ID, "host-1", "agent", now.Add(LeaseTTL-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Lend("agent", "host-2", 1, now.Add(LeaseTTL+time.Second)); !errors.Is(err, ErrInUse) {
		t.Fatalf("a renewed lease was let go: %v", err)
	}
	// Not renewed again: the machine is gone, and its place comes free.
	later := now.Add(2*LeaseTTL + time.Second)
	second, lapsed, err := l.Lend("agent", "host-2", 1, later)
	if err != nil {
		t.Fatalf("the lapsed lease still holds its place: %v", err)
	}
	if len(lapsed) != 1 || lapsed[0].ID != first.ID {
		t.Fatalf("the lapsed lease was not reported: %v", lapsed)
	}
	// Only the body holding a lease returns it.
	if _, err := l.Return(second.ID, "host-1", "agent", later); !errors.Is(err, ErrNoLease) {
		t.Fatalf("another body returned a lease it does not hold: %v", err)
	}
	if _, err := l.Return(second.ID, "host-2", "agent", later); err != nil {
		t.Fatal(err)
	}
	if n := l.InUse("agent", later); n != 0 {
		t.Fatalf("%d in use after the return", n)
	}
}

// No cap means no cap; another AI agent's runs never count against this one.
func TestAnUncappedSignInLendsToEveryRun(t *testing.T) {
	l := LeasesIn(t.TempDir())
	now := time.Now()
	for i := 0; i < 20; i++ {
		if _, _, err := l.Lend("keyed", "h", 0, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := l.Lend("other", "h", 1, now); err != nil {
		t.Fatalf("another AI agent's runs counted against this one: %v", err)
	}
}

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

// A lease record that cannot be read lends nothing, rather than counting no
// runs in use.
func TestAnUnreadableLeaseRecordLendsNothing(t *testing.T) {
	dir := t.TempDir()
	l := LeasesIn(dir)
	if err := os.WriteFile(filepath.Join(dir, "brain_sign_in_leases.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Lend("agent", "h", 1, time.Now()); !errors.Is(err, ErrLeasesUnreadable) {
		t.Fatalf("lent past an unreadable record: %v", err)
	}
}
