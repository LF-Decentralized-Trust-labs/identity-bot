package server

import (
	"testing"
	"time"

	"identity-agent-core/brainsignin"
	"identity-agent-core/brainsignin/brainsignintest"
)

// Signing in again with a new secret names the account of that secret, never
// the one signed in before: the old name and expiry stay only while the
// secret does.
func TestANewSignInKeepsNoOldAccountName(t *testing.T) {
	prev := &brainsignin.Record{Kind: brainsignin.KindAPIKey, Provider: brainsignin.OpenRouter,
		Account: "the old account", Secret: "sk-or-OLD", MaxConcurrentRuns: 0}
	now := time.Now()
	later := now.Add(time.Hour)
	prev.ExpiresAt = &later
	ask := func(q brainSignInRequest) brainsignin.Record {
		t.Helper()
		q.Kind, q.Provider = brainsignin.KindAPIKey, brainsignin.OpenRouter
		rec, err := q.record(prev, now)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	fresh := ask(brainSignInRequest{Secret: "sk-or-NEW"})
	if fresh.Account != "" {
		t.Errorf("a new key kept the old key's account %q", fresh.Account)
	}
	if fresh.ExpiresAt != nil {
		t.Errorf("a new key kept the old key's expiry %v", fresh.ExpiresAt)
	}
	kept := ask(brainSignInRequest{})
	if kept.Account != "the old account" || kept.ExpiresAt == nil {
		t.Errorf("changing nothing but the cap lost the account or expiry: %q %v", kept.Account, kept.ExpiresAt)
	}
	if got := ask(brainSignInRequest{Secret: "sk-or-OLD"}).Account; got != "the old account" {
		t.Errorf("the same key sent again lost the account: %q", got)
	}
	if got := ask(brainSignInRequest{Secret: "sk-or-NEW", Account: "the new account"}).Account; got != "the new account" {
		t.Errorf("a named account was not kept: %q", got)
	}
}

// A Grok subscription signed in again as somebody else is named from its own
// sign-in file, not as the account signed in before, and pooled as that
// account.
func TestAGrokSignInAgainAsSomebodyElseIsNamedAsThem(t *testing.T) {
	prev := &brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok,
		Secret: brainsignintest.GrokSignIn("u-old", "old@example.org", "k1"), MaxConcurrentRuns: 1}
	prev.Identify()
	q := brainSignInRequest{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok,
		Secret: brainsignintest.GrokSignIn("u-new", "new@example.org", "k2")}
	rec, err := q.record(prev, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Account != "new@example.org" {
		t.Errorf("signed in again as new@example.org, but named %q", rec.Account)
	}
	if rec.Pool() == prev.Pool() {
		t.Error("signed in again as somebody else, but pooled with the account before")
	}
}
