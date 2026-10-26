// Package brainsignin is how an AI agent's brain is signed in: once, kept in
// its Identity Agent's vault, and lent to a body for one run at a time.
//
// A brain is the program that thinks for an AI agent — Claude Code, Grok and
// the like — and a sign-in is what lets that program reach its model: an API
// key, a subscription's sign-in token, or the address of a model server. The
// sign-in is never kept on a machine. A body borrows it when a run starts,
// gives it to the brain's environment, and returns it when the run ends.
//
// A subscription is meant for one person's use, so each sign-in carries a cap
// on how many runs may hold it at once, across every machine.
package brainsignin

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kinds of sign-in.
const (
	// KindAPIKey is a provider's API key, billed by the provider per use.
	KindAPIKey = "api_key"
	// KindSubscription is a person's subscription, signed in through the
	// provider's own sign-in.
	KindSubscription = "subscription"
	// KindLocal is a model server the organisation runs, with a key only if
	// that server needs one.
	KindLocal = "local"
)

// Providers a sign-in can be for.
const (
	Anthropic  = "anthropic"
	OpenAI     = "openai"
	Google     = "google"
	XAI        = "xai"
	OpenRouter = "openrouter"
	ClaudeCode = "claude-code"
	Codex      = "codex"
	Grok       = "grok"
	Local      = "local"
)

// Harnesses are the programs that run an AI agent's loop. A raw model API has
// no agent loop, so a sign-in is always used through one of these.
const (
	HarnessClaudeCode = "claude-code"
	HarnessGrok       = "grok"
	HarnessCodex      = "codex"
	HarnessGemini     = "gemini"
)

// DefaultSubscriptionRuns is how many runs may hold one subscription sign-in
// at once, across every machine, unless its owner sets another number.
const DefaultSubscriptionRuns = 5

// labels are the names people and screens use for a provider.
var labels = map[string]string{
	"anthropic":            Anthropic,
	"claude api":           Anthropic,
	"openai":               OpenAI,
	"google":               Google,
	"gemini":               Google,
	"xai":                  XAI,
	"x.ai":                 XAI,
	"openrouter":           OpenRouter,
	"claude-code":          ClaudeCode,
	"claude code":          ClaudeCode,
	"claude":               ClaudeCode,
	"codex":                Codex,
	"codex cli":            Codex,
	"grok":                 Grok,
	"grok cli":             Grok,
	"grok build":           Grok,
	"local":                Local,
	"local model":          Local,
	"ollama":               Local,
	"lm studio":            Local,
	"vllm":                 Local,
	"local api":            Local,
	"self-hosted":          Local,
	"self hosted":          Local,
	"openai-compatible":    Local,
	"openai compatible":    Local,
	"anthropic-compatible": Local,
}

// NormaliseProvider is a provider's name as the record keeps it, from
// whatever a person or a screen called it ("Claude Code", "Grok CLI", "xAI").
// A name nobody knows is returned lower-cased and trimmed, so it is still
// compared consistently, and refused where a known one is required.
func NormaliseProvider(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if p, ok := labels[n]; ok {
		return p
	}
	return n
}

// NormaliseKind is a sign-in's kind as the record keeps it. It accepts the
// older names a brain's configuration used ("cli" for a subscription program,
// "remote" for a hosted model's API), and when no kind is given it is the
// usual kind for the provider.
func NormaliseKind(kind, provider string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case KindAPIKey, "api key", "apikey", "remote":
		return KindAPIKey
	case KindSubscription, "cli":
		return KindSubscription
	case KindLocal:
		return KindLocal
	case "":
		return KindOf(NormaliseProvider(provider))
	}
	return strings.ToLower(strings.TrimSpace(kind))
}

// KindOf is the kind of sign-in a provider is signed in with.
func KindOf(provider string) string {
	switch provider {
	case ClaudeCode, Codex, Grok:
		return KindSubscription
	case Local:
		return KindLocal
	case Anthropic, OpenAI, Google, XAI, OpenRouter:
		return KindAPIKey
	}
	return ""
}

// Harness is the program that runs an AI agent whose brain is signed in with
// this provider. Claude Code speaks Anthropic's API, so it runs Anthropic
// keys, its own subscription and local model servers; Grok's program runs
// xAI and other OpenAI-shaped endpoints; Codex runs OpenAI.
func Harness(provider string) string {
	switch NormaliseProvider(provider) {
	case "", ClaudeCode, Anthropic, Local:
		return HarnessClaudeCode
	case Grok, XAI, OpenRouter:
		return HarnessGrok
	case Codex, OpenAI:
		return HarnessCodex
	case Google:
		return HarnessGemini
	}
	return ""
}

// DefaultMaxConcurrentRuns is a sign-in's cap on simultaneous runs when its
// owner sets none: a subscription is shared by at most five runs, Codex's by
// one because its sign-in cannot be shared between runs, and an API key or a
// local model server has no cap (0).
func DefaultMaxConcurrentRuns(kind, provider string) int {
	if kind != KindSubscription {
		return 0
	}
	if provider == Codex {
		return 1
	}
	return DefaultSubscriptionRuns
}

// Record is one AI agent's brain sign-in, as the vault keeps it.
type Record struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	// Account is a label for whose account this is, for the people managing
	// it: an email, or a name for the key. Never used to sign in.
	Account string `json:"account,omitempty"`
	// Endpoint is a local model server's address.
	Endpoint string `json:"endpoint,omitempty"`
	// ExpiresAt is when the sign-in stops working, where that is known.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// MaxConcurrentRuns is how many runs may hold it at once across every
	// machine; 0 is no cap.
	MaxConcurrentRuns int `json:"max_concurrent_runs"`
	// Secret is the key or sign-in token. It leaves the vault only sealed to a
	// body, for one run.
	Secret string    `json:"secret,omitempty"`
	SetAt  time.Time `json:"set_at"`
}

// Public is the record without its secret, as it may be shown.
func (r Record) Public() Record {
	r.Secret = ""
	return r
}

// HasSecret reports whether the record holds a key or token.
func (r Record) HasSecret() bool { return r.Secret != "" }

// Expired reports whether the sign-in has stopped working by now.
func (r Record) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt)
}

// Check refuses a record that could not be used as it stands.
func (r Record) Check() error {
	switch r.Kind {
	case KindAPIKey:
		switch r.Provider {
		case Anthropic, OpenAI, Google, XAI, OpenRouter:
		default:
			return fmt.Errorf("an API key is for anthropic, openai, google, xai or openrouter, not %q", r.Provider)
		}
		if r.Secret == "" {
			return errors.New("an API key sign-in needs the key")
		}
	case KindSubscription:
		switch r.Provider {
		case ClaudeCode, Codex, Grok:
		default:
			return fmt.Errorf("a subscription is signed in for claude-code, codex or grok, not %q", r.Provider)
		}
		if r.Secret == "" {
			return errors.New("a subscription sign-in needs the sign-in token the provider gave")
		}
	case KindLocal:
		if r.Provider != Local {
			return fmt.Errorf("a local model's provider is %q, not %q", Local, r.Provider)
		}
		if strings.TrimSpace(r.Endpoint) == "" {
			return errors.New("a local model needs the address of its server")
		}
	default:
		return fmt.Errorf("a sign-in's kind is api_key, subscription or local, not %q", r.Kind)
	}
	if r.MaxConcurrentRuns < 0 {
		return errors.New("the cap on simultaneous runs cannot be below 0 (0 is no cap)")
	}
	return nil
}

// refPrefix marks a brain configuration's credential reference as naming a
// sign-in this package keeps.
const refPrefix = "ai-agent-brain:"

// Ref is the vault reference for an AI agent's sign-in, by the AI agent's
// asset id.
func Ref(assetID string) string { return refPrefix + assetID }

// IsRef reports whether s names a brain sign-in in the vault, rather than
// being anything else — a key typed where a reference belongs, for one.
func IsRef(s string) bool { return strings.HasPrefix(s, refPrefix) && len(s) > len(refPrefix) }
