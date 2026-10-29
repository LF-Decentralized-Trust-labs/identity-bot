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
	// OpenAICompatible is a model server that speaks OpenAI's format, such as
	// vLLM or a hosted endpoint, run by Grok's program.
	OpenAICompatible = "openai-compatible"
)

// Harnesses are the programs that run an AI agent's brain. A model's API does
// not run the program's own loop of thinking and using tools, so a sign-in is
// always used through one of these.
const (
	HarnessClaudeCode = "claude-code"
	HarnessGrok       = "grok"
	HarnessCodex      = "codex"
	HarnessGemini     = "gemini"
	// HarnessBuiltIn is agent-host's own loop (ADR-058), which runs any key
	// the Identity Agent keeps, with no program from anybody else.
	HarnessBuiltIn = "built-in"
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
	"openai-compatible":    OpenAICompatible,
	"openai compatible":    OpenAICompatible,
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
	case Local, OpenAICompatible:
		return KindLocal
	case Anthropic, OpenAI, Google, XAI, OpenRouter:
		return KindAPIKey
	}
	return ""
}

// Harness is the program that runs an AI agent whose brain is signed in with
// this provider, unless the AI agent names another. Claude Code speaks
// Anthropic's API, so it runs Anthropic keys, its own subscription and model
// servers that speak Anthropic's format; Grok's program runs xAI and any
// server that speaks OpenAI's format; Codex runs OpenAI; and agent-host's own
// loop runs OpenRouter (ADR-058).
func Harness(provider string) string {
	switch NormaliseProvider(provider) {
	case "", ClaudeCode, Anthropic, Local:
		return HarnessClaudeCode
	case Grok, XAI, OpenAICompatible:
		return HarnessGrok
	case OpenRouter, HarnessBuiltIn, "builtin":
		return HarnessBuiltIn
	case Codex, OpenAI:
		return HarnessCodex
	case Google:
		return HarnessGemini
	}
	return ""
}

// DefaultMaxConcurrentRuns is a sign-in's cap on simultaneous runs when its
// owner sets none: a Claude subscription is shared by at most five runs; a
// sign-in that renews itself while it runs — Codex's, and Grok's on a
// subscription — by one, because two runs renewing one sign-in may sign each
// other out; and an API key or a model server has no cap (0).
func DefaultMaxConcurrentRuns(kind, provider string) int {
	if kind != KindSubscription {
		return 0
	}
	if RefreshesItself(kind, provider) {
		return 1
	}
	return DefaultSubscriptionRuns
}

// RefreshesItself reports whether a sign-in's program renews it while it
// runs, so that two runs at once on it may sign each other out: Codex's, and
// Grok's on a subscription. Its owner may still raise its cap, warned.
func RefreshesItself(kind, provider string) bool {
	return kind == KindSubscription && (provider == Codex || provider == Grok)
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
	// AccountID is the account the sign-in itself names, where it names one: a
	// ChatGPT account in a Codex sign-in, an xAI user in a Grok sign-in. Every
	// sign-in of one account shares one cap, whichever AI agents hold it.
	AccountID string `json:"account_id,omitempty"`
	// MaxConcurrentRuns is how many runs of the account may hold it at once
	// across every machine; 0 is no cap.
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

// ModelCallHeaders are the headers of a brain's model call that travel on to
// its provider when the Identity Agent makes the call: what describes the
// call, and never how the brain proved itself, which the Identity Agent
// replaces with the key. The body and the Identity Agent both pass only these.
var ModelCallHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// ProgramNone is the program of an AI agent that only reads and answers: its
// body calls the model itself, through the Identity Agent, with no program
// that could use the machine.
const ProgramNone = "none"

// ProgramBuiltIn is agent-host's own loop, named as an AI agent's program: it
// runs a key the Identity Agent keeps for any provider whose model calls it
// makes, in place of that provider's own program (ADR-058).
const ProgramBuiltIn = HarnessBuiltIn

// NormaliseProgram is a brain's program as the record keeps it: empty for the
// program its provider is run by, ProgramNone or ProgramBuiltIn, from the
// names a screen may send for it. Anything else is returned lower-cased, and
// refused by ProgramFits.
func NormaliseProgram(p string) string {
	switch n := strings.ToLower(strings.TrimSpace(p)); n {
	case "", "default", "harness":
		return ""
	case ProgramNone, "direct", "model", "answers only", "read and answer":
		return ProgramNone
	case ProgramBuiltIn, "builtin", "built in", "agent-host", "own", "its own":
		return ProgramBuiltIn
	default:
		return n
	}
}

// ProgramFits says why a brain cannot be run by program. Only a key the
// Identity Agent calls its provider with itself can be used with no program:
// a subscription is for its provider's own program, and a model server's key
// is lent to the machine rather than used here.
func ProgramFits(program, kind, provider string) error {
	switch program {
	case "":
		return nil
	case ProgramNone:
		if (Record{Kind: kind, Provider: provider}).StaysInVault() && provider != Google {
			return nil
		}
		return fmt.Errorf("an AI agent that only reads and answers needs an API key for Anthropic, OpenAI, xAI or "+
			"OpenRouter, which its Identity Agent uses for it; %s %s is run by its own program", kind, provider)
	case ProgramBuiltIn:
		if (Record{Kind: kind, Provider: provider}).StaysInVault() && provider != Google {
			return nil
		}
		return fmt.Errorf("agent-host's own program needs an API key for Anthropic, OpenAI, xAI or OpenRouter, "+
			"which its Identity Agent uses for it; %s %s is run by its own program", kind, provider)
	}
	return fmt.Errorf("%q is not a program a brain is run by", program)
}

// StaysInVault reports whether this sign-in is never lent to a body: an API
// key for a provider the Identity Agent calls itself. Its body's brain is
// pointed at the Identity Agent instead, which adds the key to each model call
// and records it, so taking the key away ends its use at the next call. A
// subscription is still lent, because its program must hold it, and so is a
// model server's key, because the server may be reachable only from the
// machines that run the AI agent.
func (r Record) StaysInVault() bool {
	if r.Kind != KindAPIKey {
		return false
	}
	switch r.Provider {
	case Anthropic, OpenAI, XAI, OpenRouter, Google:
		return true
	}
	return false
}

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
		if r.Provider == Codex || r.Provider == Grok {
			if _, err := ReadSignInFile(r.Provider, r.Secret); err != nil {
				return err
			}
		}
	case KindLocal:
		if r.Provider != Local && r.Provider != OpenAICompatible {
			return fmt.Errorf("a model server's provider is %q or %q, not %q", Local, OpenAICompatible, r.Provider)
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
	// A subscription is one person's, and always capped: 0 means no cap only
	// for a key or a model server.
	if r.Kind == KindSubscription && r.MaxConcurrentRuns < 1 {
		return errors.New("a subscription's runs are always capped: at least 1 at a time")
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

// Choice is a brain a sign-in can be made for, by its provider and kind.
type Choice struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	Harness  string `json:"harness"`
	// DefaultMaxConcurrentRuns is the cap a sign-in gets unless its owner
	// sets another; 0 is no cap.
	DefaultMaxConcurrentRuns int `json:"default_max_concurrent_runs"`
	// RefreshesItself is a sign-in its program renews while it runs: two runs
	// at once on it may sign each other out, so a screen warns before its cap
	// is raised past one.
	RefreshesItself bool `json:"refreshes_itself"`
	// StaysWithIdentityAgent is a key never lent to a machine: the Identity
	// Agent adds it to each of the brain's model calls (Record.StaysInVault).
	StaysWithIdentityAgent bool `json:"stays_with_identity_agent"`
	// CanAnswerOnly is a sign-in an AI agent that only reads and answers can
	// run with, with no program (ProgramNone).
	CanAnswerOnly bool `json:"can_answer_only"`
	// CanRunBuiltIn is a sign-in agent-host's own loop can run
	// (ProgramBuiltIn), whichever program runs it unless the AI agent says.
	CanRunBuiltIn bool `json:"can_run_built_in"`
}

// Runnable are the brains a body can run from a sign-in it borrows, and so
// the only ones a screen offers. A Google key is kept if sent, but not
// offered: no program a body runs takes it yet.
func Runnable() []Choice {
	out := []Choice{
		{Provider: ClaudeCode, Kind: KindSubscription}, {Provider: Codex, Kind: KindSubscription},
		{Provider: Grok, Kind: KindSubscription},
		{Provider: Anthropic, Kind: KindAPIKey}, {Provider: OpenAI, Kind: KindAPIKey},
		{Provider: XAI, Kind: KindAPIKey}, {Provider: OpenRouter, Kind: KindAPIKey},
		{Provider: Local, Kind: KindLocal}, {Provider: OpenAICompatible, Kind: KindLocal},
	}
	for i := range out {
		out[i].Harness = Harness(out[i].Provider)
		out[i].DefaultMaxConcurrentRuns = DefaultMaxConcurrentRuns(out[i].Kind, out[i].Provider)
		out[i].RefreshesItself = RefreshesItself(out[i].Kind, out[i].Provider)
		out[i].StaysWithIdentityAgent = Record{Kind: out[i].Kind, Provider: out[i].Provider}.StaysInVault()
		out[i].CanAnswerOnly = ProgramFits(ProgramNone, out[i].Kind, out[i].Provider) == nil
		out[i].CanRunBuiltIn = ProgramFits(ProgramBuiltIn, out[i].Kind, out[i].Provider) == nil
	}
	return out
}
