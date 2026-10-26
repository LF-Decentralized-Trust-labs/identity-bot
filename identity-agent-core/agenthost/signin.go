package agenthost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/brainsignin"
)

// A machine never keeps its AI agent's sign-in. For each run it borrows it
// from the Identity Agent, gives it to the brain's environment for that run
// alone, and returns it when the run ends — also when the run fails. Nothing
// of it is written to disk, and nothing of it goes on a command line.
//
// An AI agent with no sign-in kept at its Identity Agent runs as it always
// has: with whatever this machine's brain was signed in with by hand.

// Borrowed is a sign-in lent for one run.
type Borrowed struct {
	LeaseID    string
	Kind       string
	Provider   string
	Account    string
	Endpoint   string
	secret     string
	renewEvery time.Duration
}

// ErrSignInBusy is a sign-in whose runs are all in use; the run waits.
var ErrSignInBusy = errors.New("this sign-in already has its runs in use")

// ErrNoSignIn is an AI agent whose Identity Agent keeps no sign-in for it.
var ErrNoSignIn = errors.New("no sign-in is kept for this AI agent")

// ErrIdentityAgentLendsNoSignIns is an Identity Agent from before sign-ins
// were lent to bodies.
var ErrIdentityAgentLendsNoSignIns = errors.New("this AI agent's Identity Agent does not lend sign-ins yet")

// Borrow asks the Identity Agent for this AI agent's sign-in, for one run.
// It returns ErrNoSignIn when none is kept, and ErrSignInBusy when its cap on
// simultaneous runs is reached.
func (h *Host) Borrow(ctx context.Context) (*Borrowed, error) {
	code, b, err := h.CallContext(ctx, "POST", "/api/agent-host/brain-sign-in", []byte("{}"))
	if err != nil {
		return nil, err
	}
	var out struct {
		Error         string `json:"error"`
		NoSignIn      bool   `json:"no_sign_in"`
		LeaseID       string `json:"lease_id"`
		RenewEverySec int    `json:"renew_every_seconds"`
		Kind          string `json:"kind"`
		Provider      string `json:"provider"`
		Account       string `json:"account"`
		Endpoint      string `json:"endpoint"`
		Secret        string `json:"secret"`
	}
	_ = json.Unmarshal(b, &out)
	switch code {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusForbidden, http.StatusMethodNotAllowed:
		if out.NoSignIn {
			return nil, ErrNoSignIn
		}
		// An Identity Agent from before sign-ins were lent does not know the
		// route: its gate refuses it as not authorised, or nothing answers.
		if code == http.StatusMethodNotAllowed || out.Error == "not_authorized" ||
			(code == http.StatusNotFound && out.Error == "") {
			return nil, ErrIdentityAgentLendsNoSignIns
		}
		return nil, fmt.Errorf("the AI agent's sign-in could not be borrowed (%d): %s", code, firstNonEmpty(out.Error, string(b)))
	case http.StatusConflict:
		return nil, ErrSignInBusy
	default:
		return nil, fmt.Errorf("the AI agent's sign-in could not be borrowed (%d): %s", code, firstNonEmpty(out.Error, string(b)))
	}
	if out.LeaseID == "" {
		return nil, errors.New("the Identity Agent lent a sign-in with no lease")
	}
	every := time.Duration(out.RenewEverySec) * time.Second
	if every <= 0 {
		every = brainsignin.RenewEvery
	}
	return &Borrowed{LeaseID: out.LeaseID, Kind: out.Kind, Provider: out.Provider, Account: out.Account,
		Endpoint: out.Endpoint, secret: out.Secret, renewEvery: every}, nil
}

// Renew keeps a borrowed sign-in while its run goes on.
func (h *Host) Renew(ctx context.Context, b *Borrowed) error {
	body, _ := json.Marshal(map[string]string{"lease_id": b.LeaseID})
	code, out, err := h.CallContext(ctx, "POST", "/api/agent-host/brain-sign-in/renew", body)
	if err != nil {
		return err
	}
	if code == http.StatusNotFound && strings.Contains(string(out), "no_lease") {
		return &leaseLapsed{status: code}
	}
	if code != http.StatusOK {
		return fmt.Errorf("the sign-in's lease could not be renewed (%d): %s", code, out)
	}
	return nil
}

// Return gives a borrowed sign-in back, and forgets it here.
func (h *Host) Return(ctx context.Context, b *Borrowed) error {
	body, _ := json.Marshal(map[string]string{"lease_id": b.LeaseID})
	b.secret = ""
	code, out, err := h.CallContext(ctx, "POST", "/api/agent-host/brain-sign-in/return", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("the sign-in could not be returned (%d): %s", code, out)
	}
	return nil
}

// credentialVars are the variables a brain reads a sign-in from, or that turn
// a borrowed one off: Claude Code's cloud-provider switches outrank every
// token, and its simple mode is bare mode, which ignores a subscription token.
// When a run is given a borrowed sign-in, none of these is passed on from this
// machine's own environment.
//
// That keeps the machine's environment out of it, not the brain user's own
// configuration: an apiKeyHelper in Claude Code's settings outranks a
// subscription token, and a session from Grok's own sign-in outranks
// XAI_API_KEY. A machine whose brain user was signed in by hand keeps using
// that sign-in.
var credentialVars = []string{
	"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
	"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_SIMPLE",
	"XAI_API_KEY", "GROK_CODE_XAI_API_KEY", "GROK_AUTH_PROVIDER_COMMAND", "GROK_OIDC_ISSUER",
	"GROK_OIDC_CLIENT_ID", "GROK_MODELS_BASE_URL",
	"CODEX_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
}

// localModelNoKey stands in for a key a local model server does not need.
// Without some value Claude Code would send this machine's own sign-in to
// whatever address the model server has.
const localModelNoKey = "no-key"

// Env is the borrowed sign-in as the environment of the brain that runs it,
// named by the brain's program: "claude-code" or "grok".
func (b *Borrowed) Env(brain string) ([]string, error) {
	harness := brainsignin.Harness(b.Provider)
	if harness != NormaliseBrain(brain) {
		return nil, fmt.Errorf("this AI agent is signed in for %s, which its brain %s cannot use", b.Provider, brain)
	}
	switch {
	case harness == brainsignin.HarnessClaudeCode && b.Kind == brainsignin.KindSubscription:
		// Claude Code reads a subscription's long-lived sign-in token from here.
		// It must never be run with --bare, which ignores it.
		return []string{"CLAUDE_CODE_OAUTH_TOKEN=" + b.secret}, nil
	case harness == brainsignin.HarnessClaudeCode && b.Kind == brainsignin.KindAPIKey:
		return []string{"ANTHROPIC_API_KEY=" + b.secret}, nil
	case harness == brainsignin.HarnessClaudeCode && b.Kind == brainsignin.KindLocal:
		if b.Endpoint == "" {
			return nil, errors.New("this AI agent's local model has no address")
		}
		key := firstNonEmpty(b.secret, localModelNoKey)
		return []string{"ANTHROPIC_BASE_URL=" + strings.TrimRight(b.Endpoint, "/"), "ANTHROPIC_AUTH_TOKEN=" + key}, nil
	case harness == brainsignin.HarnessGrok && b.Kind == brainsignin.KindAPIKey && b.Provider == brainsignin.XAI:
		return []string{"XAI_API_KEY=" + b.secret}, nil
	}
	return nil, fmt.Errorf("this machine cannot yet run a %s sign-in for %s borrowed from the Identity Agent", b.Kind, b.Provider)
}

// withCredentials is the environment a brain's process is started with: this
// machine's own, then env on top. When env carries a sign-in, every other
// sign-in in this machine's environment is withheld, so the brain cannot fall
// back on one somebody exported by hand.
func withCredentials(base, env []string) []string {
	given := false
	for _, kv := range env {
		for _, name := range credentialVars {
			if strings.HasPrefix(kv, name+"=") {
				given = true
			}
		}
	}
	if !given {
		return append(base, env...)
	}
	out := make([]string, 0, len(base)+len(env))
next:
	for _, kv := range base {
		for _, name := range credentialVars {
			if strings.HasPrefix(kv, name+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return append(out, env...)
}

// signInForRun borrows the AI agent's sign-in for one run, waiting while its
// runs are all in use, for at most wait. It returns nil with no error when the
// Identity Agent keeps no sign-in for this AI agent.
func (h *Host) signInForRun(ctx context.Context, wait time.Duration, logf func(string, ...any)) (*Borrowed, error) {
	deadline := time.Now().Add(wait)
	pause := 5 * time.Second
	for {
		b, err := h.Borrow(ctx)
		switch {
		case err == nil:
			return b, nil
		case errors.Is(err, ErrNoSignIn):
			return nil, nil
		case errors.Is(err, ErrIdentityAgentLendsNoSignIns):
			logf("[agent-host] %v", err)
			return nil, nil
		case !errors.Is(err, ErrSignInBusy):
			return nil, err
		}
		if !time.Now().Add(pause).Before(deadline) {
			return nil, ErrSignInBusy
		}
		logf("[agent-host] %v; waiting for one to be returned", err)
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if pause *= 2; pause > time.Minute {
			pause = time.Minute
		}
	}
}

// keep renews a borrowed sign-in until stop is closed, then closes done. A
// lease that lapsed anyway — the Identity Agent was out of reach for longer
// than it holds — no longer counts against the cap, so the run takes a place
// again, and says so when it cannot.
func (h *Host) keep(b *Borrowed, stop <-chan struct{}, done chan<- struct{}, logf func(string, ...any)) {
	defer close(done)
	t := time.NewTicker(b.renewEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := h.Renew(ctx, b)
			var lapsed *leaseLapsed
			if errors.As(err, &lapsed) {
				if again, berr := h.Borrow(ctx); berr == nil {
					b.LeaseID = again.LeaseID
					again.secret = ""
					err = nil
				} else {
					err = fmt.Errorf("this run's lease on its sign-in lapsed and no place could be taken again "+
						"(%v); the run goes on outside the sign-in's cap", berr)
				}
			}
			if err != nil {
				logf("[agent-host] %v", err)
			}
			cancel()
		}
	}
}

// leaseLapsed is a lease the Identity Agent no longer holds.
type leaseLapsed struct{ status int }

func (e *leaseLapsed) Error() string {
	return fmt.Sprintf("the sign-in's lease has lapsed (%d)", e.status)
}

// giveBack returns a borrowed sign-in, whatever became of the run: with its
// own time limit, so a run cancelled or timed out still gives it back.
func (h *Host) giveBack(b *Borrowed, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.Return(ctx, b); err != nil {
		logf("[agent-host] %v; its lease lapses on its own", err)
	}
}

// lendForTurn is the sign-in a turn runs with: borrowed from the Identity
// Agent, as the brain's environment. Nil with no error when the Identity Agent
// keeps none for this AI agent, and the brain uses this machine's own.
func (h *Host) lendForTurn(ctx context.Context, brain Brain, logf func(string, ...any)) ([]string, *Borrowed, error) {
	wait := h.signInWait
	if wait <= 0 {
		wait = turnTimeout
	}
	b, err := h.signInForRun(ctx, wait, logf)
	if errors.Is(err, ErrSignInBusy) {
		return nil, nil, fmt.Errorf("%w, and none was returned in time", err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("the AI agent's sign-in could not be borrowed: %w", err)
	}
	if b == nil {
		logf("[agent-host] %s; the brain uses whatever this machine is signed in with", ErrNoSignIn)
		return nil, nil, nil
	}
	env, err := b.Env(brain.Name())
	if err != nil {
		h.giveBack(b, logf)
		return nil, nil, err
	}
	return env, b, nil
}
