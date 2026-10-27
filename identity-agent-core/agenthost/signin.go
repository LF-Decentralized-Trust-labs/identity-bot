package agenthost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// refreshed is the sign-in file the run's program renewed, given back
	// with the lease.
	refreshed string
	// agent is the AI agent the sign-in is for, which names its brain's home.
	agent string
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

// Return gives a borrowed sign-in back. A sign-in file the run's program
// renewed goes back with it, sealed like everything a body sends, so the
// Identity Agent keeps the renewed one; it is forgotten here only once the
// Identity Agent has answered, so a return that fails can be tried again.
func (h *Host) Return(ctx context.Context, b *Borrowed) error {
	b.secret = ""
	err := h.returnLease(ctx, b.LeaseID, b.refreshed)
	if returnIsFinal(err) {
		b.refreshed = ""
	}
	return err
}

// ErrLeaseUnknown is a lease the Identity Agent no longer knows: returned
// already, or lapsed so long ago it was forgotten.
var ErrLeaseUnknown = errors.New("the Identity Agent no longer knows this lease")

func (h *Host) returnLease(ctx context.Context, lease, refreshed string) error {
	q := map[string]string{"lease_id": lease}
	if refreshed != "" {
		q["sign_in"] = refreshed
	}
	body, _ := json.Marshal(q)
	code, out, err := h.CallContext(ctx, "POST", "/api/agent-host/brain-sign-in/return", body)
	if err != nil {
		return err
	}
	if code == http.StatusNotFound && strings.Contains(string(out), "no_lease") {
		return ErrLeaseUnknown
	}
	if code >= 400 && code < 500 {
		// Refused, not unreached: trying again would be refused again.
		return fmt.Errorf("%w (%d): %s", errReturnRefused, code, out)
	}
	if code != http.StatusOK {
		return fmt.Errorf("the sign-in could not be returned (%d): %s", code, out)
	}
	return nil
}

// errReturnRefused is a return the Identity Agent answered and refused.
var errReturnRefused = errors.New("the Identity Agent refused the sign-in's return")

// returnIsFinal reports whether a return's outcome would be the same if tried
// again: it went through, or the Identity Agent answered and refused it.
func returnIsFinal(err error) bool {
	return err == nil || errors.Is(err, ErrLeaseUnknown) || errors.Is(err, errReturnRefused)
}

// credentialVars are the variables a brain reads a sign-in from, or that turn
// a borrowed one off: Claude Code's cloud-provider switches outrank every
// token, and its simple mode is bare mode, which ignores a subscription token.
// When a run is given a borrowed sign-in, none of these is passed on from this
// machine's own environment.
//
// That keeps the machine's environment out of it, not the brain user's own
// configuration: an apiKeyHelper in Claude Code's settings outranks a
// subscription token, and a machine whose Claude Code was signed in by hand
// keeps using that. Codex and Grok run in a home of the host's making
// (brainHome), so their own sign-ins and settings do not.
var credentialVars = []string{
	"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
	"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_SIMPLE",
	"XAI_API_KEY", "GROK_CODE_XAI_API_KEY", "GROK_AUTH_PROVIDER_COMMAND", "GROK_OIDC_ISSUER",
	"GROK_OIDC_CLIENT_ID", "GROK_MODELS_BASE_URL",
	"CODEX_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME", "GROK_HOME",
	"OPENROUTER_API_KEY", envModelKey, envBrainHome,
}

// envModelKey carries the key for a model Grok reaches at an address of the
// sign-in's (OpenRouter, or a server that speaks OpenAI's format). Grok's
// settings name the variable, never the key.
const envModelKey = "AGENT_HOST_MODEL_KEY"

// openRouterAPI is OpenRouter's OpenAI-shaped address.
const openRouterAPI = "https://openrouter.ai/api/v1"

// localModelNoKey stands in for a key a local model server does not need.
// Without some value Claude Code would send this machine's own sign-in to
// whatever address the model server has.
const localModelNoKey = "no-key"

// Env is the borrowed sign-in as the environment of the brain that runs it,
// named by the brain's program: "claude-code", "codex" or "grok". A program
// that reads its sign-in from a file — Codex and Grok — is given the file in
// its home for the run (brainHome), which travels in the environment to the
// wrapper that writes it; a key is given as a variable, and the program still
// runs in a home of the host's making, so neither its own sign-in nor its own
// settings outrank the one lent.
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
		return []string{"XAI_API_KEY=" + b.secret, b.homeEnv(brainHome{Var: "GROK_HOME"})}, nil
	case harness == brainsignin.HarnessGrok && b.Kind == brainsignin.KindSubscription:
		return []string{b.homeEnv(brainHome{Var: "GROK_HOME",
			Files: map[string]string{"auth.json": b.secret}, Return: "auth.json"})}, nil
	case harness == brainsignin.HarnessGrok && b.Provider == brainsignin.OpenRouter:
		return []string{envModelKey + "=" + b.secret, b.homeEnv(brainHome{Var: "GROK_HOME",
			ModelBaseURL: openRouterAPI})}, nil
	case harness == brainsignin.HarnessGrok && b.Provider == brainsignin.OpenAICompatible:
		if b.Endpoint == "" {
			return nil, errors.New("this AI agent's model server has no address")
		}
		return []string{envModelKey + "=" + firstNonEmpty(b.secret, localModelNoKey), b.homeEnv(brainHome{
			Var: "GROK_HOME", ModelBaseURL: strings.TrimRight(b.Endpoint, "/")})}, nil
	case harness == brainsignin.HarnessCodex && b.Kind == brainsignin.KindSubscription:
		return []string{b.homeEnv(brainHome{Var: "CODEX_HOME",
			Files: map[string]string{"auth.json": b.secret}, Return: "auth.json"})}, nil
	case harness == brainsignin.HarnessCodex && b.Kind == brainsignin.KindAPIKey:
		return []string{"CODEX_API_KEY=" + b.secret, b.homeEnv(brainHome{Var: "CODEX_HOME"})}, nil
	}
	return nil, fmt.Errorf("this machine cannot yet run a %s sign-in for %s borrowed from the Identity Agent", b.Kind, b.Provider)
}

// homeEnv is a brainHome for this sign-in's AI agent, as the variable that
// carries it: the home is the AI agent's own for the program that reads Var.
func (b *Borrowed) homeEnv(h brainHome) string {
	program := "grok"
	if h.Var == "CODEX_HOME" {
		program = "codex"
	}
	h.Name, h.Legacy = homeName(program, b.agent), program
	return homeEnv(h)
}

// homeEnv is a brainHome as the variable that carries it.
func homeEnv(h brainHome) string {
	b, _ := json.Marshal(h)
	return envBrainHome + "=" + string(b)
}

// homeIn takes the brainHome out of a run's sign-in variables, if one is
// there, and returns the rest.
func homeIn(creds []string) (*brainHome, []string) {
	var home *brainHome
	rest := make([]string, 0, len(creds))
	for _, kv := range creds {
		if v, ok := strings.CutPrefix(kv, envBrainHome+"="); ok {
			var h brainHome
			if json.Unmarshal([]byte(v), &h) == nil {
				home = &h
			}
			continue
		}
		rest = append(rest, kv)
	}
	return home, rest
}

// withCredentials is the environment a brain's process is started with: this
// machine's own, then env on top. When env carries a sign-in, every other
// sign-in in this machine's environment is withheld, so the brain cannot fall
// back on one somebody exported by hand; and when it carries GitHub access,
// every other way git and gh might find GitHub access is withheld the same way.
func withCredentials(base, env []string) []string {
	groups := []struct {
		names, prefixes []string
	}{
		{names: credentialVars},
		{names: githubVars, prefixes: githubVarPrefixes},
	}
	in := func(kv string, names, prefixes []string) bool {
		for _, name := range names {
			if strings.HasPrefix(kv, name+"=") {
				return true
			}
		}
		for _, p := range prefixes {
			if strings.HasPrefix(kv, p) {
				return true
			}
		}
		return false
	}
	var withheld [][2][]string
	for _, g := range groups {
		for _, kv := range env {
			if in(kv, g.names, g.prefixes) {
				withheld = append(withheld, [2][]string{g.names, g.prefixes})
				break
			}
		}
	}
	if len(withheld) == 0 {
		return append(base, env...)
	}
	out := make([]string, 0, len(base)+len(env))
next:
	for _, kv := range base {
		for _, g := range withheld {
			if in(kv, g[0], g[1]) {
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

// returnBackoff is how long a return waits before each further try.
var returnBackoff = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

// retryReturn gives something lent back, whatever became of the run: each try
// with its own time limit, so a run cancelled or timed out still gives it
// back, and tried again, waiting longer each time, while the Identity Agent
// cannot be reached. It returns the last try's outcome. Every kind of lend is
// given back this way.
func retryReturn(give func(ctx context.Context) error) error {
	var err error
	for i := 0; ; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = give(ctx)
		cancel()
		if returnIsFinal(err) || i >= len(returnBackoff) {
			return err
		}
		time.Sleep(returnBackoff[i])
	}
}

// giveBack returns a borrowed sign-in, whatever became of the run
// (retryReturn). A sign-in the run's program renewed that still could not be given
// back is kept on this machine for the next time it reaches the Identity
// Agent (pendingReturn): the one lent may no longer work, so it must not be
// lost with the run.
func (h *Host) giveBack(b *Borrowed, logf func(string, ...any)) {
	err := retryReturn(func(ctx context.Context) error { return h.Return(ctx, b) })
	switch {
	case err != nil && returnIsFinal(err):
		logf("[agent-host] %v; nothing more to give back", err)
	case err != nil && b.refreshed != "":
		if perr := h.keepPendingReturn(b.LeaseID, b.refreshed); perr != nil {
			logf("[agent-host] %v; the sign-in its brain renewed could not be kept to give back later either: %v", err, perr)
		} else {
			logf("[agent-host] %v; the sign-in its brain renewed is kept on this machine, readable only by this "+
				"host, and given back the next time the Identity Agent can be reached", err)
		}
		b.refreshed = ""
	case err != nil:
		logf("[agent-host] %v; its lease lapses on its own", err)
	}
}

// pendingReturn is a lease whose run's renewed sign-in could not be given
// back, kept for the next time the Identity Agent can be reached.
type pendingReturn struct {
	LeaseID string `json:"lease_id"`
	SignIn  string `json:"sign_in"`
}

func (h *Host) pendingReturnsPath() string {
	return filepath.Join(h.DataDir, "sign-ins-to-give-back.json")
}

func (h *Host) loadPendingReturns() []pendingReturn {
	b, err := os.ReadFile(h.pendingReturnsPath())
	if err != nil {
		return nil
	}
	var out []pendingReturn
	_ = json.Unmarshal(b, &out)
	return out
}

func (h *Host) savePendingReturns(all []pendingReturn) error {
	p := h.pendingReturnsPath()
	if len(all) == 0 {
		err := os.Remove(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.DataDir, 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// pendingMu keeps one change to the sign-ins waiting to be given back at a time.
var pendingMu sync.Mutex

// keepPendingReturn keeps a renewed sign-in on this machine, in the host's own
// directory with mode 600, until it can be given back.
func (h *Host) keepPendingReturn(lease, signIn string) error {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	all := h.loadPendingReturns()
	for i := range all {
		if all[i].LeaseID == lease {
			all[i].SignIn = signIn
			return h.savePendingReturns(all)
		}
	}
	return h.savePendingReturns(append(all, pendingReturn{LeaseID: lease, SignIn: signIn}))
}

// givePendingBack gives back every renewed sign-in an earlier run could not,
// before this run borrows: the one it would be lent may be the one retired.
// One the Identity Agent no longer knows is dropped; one it cannot be reached
// for is kept for next time.
func (h *Host) givePendingBack(ctx context.Context, logf func(string, ...any)) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	all := h.loadPendingReturns()
	if len(all) == 0 {
		return
	}
	var left []pendingReturn
	for _, p := range all {
		err := h.returnLease(ctx, p.LeaseID, p.SignIn)
		switch {
		case err == nil:
			logf("[agent-host] a sign-in an earlier run's brain renewed was given back")
		case returnIsFinal(err):
			logf("[agent-host] a sign-in an earlier run's brain renewed could not be given back: %v", err)
		default:
			left = append(left, p)
		}
	}
	if err := h.savePendingReturns(left); err != nil {
		logf("[agent-host] the sign-ins still to give back could not be saved: %v", err)
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
	h.givePendingBack(ctx, logf)
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
	if st, err := h.loadState(); err == nil {
		b.agent = st.Agent
	}
	env, err := b.Env(brain.Name())
	if err != nil {
		h.giveBack(b, logf)
		return nil, nil, err
	}
	return env, b, nil
}
