package aiagents

import (
	"context"
	"errors"
	"identity-agent-core/lending"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"identity-agent-core/agenthost"
	"identity-agent-core/brainsignin"

	"github.com/go-chi/chi/v5"
)

// A display label names the program that runs: "Claude Code" is stored as
// claude-code, and a body asked to run it runs Claude Code.
func TestClaudeCodeByItsDisplayNameRunsClaudeCode(t *testing.T) {
	w := signInWorld(t)
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents", `{"name":"Labelled","capabilities":["`+
		capabilityMessageAgent+`"],"brain":{"kind":"cli","provider":"Claude Code"}}`)
	if code != http.StatusCreated {
		t.Fatalf("creating: %d %s", code, raw)
	}
	a, _ := hostOf(w.s).AssetHandler().Store.GetAsset(out["asset_id"].(string))
	if a.AgentConfig.Brain.Provider != brainsignin.ClaudeCode || a.AgentConfig.Brain.Kind != brainsignin.KindSubscription {
		t.Fatalf("the label was stored as sent: %+v", a.AgentConfig.Brain)
	}
	b, err := agenthost.BrainFor("Claude Code", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.(agenthost.ClaudeCode); !ok {
		t.Fatalf("\"Claude Code\" ran %T", b)
	}
}

// A subscription capped at one run lends to one run at a time: a second
// borrow is refused while the first holds it, and allowed once it is
// returned. Each lend, refusal and return is in the signed record, without
// the secret.
func TestASubscriptionCappedAtOneLendsToOneRunAtATime(t *testing.T) {
	w := signInWorld(t)
	const token = "sk-ant-oat01-A-CLAUDE-SUBSCRIPTION-TOKEN"
	code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"subscription","provider":"Claude Code","account":"alex@example.org","secret":"`+token+`","max_concurrent_runs":1}`)
	if code != http.StatusOK || strings.Contains(raw, token) {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if v := out["sign_in"].(map[string]any); v["max_concurrent_runs"].(float64) != 1 || v["provider"] != brainsignin.ClaudeCode {
		t.Fatalf("the sign-in is not as set: %v", v)
	}
	ctx := context.Background()
	first, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env, err := first.Env("claude-code"); err != nil || env[0] != "CLAUDE_CODE_OAUTH_TOKEN="+token {
		t.Fatalf("the body was not lent the token for its brain: %v %v", env, err)
	}
	if _, err := w.hostA.Borrow(ctx); !errors.Is(err, agenthost.ErrSignInBusy) {
		t.Fatalf("a second run borrowed a sign-in capped at one: %v", err)
	}
	if err := w.hostA.Return(ctx, first); err != nil {
		t.Fatal(err)
	}
	again, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatalf("the returned place was not free: %v", err)
	}
	if err := w.hostA.Renew(ctx, again); err != nil {
		t.Fatalf("renewing: %v", err)
	}
	// Another AI agent's body cannot return or renew a lease it does not hold.
	if err := w.hostB.Renew(ctx, again); err == nil {
		t.Fatal("another body renewed a lease it does not hold")
	}
	if err := w.hostA.Return(ctx, again); err != nil {
		t.Fatal(err)
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.lent")); n != 2 {
		t.Fatalf("%d lends recorded, want 2", n)
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.lend")); n != 1 {
		t.Fatalf("%d refusals recorded, want 1", n)
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.returned")); n != 2 {
		t.Fatalf("%d returns recorded, want 2", n)
	}
	noFileHolds(t, w.s.DataDir, token)
	noFileHolds(t, w.hostA.DataDir, token)
}

// A body with no sign-in kept for its AI agent is told so, and runs as it
// always has; a body that is not live is refused.
func TestABodyWithNoSignInRunsAsBefore(t *testing.T) {
	w := signInWorld(t)
	if _, err := w.hostB.Borrow(context.Background()); !errors.Is(err, agenthost.ErrNoSignIn) {
		t.Fatalf("an AI agent with no sign-in: %v", err)
	}
	// Nor does an Identity Agent with no vault stop a body that never had one.
	v, mgr := w.s.Vault, w.s.SandboxManager
	w.s.Vault, w.s.SandboxManager = nil, nil
	_, err := w.hostB.Borrow(context.Background())
	w.s.Vault, w.s.SandboxManager = v, mgr
	if !errors.Is(err, agenthost.ErrNoSignIn) {
		t.Fatalf("an Identity Agent with no vault: %v", err)
	}
	// The lending route takes only a sealed, signed request from a live body.
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, httptest.NewRequest("POST", "/api/agent-host/brain-sign-in", strings.NewReader("{}")))
	if rec.Code == http.StatusOK {
		t.Fatal("a sign-in was lent to a request that is not a body's")
	}
}

// fakeClaude is a stand-in for Claude Code that writes down its arguments and
// the sign-in variables it was started with, then answers or fails.
func fakeClaude(t *testing.T, fail bool) (path, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "claude")
	script := "#!/bin/sh\ncat >/dev/null\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\" >> " + record + "; done\n" +
		"printf 'OAUTH:%s\\n' \"$CLAUDE_CODE_OAUTH_TOKEN\" >> " + record + "\n" +
		"printf 'APIKEY:%s\\n' \"$ANTHROPIC_API_KEY\" >> " + record + "\n"
	if fail {
		script += "echo 'usage limit reached' >&2\nexit 1\n"
	} else {
		script += "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"done\",\"session_id\":\"s\",\"modelUsage\":{}}'\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

// The borrowed sign-in reaches the brain through its environment only — not
// its arguments, not a file — and any sign-in exported on the machine is
// withheld so the brain cannot use another. It is returned when the run ends,
// and when the run fails.
func TestABorrowedSignInReachesTheBrainOnlyThroughItsEnvironment(t *testing.T) {
	for _, fail := range []bool{false, true} {
		w := signInWorld(t)
		const token = "sk-ant-oat01-LENT-FOR-ONE-RUN"
		t.Setenv("ANTHROPIC_API_KEY", "a-key-somebody-exported-on-this-machine")
		if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
			`{"kind":"subscription","provider":"claude-code","secret":"`+token+`"}`); code != http.StatusOK {
			t.Fatalf("signing in: %d %s", code, raw)
		}
		conv, _ := w.openedWith(t)
		path, record := fakeClaude(t, fail)
		workspace := t.TempDir()
		if err := w.hostA.Run(context.Background(), agenthost.RunOptions{
			Brain: agenthost.ClaudeCode{Path: path}, Once: true, Workspace: workspace}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(record)
		if err != nil {
			t.Fatalf("the brain never ran: %v", err)
		}
		got := string(b)
		if !strings.Contains(got, "OAUTH:"+token+"\n") {
			t.Fatalf("the brain was not given the borrowed token in its environment:\n%s", got)
		}
		if !strings.Contains(got, "APIKEY:\n") {
			t.Fatalf("a key exported on the machine reached the brain beside the borrowed one:\n%s", got)
		}
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, "ARG:") && (strings.Contains(l, token) || l == "ARG:--bare") {
				t.Fatalf("the token, or --bare, went on the command line: %s", l)
			}
		}
		noFileHolds(t, workspace, token)
		noFileHolds(t, w.hostA.DataDir, token)
		if n := of(w.s).brainRunsInUse(func(x lending.Lend) bool { return x.Agent == w.a.ID }); n != 0 {
			t.Fatalf("fail=%v: %d run(s) still hold the sign-in after the run ended", fail, n)
		}
		if n := len(governanceRows(t, w, "agent.brain.sign_in.returned")); n != 1 {
			t.Fatalf("fail=%v: %d returns recorded, want 1", fail, n)
		}
		if fail {
			entries := w.read(t, conv)
			if last := entries[len(entries)-1]; !strings.Contains(last.Body, "usage limit reached") {
				t.Fatalf("the failed run was not answered with why: %q", last.Body)
			}
		}
	}
}

// An Identity Agent from before sign-ins were lent refuses the route as not
// authorised. A body of it runs as it did, on the machine's own sign-in,
// rather than failing every run.
func TestABodyOfAnOlderIdentityAgentRunsAsBefore(t *testing.T) {
	w := signInWorld(t)
	current := hostOf(w.s).Router()
	older := chi.NewRouter()
	older.Post("/api/agent-host/brain-sign-in", func(rw http.ResponseWriter, _ *http.Request) {
		helpers.DenyAuthorization(rw, "a route nobody classified")
	})
	older.NotFound(current.ServeHTTP)
	helpers.SetRouter(w.s, older)
	t.Cleanup(func() { helpers.SetRouter(w.s, current) })
	if _, err := w.hostA.Borrow(context.Background()); !errors.Is(err, agenthost.ErrIdentityAgentLendsNoSignIns) {
		t.Fatalf("an older Identity Agent: %v", err)
	}
	conv, _ := w.openedWith(t)
	ran := false
	brain := scripted{name: "claude-code", act: func(Turn) (string, error) { ran = true; return "fine", nil }}
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{Brain: brain, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	entries := w.read(t, conv)
	if !ran || entries[len(entries)-1].Body != "fine" {
		t.Fatalf("the run did not go ahead: ran=%v last=%q", ran, entries[len(entries)-1].Body)
	}
}

// An AI agent whose grant is revoked is lent nothing, though its body still
// stands.
func TestARevokedAIAgentIsLentNothing(t *testing.T) {
	w := signInWorld(t)
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"anthropic","secret":"sk-ant-api03-K"}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	held := hostOf(w.s).GrantsHeldBy(w.a.PairwiseAID, false)
	if len(held) == 0 {
		t.Fatal("the AI agent holds no grant")
	}
	if err := w.s.DataStore.UpdateCredentialStatus(held[0].SAID, "revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.hostA.Borrow(context.Background()); err == nil || errors.Is(err, agenthost.ErrNoSignIn) {
		t.Fatalf("a revoked AI agent was lent its sign-in, or told it had none: %v", err)
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.lent")); n != 0 {
		t.Fatalf("%d lends recorded for a revoked AI agent", n)
	}
}
