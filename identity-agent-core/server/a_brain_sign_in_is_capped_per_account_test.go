package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/agenthost"
	"identity-agent-core/brainsignin"
	"identity-agent-core/brainsignin/brainsignintest"
)

// Two AI agents using one Claude sign-in share its cap: the second cannot
// run while the first holds the only place. Before, each AI agent's sign-in
// was capped on its own, so the same subscription ran once per AI agent.
func TestAIAgentsSharingASignInShareItsCap(t *testing.T) {
	w := signInWorld(t)
	const token = "sk-ant-oat01-ONE-PLAN-FOR-TWO-AGENTS"
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"subscription","provider":"claude-code","secret":"`+token+`","max_concurrent_runs":1}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/brain-sign-in",
		`{"same_as":"`+w.a.ID+`","max_concurrent_runs":1}`)
	if code != http.StatusOK || strings.Contains(raw, token) {
		t.Fatalf("sharing the sign-in: %d %s", code, raw)
	}
	view := out["sign_in"].(map[string]any)
	if shared, _ := view["shared_with"].([]any); len(shared) != 1 || shared[0].(map[string]any)["id"] != w.a.ID {
		t.Fatalf("the view does not say which AI agent shares the account: %v", view)
	}
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.hostB.Borrow(ctx); !errors.Is(err, agenthost.ErrSignInBusy) {
		t.Fatalf("a second AI agent on the same account ran past the account's cap: %v", err)
	}
	if err := w.hostA.Return(ctx, held); err != nil {
		t.Fatal(err)
	}
	again, err := w.hostB.Borrow(ctx)
	if err != nil {
		t.Fatalf("the account's place was not free once returned: %v", err)
	}
	if env, _ := again.Env("claude-code"); len(env) != 1 || env[0] != "CLAUDE_CODE_OAUTH_TOKEN="+token {
		t.Fatalf("the shared sign-in was not lent: %v", env)
	}
	_ = w.hostB.Return(ctx, again)
	// An AI agent cannot be named as sharing its own sign-in.
	if code, _, _ := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", `{"same_as":"`+w.a.ID+`"}`); code != http.StatusBadRequest {
		t.Fatalf("an AI agent shared its own sign-in: %d", code)
	}
	// Nothing that lists sign-ins returns the token.
	if code, out, raw := w.asOwner(t, "GET", "/api/mcp/brain-sign-ins", ""); code != http.StatusOK ||
		strings.Contains(raw, token) || len(out["sign_ins"].([]any)) != 2 {
		t.Fatalf("listing sign-ins: %d %s", code, raw)
	}
}

// Two Codex sign-ins made separately for one ChatGPT account are the same
// account, so they share its cap of one, though their tokens differ.
func TestTwoCodexSignInsOfOneAccountShareOneRun(t *testing.T) {
	w := signInWorld(t)
	for i, id := range []string{w.a.ID, w.b.ID} {
		body, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex",
			"secret": brainsignintest.CodexSignIn("acct-shared", "alex@example.org", "refresh-"+string(rune('a'+i)))})
		if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+id+"/brain-sign-in", string(body)); code != http.StatusOK {
			t.Fatalf("signing in: %d %s", code, raw)
		}
	}
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.hostB.Borrow(ctx); !errors.Is(err, agenthost.ErrSignInBusy) {
		t.Fatalf("two runs on one ChatGPT account at once: %v", err)
	}
	_ = w.hostA.Return(ctx, held)
	_, out, _ := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", "")
	if v := out["sign_in"].(map[string]any); v["account"] != "alex@example.org" || v["max_concurrent_runs"].(float64) != 1 {
		t.Fatalf("the sign-in does not name its account or its cap: %v", v)
	}
}

// providerStub stands in for the providers a sign-in is checked against, and
// writes down what each was sent.
type providerStub struct {
	mu   sync.Mutex
	seen []string
}

func (p *providerStub) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.Path+" "+r.Header.Get("Authorization")+r.Header.Get("x-api-key"))
		p.mu.Unlock()
		good := strings.Contains(r.Header.Get("Authorization")+r.Header.Get("x-api-key"), "GOOD")
		if !good {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/x/v1/api-key":
			_, _ = rw.Write([]byte(`{"name":"Support team key","api_key_blocked":false}`))
		case "/or/v1/key":
			_, _ = rw.Write([]byte(`{"data":{"label":"Research"}}`))
		case "/oa/v1/models":
			rw.Header().Set("openai-organization", "acme-co")
			_, _ = rw.Write([]byte(`{"data":[]}`))
		case "/redirect/v1/models":
			http.Redirect(rw, r, "http://elsewhere.invalid/", http.StatusFound)
		default:
			_, _ = rw.Write([]byte(`{"data":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A sign-in is checked before it is kept, by one request to its provider, and
// nothing is kept by checking. A Claude subscription is never sent anywhere by
// the Identity Agent; a Codex sign-in file is read for its account.
func TestASignInIsCheckedBeforeItIsKept(t *testing.T) {
	w := signInWorld(t)
	stub := &providerStub{}
	srv := stub.serve(t)
	w.s.brainChecker = &brainsignin.Checker{Anthropic: srv.URL + "/a", OpenAI: srv.URL + "/oa", XAI: srv.URL + "/x",
		OpenRouter: srv.URL + "/or", Google: srv.URL + "/g"}
	for _, c := range []struct {
		body, account, checked string
		ok                     bool
	}{
		{`{"kind":"api_key","provider":"anthropic","secret":"sk-ant-api03-GOOD"}`, "", "provider", true},
		{`{"kind":"api_key","provider":"anthropic","secret":"sk-ant-api03-BAD"}`, "", "provider", false},
		{`{"kind":"api_key","provider":"openai","secret":"sk-GOOD"}`, "acme-co", "provider", true},
		{`{"kind":"api_key","provider":"xai","secret":"xai-GOOD"}`, "Support team key", "provider", true},
		{`{"kind":"api_key","provider":"openrouter","secret":"sk-or-GOOD"}`, "Research", "provider", true},
		{`{"kind":"local","provider":"local","endpoint":"` + srv.URL + `","secret":"GOOD"}`, "", "provider", true},
		{`{"kind":"local","provider":"openai-compatible","endpoint":"` + srv.URL + `/redirect/v1","secret":"GOOD"}`, "", "provider", false},
		{`{"kind":"subscription","provider":"claude-code","secret":"sk-ant-oat01-NEVER-SENT"}`, "", "not_here", false},
	} {
		code, out, raw := w.asOwner(t, "POST", "/api/mcp/brain-sign-in/test", c.body)
		if code != http.StatusOK || out["ok"] != c.ok || out["account"] != c.account || out["checked"] != c.checked {
			t.Errorf("%s: %d %s", c.body, code, raw)
		}
		if strings.Contains(raw, "GOOD") || strings.Contains(raw, "BAD") {
			t.Errorf("the check's answer carries the key: %s", raw)
		}
	}
	codex, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex",
		"secret": brainsignintest.CodexSignIn("acct-1", "alex@example.org", "r")})
	if code, out, raw := w.asOwner(t, "POST", "/api/mcp/brain-sign-in/test", string(codex)); code != http.StatusOK ||
		out["ok"] != true || out["account"] != "alex@example.org" || out["checked"] != "sign_in_file" {
		t.Errorf("a Codex sign-in: %d %s", code, raw)
	}
	for _, s := range stub.seen {
		if strings.Contains(s, "NEVER-SENT") {
			t.Fatal("the Identity Agent sent a Claude subscription's token to a provider")
		}
	}
	// Checking kept nothing, and wrote no key anywhere.
	if _, out, _ := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", ""); out["sign_in"] != nil {
		t.Fatalf("checking a sign-in kept it: %v", out)
	}
	noFileHolds(t, w.s.DataDir, "sk-ant-api03-GOOD")
	// The kept sign-in can be checked again later.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"xai","secret":"xai-GOOD"}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in/test", ""); code != http.StatusOK ||
		out["ok"] != true || out["account"] != "Support team key" {
		t.Fatalf("checking the kept sign-in: %d %s", code, raw)
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.checked")); n != 1 {
		t.Fatalf("%d checks recorded, want 1", n)
	}
	// The screen is told which brains a body can run.
	_, out, _ := w.asOwner(t, "GET", "/api/mcp/brain-sign-in/choices", "")
	if n := len(out["choices"].([]any)); n != len(brainsignin.Runnable()) {
		t.Fatalf("%d choices", n)
	}
}

// fakeCodex is a stand-in for Codex that renews the sign-in file it is lent,
// as Codex does when its token is near its end.
func fakeCodex(t *testing.T, renewed string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	path := filepath.Join(t.TempDir(), "codex")
	script := "#!/bin/sh\ncat >/dev/null\n" +
		"test -f \"$CODEX_HOME/auth.json\" || { echo 'not signed in' >&2; exit 1; }\n" +
		"printf '%s' '" + renewed + "' > \"$CODEX_HOME/auth.json\"\n" +
		`echo '{"type":"thread.started","thread_id":"t-1"}'` + "\n" +
		`echo '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}'` + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A Codex sign-in is lent to one run, which renews it; the renewed one is kept
// for every AI agent sharing it, so the next run is not lent a token Codex has
// already replaced. Before, a Codex sign-in could not be lent to a run at all.
func TestARenewedCodexSignInIsKept(t *testing.T) {
	w := signInWorld(t)
	t.Setenv("HOME", t.TempDir())
	first := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-ONE")
	renewed := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-TWO")
	body, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex", "secret": first})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", string(body)); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/brain-sign-in", `{"same_as":"`+w.a.ID+`"}`); code != http.StatusOK {
		t.Fatalf("sharing: %d %s", code, raw)
	}
	w.openedWith(t)
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{
		Brain: agenthost.Codex{Path: fakeCodex(t, renewed)}, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{w.a.ID, w.b.ID} {
		rec, _, err := w.s.SandboxManager.BrainSignIn(brainsignin.Ref(id))
		if err != nil || rec.Secret != renewed {
			t.Fatalf("the renewed sign-in was not kept for %s: %v", id, err)
		}
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.returned")); n != 1 {
		t.Fatalf("%d returns recorded, want 1", n)
	}
	noFileHolds(t, w.hostA.DataDir, "REFRESH-TWO")
	// A renewed file for some other account is not kept.
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	other := brainsignintest.CodexSignIn("acct-OTHER", "eve@example.org", "R")
	got := w.s.keepRefreshedSignIn(*w.a, brainsignin.Lease{Lent: brainsignin.Fingerprint("codex", renewed)}, other)
	if !strings.Contains(got, "another account") {
		t.Fatalf("a sign-in for another account was kept: %s", got)
	}
	_ = w.hostA.Return(context.Background(), held)
}
