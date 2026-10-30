package server

import (
	"context"
	"encoding/json"
	"errors"
	"identity-agent-core/lending"
	"identity-agent-core/sandbox"
	"identity-agent-core/vault"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/agenthost"
	"identity-agent-core/authprovider"
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

// loopbackAllowed is the rule for which addresses a model server is checked
// at, with this computer allowed, so a test server can stand in for one on the
// network.
func loopbackAllowed(a netip.Addr) error {
	if a.IsLoopback() {
		return nil
	}
	return brainsignin.ModelServerAddress(a)
}

// A sign-in is checked before it is kept, by one request to its provider, and
// nothing is kept by checking. A Claude subscription is never sent anywhere by
// the Identity Agent; a Codex sign-in file is read for its account.
func TestASignInIsCheckedBeforeItIsKept(t *testing.T) {
	w := signInWorld(t)
	stub := &providerStub{}
	srv := stub.serve(t)
	w.s.brainChecker = &brainsignin.Checker{Anthropic: srv.URL + "/a", OpenAI: srv.URL + "/oa", XAI: srv.URL + "/x",
		OpenRouter: srv.URL + "/or", Google: srv.URL + "/g", AddressRule: loopbackAllowed}
	// A model server that sends the check on to another: the key must not
	// follow it there.
	var elsewhereHit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		elsewhereHit.Store(true)
		_, _ = rw.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(elsewhere.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, elsewhere.URL+"/v1/models", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
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
		{`{"kind":"local","provider":"openai-compatible","endpoint":"` + redirector.URL + `/v1","secret":"GOOD"}`, "", "provider", false},
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
	if elsewhereHit.Load() {
		t.Fatal("the check followed a redirect, and the key went to another server")
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
	// A machine the owner authorised checks it the same way: the Identity
	// Agent's call goes out as it does for the owner.
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "POST",
		"/api/mcp/agents/"+w.a.ID+"/brain-sign-in/test", "", w.ctlSeed, authprovider.LevelVerified, time.Now()))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("a controller checking the kept sign-in: %d %s", rec.Code, rec.Body.String())
	}
	// The screen is told which brains a body can run.
	_, out, _ := w.asOwner(t, "GET", "/api/mcp/brain-sign-in/choices", "")
	if n := len(out["choices"].([]any)); n != len(brainsignin.Runnable()) {
		t.Fatalf("%d choices", n)
	}
}

// A check carries only the key it is checking: the vault adds none of its
// own, even for an address the vault holds a key for. Otherwise a wrong key
// would be answered with the right one, and look as if it worked.
func TestTheVaultAddsNoKeyToACheck(t *testing.T) {
	w := signInWorld(t)
	stub := &providerStub{}
	srv := stub.serve(t)
	w.s.brainChecker = &brainsignin.Checker{Anthropic: srv.URL + "/a", AddressRule: loopbackAllowed}
	if err := w.s.Vault.SetCredential("a-kept-key", []string{"127.0.0.1"},
		map[string]string{"Authorization": "Bearer VAULT-KEY-GOOD", "x-api-key": "VAULT-KEY-GOOD"}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"kind":"api_key","provider":"anthropic","secret":"sk-ant-api03-BAD"}`,
		`{"kind":"local","provider":"local","endpoint":"` + srv.URL + `"}`,
	} {
		if code, out, raw := w.asOwner(t, "POST", "/api/mcp/brain-sign-in/test", body); code != http.StatusOK || out["ok"] != false {
			t.Errorf("%s was answered with the vault's key: %d %s", body, code, raw)
		}
	}
	for _, s := range stub.seen {
		if strings.Contains(s, "VAULT-KEY") {
			t.Fatalf("the vault added its own key to a check: %s", s)
		}
	}
	if len(stub.seen) != 2 {
		t.Fatalf("the checks did not reach the server: %v", stub.seen)
	}
}

// A check goes only where the owner lets this Identity Agent go: a domain the
// owner blocked is not reached by a check either. Before, the Identity Agent's
// own requests were approved without looking at the owner's blocks.
func TestACheckKeepsToTheOwnersBlocks(t *testing.T) {
	w := signInWorld(t)
	stub := &providerStub{}
	srv := stub.serve(t)
	w.s.brainChecker = &brainsignin.Checker{AddressRule: loopbackAllowed}
	// No screen sets the owner's blocks for this Identity Agent's own requests
	// yet; a rule kept for them is still applied.
	if err := w.s.SandboxManager.Store().SaveApp(sandbox.App{ID: sandbox.BackendLLMAppID, Name: "this Identity Agent",
		ExecutionType: "native", DisplayMethod: "none", ManifestJSON: "{}", InstallStatus: "installed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.SandboxManager.Store().SavePolicyRule(sandbox.PolicyRule{AppID: sandbox.BackendLLMAppID,
		RuleType: "domain_block", Target: "127.0.0.1", Source: "user"}); err != nil {
		t.Fatal(err)
	}
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/brain-sign-in/test",
		`{"kind":"local","provider":"local","endpoint":"http://someone:pw@`+strings.TrimPrefix(srv.URL, "http://")+`"}`)
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(raw, "user name or password") {
		t.Fatalf("an address with a password: %d %s", code, raw)
	}
	code, out, raw = w.asOwner(t, "POST", "/api/mcp/brain-sign-in/test",
		`{"kind":"local","provider":"local","endpoint":"`+srv.URL+`"}`)
	if code != http.StatusOK || out["ok"] != false || len(stub.seen) != 0 {
		t.Fatalf("a blocked domain was reached: %d %s, %v", code, raw, stub.seen)
	}
}

// One account has one cap, whichever of its AI agents set it, and a
// subscription's cannot be lifted to none.
func TestAnAccountsCapIsOneNumber(t *testing.T) {
	w := signInWorld(t)
	put := func(id string, body map[string]any) (int, map[string]any, string) {
		b, _ := json.Marshal(body)
		return w.asOwner(t, "PUT", "/api/mcp/agents/"+id+"/brain-sign-in", string(b))
	}
	if code, _, raw := put(w.a.ID, map[string]any{"kind": "subscription", "provider": "codex", "max_concurrent_runs": 2,
		"secret": brainsignintest.CodexSignIn("acct-1", "alex@example.org", "RA")}); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	// Signed in separately for the same account, with no cap given: it takes
	// the account's.
	code, out, raw := put(w.b.ID, map[string]any{"kind": "subscription", "provider": "codex",
		"secret": brainsignintest.CodexSignIn("acct-1", "alex@example.org", "RB")})
	if code != http.StatusOK || out["sign_in"].(map[string]any)["max_concurrent_runs"].(float64) != 2 {
		t.Fatalf("a second sign-in of the account did not take its cap: %d %s", code, raw)
	}
	// Either AI agent changing it changes it for both.
	if code, _, raw := put(w.b.ID, map[string]any{"max_concurrent_runs": 3}); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	_, out, _ = w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", "")
	if n := out["sign_in"].(map[string]any)["max_concurrent_runs"].(float64); n != 3 {
		t.Fatalf("the other AI agent on the account has cap %v, want 3", n)
	}
	ctx := context.Background()
	var held []*agenthost.Borrowed
	for _, h := range []*agenthost.Host{w.hostA, w.hostA, w.hostB} {
		b, err := h.Borrow(ctx)
		if err != nil {
			t.Fatalf("run %d of 3: %v", len(held)+1, err)
		}
		held = append(held, b)
	}
	if _, err := w.hostA.Borrow(ctx); !errors.Is(err, agenthost.ErrSignInBusy) {
		t.Fatalf("a fourth run on an account capped at three: %v", err)
	}
	for i, b := range held {
		h := w.hostA
		if i == 2 {
			h = w.hostB
		}
		_ = h.Return(ctx, b)
	}
	if code, _, raw := put(w.a.ID, map[string]any{"max_concurrent_runs": 0}); code != http.StatusBadRequest {
		t.Fatalf("a subscription's cap was lifted to none: %d %s", code, raw)
	}
	if code, _, raw := put(w.a.ID, map[string]any{"kind": "api_key", "provider": "openai", "secret": "sk-X",
		"max_concurrent_runs": 0}); code != http.StatusOK {
		t.Fatalf("a key could not be left uncapped: %d %s", code, raw)
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
		rec, _, err := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(id))
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
	got, _ := w.s.keepRefreshedSignIn(*w.a, lending.Lend{Lent: brainsignin.Fingerprint("codex", renewed)}, other)
	if !strings.Contains(got, "another account") {
		t.Fatalf("a sign-in for another account was kept: %s", got)
	}
	_ = w.hostA.Return(context.Background(), held)
}

// A run whose lease lapsed — its body was out of reach for longer than a
// lease holds — still gives back the sign-in its program refreshed, and it is
// kept. Before, the lapsed lease was forgotten before the return was read, so
// the refresh was lost and the next run was lent a token Codex had replaced.
func TestARefreshReturnedAfterTheLeaseLapsedIsKept(t *testing.T) {
	w := signInWorld(t)
	first := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-ONE")
	renewed := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-TWO")
	body, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex", "secret": first})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", string(body)); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.lends().Lapse(time.Now().Add(brainsignin.LeaseTTL + time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Another run takes the place the lapsed lease held.
	other, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatalf("the lapsed lease still held its place: %v", err)
	}
	ret, _ := json.Marshal(map[string]string{"lease_id": held.LeaseID, "sign_in": renewed})
	code, out, err := w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/brain-sign-in/return", ret)
	if err != nil || code != http.StatusOK {
		t.Fatalf("returning a lapsed lease: %d %s %v", code, out, err)
	}
	if rec, _, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(w.a.ID)); rec.Secret != renewed {
		t.Fatal("the sign-in refreshed during a run whose lease lapsed was lost")
	}
	_ = w.hostA.Return(context.Background(), other)
}

// A refreshed sign-in that could not be given back when its run ended is
// given back the next time the body reaches the Identity Agent, before it
// borrows again: the next run is lent the refreshed one.
func TestARefreshKeptOnTheMachineIsGivenBackOnTheNextRun(t *testing.T) {
	w := signInWorld(t)
	t.Setenv("HOME", t.TempDir())
	first := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-ONE")
	renewed := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-TWO")
	body, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex", "secret": first})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", string(body)); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// What a run that could not reach the Identity Agent left on its machine.
	pending, _ := json.Marshal([]map[string]string{{"lease_id": held.LeaseID, "sign_in": renewed}})
	if err := os.WriteFile(filepath.Join(w.hostA.DataDir, "sign-ins-to-give-back.json"), pending, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.lends().Lapse(time.Now().Add(brainsignin.LeaseTTL + time.Minute)); err != nil {
		t.Fatal(err)
	}
	w.openedWith(t)
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{
		Brain: agenthost.Codex{Path: fakeCodexLentOnly(t, renewed)}, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(w.hostA.DataDir, "sign-ins-to-give-back.json")); !os.IsNotExist(err) {
		t.Fatalf("the refresh given back is still kept on the machine: %v", err)
	}
	if rec, _, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(w.a.ID)); rec.Secret != renewed {
		t.Fatal("the refresh kept on the machine was not given back")
	}
}

// fakeCodexLentOnly is a stand-in for Codex that answers only when it is lent
// want, and renews nothing.
func fakeCodexLentOnly(t *testing.T, want string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	path := filepath.Join(t.TempDir(), "codex")
	wantFile := filepath.Join(t.TempDir(), "want")
	if err := os.WriteFile(wantFile, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat >/dev/null\n" +
		"cmp -s \"$CODEX_HOME/auth.json\" " + wantFile + " || { echo 'lent the wrong sign-in' >&2; exit 1; }\n" +
		`echo '{"type":"thread.started","thread_id":"t-1"}'` + "\n" +
		`echo '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}'` + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A refreshed sign-in is written only where the very sign-in lent is kept: the
// borrowing AI agent's, and one shared from it. Another AI agent's sign-in of
// the same account, made separately, is its own and is left alone; and a
// refreshed file for another person on the account is not kept at all.
func TestARefreshIsWrittenOnlyWhereTheLentSignInIsKept(t *testing.T) {
	w := signInWorld(t)
	third := w.provision(t, "Third", []string{capabilityMessageAgent})
	first := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-ONE")
	separate := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-SEPARATE")
	renewed := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-TWO")
	for id, body := range map[string]map[string]any{
		w.a.ID:   {"kind": "subscription", "provider": "codex", "secret": first},
		third.ID: {"kind": "subscription", "provider": "codex", "secret": separate},
	} {
		b, _ := json.Marshal(body)
		if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+id+"/brain-sign-in", string(b)); code != http.StatusOK {
			t.Fatalf("signing in: %d %s", code, raw)
		}
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/brain-sign-in", `{"same_as":"`+w.a.ID+`"}`); code != http.StatusOK {
		t.Fatalf("sharing: %d %s", code, raw)
	}
	lease := lending.Lend{Lent: brainsignin.Fingerprint("codex", first)}
	if got, _ := w.s.keepRefreshedSignIn(*w.a, lease, brainsignintest.CodexSignIn("acct-1", "eve@example.org", "R")); !strings.Contains(got, "not kept") {
		t.Fatalf("a refresh for another person on the account: %s", got)
	}
	if got, _ := w.s.keepRefreshedSignIn(*w.a, lease, renewed); !strings.Contains(got, "every AI agent sharing it") {
		t.Fatalf("keeping the refresh: %s", got)
	}
	for id, want := range map[string]string{w.a.ID: renewed, w.b.ID: renewed, third.ID: separate} {
		if rec, _, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(id)); rec.Secret != want {
			t.Errorf("%s holds the wrong sign-in after the refresh", id)
		}
	}
}

// A refreshed sign-in that reaches the Identity Agent while its vault cannot
// be written is not taken as returned: the lease stays, the run is told to
// try again, and the next try keeps it. Answering "returned" would have the
// machine drop the only copy of a sign-in whose old refresh token is spent.
func TestARefreshTheVaultCannotKeepYetIsNotTakenAsReturned(t *testing.T) {
	w := signInWorld(t)
	first := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-ONE")
	renewed := brainsignintest.CodexSignIn("acct-1", "alex@example.org", "REFRESH-TWO")
	body, _ := json.Marshal(map[string]any{"kind": "subscription", "provider": "codex", "secret": first})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", string(body)); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("a read-only file does not stop root")
	}
	var vaultFile string
	_ = filepath.WalkDir(w.s.DataDir, func(p string, d fs.DirEntry, _ error) error {
		if d != nil && d.Name() == "service_credentials.enc" {
			vaultFile = p
		}
		return nil
	})
	if vaultFile == "" {
		t.Fatal("no vault file to make unwritable")
	}
	if err := os.Chmod(vaultFile, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vaultFile, 0o600) })
	ret, _ := json.Marshal(map[string]string{"lease_id": held.LeaseID, "sign_in": renewed})
	code, out, _ := w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/brain-sign-in/return", ret)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a refresh the vault could not keep was answered %d %s", code, out)
	}
	if w.s.brainRunsInUse(func(x lending.Lend) bool { return x.Agent == w.a.ID }) != 1 {
		t.Fatal("the lease was given back though its refresh was not kept")
	}
	if err := os.Chmod(vaultFile, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/brain-sign-in/return", ret)
	if code != http.StatusOK {
		t.Fatalf("trying again once the vault opened: %d %s", code, out)
	}
	if rec, _, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(w.a.ID)); rec.Secret != renewed {
		t.Fatal("the refresh was lost")
	}
}
