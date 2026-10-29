package agenthost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"identity-agent-core/brainsignin"
)

// A brain whose key stays with the Identity Agent is given this body's model
// address and its run's token, in the variables its program reads, and no
// key: Claude Code an Anthropic base address and auth token, Grok its xAI
// address or a model at the body's address, Codex OpenAI's base address.
func TestABrainWhoseKeyStaysHereIsGivenItsBodysModelAddress(t *testing.T) {
	const url, tok = "http://127.0.0.1:4000/model", "ahm-RUN-TOKEN"
	H := homeName("grok", "agent-1")
	C := homeName("codex", "agent-1")
	for _, c := range []struct {
		provider, brain string
		want            []string
	}{
		{brainsignin.Anthropic, "claude-code", []string{"ANTHROPIC_BASE_URL=" + url, "ANTHROPIC_AUTH_TOKEN=" + tok}},
		{brainsignin.XAI, "grok", []string{"XAI_API_KEY=" + tok, "GROK_XAI_API_BASE_URL=" + url + "/v1",
			envBrainHome + `={"var":"GROK_HOME","name":"` + H + `","legacy":"grok"}`}},
		{brainsignin.OpenRouter, "grok", []string{envModelKey + "=" + tok,
			envBrainHome + `={"var":"GROK_HOME","name":"` + H + `","legacy":"grok","model_base_url":"` + url + `/v1"}`}},
		{brainsignin.OpenAI, "codex", []string{"CODEX_API_KEY=" + tok, "OPENAI_BASE_URL=" + url + "/v1",
			envBrainHome + `={"var":"CODEX_HOME","name":"` + C + `","legacy":"codex"}`}},
	} {
		b := &Borrowed{Kind: brainsignin.KindAPIKey, Provider: c.provider, throughIdentityAgent: true,
			modelURL: url, modelToken: tok, agent: "agent-1"}
		got, err := b.Env(c.brain)
		if err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Fatalf("%s:\n got %q\nwant %q", c.provider, got, c.want)
		}
	}
	// Without a model address there is nothing to point the brain at, and it
	// does not run.
	b := &Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.Anthropic, throughIdentityAgent: true}
	if env, err := b.Env("claude-code"); err == nil {
		t.Fatalf("a brain was run with no model address: %v", env)
	}
}

// The body's model address answers only a token for a run under way: none,
// another, or one whose run has ended is refused, in the shape the brain's
// program reads.
func TestTheModelAddressAnswersOnlyARunsOwnToken(t *testing.T) {
	ts, err := newToolServer(&Host{})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.close()
	b := &Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.Anthropic, throughIdentityAgent: true}
	ts.openModel(b)
	if !strings.HasPrefix(b.modelURL, "http://127.0.0.1:") || b.modelToken == "" {
		t.Fatalf("no model address was given: %q", b.modelURL)
	}
	call := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/model/v1/messages", strings.NewReader(`{}`))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		ts.serve(w, r)
		return w
	}
	for _, tok := range []string{"", "ahm-not-this-run", b.modelToken + "x"} {
		if w := call(tok); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"type":"error"`) {
			t.Fatalf("token %q: %d %s", tok, w.Code, w.Body)
		}
	}
	if ts.modelFor(httptest.NewRequest("POST", "/model/v1/messages", nil)) != nil {
		t.Fatal("a call with no token was taken for a run")
	}
	r := httptest.NewRequest("POST", "/model/v1/messages", nil)
	r.Header.Set("X-Api-Key", b.modelToken)
	if ts.modelFor(r) != b {
		t.Fatal("a run's token in Anthropic's key header was not taken for its run")
	}
	ts.shutModel(b)
	if w := call(b.modelToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("a token whose run ended: %d %s", w.Code, w.Body)
	}
	// A tool call is not a model call: the run's model token does not open a
	// turn's tools.
	ts.openModel(b)
	tr := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"list_agents"}`))
	tr.Header.Set("Authorization", "Bearer "+b.modelToken)
	tw := httptest.NewRecorder()
	ts.serve(tw, tr)
	if tw.Code != http.StatusUnauthorized {
		t.Fatalf("a model token opened the tools: %d", tw.Code)
	}
}

// Codex ignores its user's settings, and with them any base address in its
// environment, so a key that stays with the Identity Agent has Codex told on
// its command line where its model is and which variable holds the run's
// token — never the token itself.
func TestCodexIsToldWhereItsModelIsWhenItsKeyStaysHere(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, record := fakeHomeBrain(t, "CODEX_HOME", codexAnswer, false, false)
	b := &Borrowed{Kind: brainsignin.KindAPIKey, Provider: brainsignin.OpenAI, throughIdentityAgent: true,
		modelURL: "http://127.0.0.1:4000/model", modelToken: "ahm-RUN-TOKEN", agent: "agent-1"}
	env, err := b.Env("codex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Codex{Path: path}).Run(context.Background(), Turn{Session: "s", Prompt: "hi",
		Workspace: t.TempDir(), Credentials: env}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(record)
	for _, want := range []string{"ARG:model_provider=\"agenthost\"\n",
		"ARG:model_providers.agenthost.base_url=\"http://127.0.0.1:4000/model/v1\"\n",
		"ARG:model_providers.agenthost.env_key=\"CODEX_API_KEY\"\n"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("Codex was not told %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "ahm-RUN-TOKEN") {
		t.Fatalf("the run's token went on the command line:\n%s", got)
	}
}
