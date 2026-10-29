package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/brainsignin"
)

// The models a key may call are listed through the Identity Agent, before the
// key is kept and once it is, so a person chooses one from what the provider
// offers. The key goes to the provider alone and is in no answer.
func TestABrainsModelsAreListedToChooseFrom(t *testing.T) {
	const key = "sk-or-v1-THE-KEY-THAT-STAYS-HERE"
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path+" "+r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/or/v1/key":
			_, _ = rw.Write([]byte(`{"data":{"label":"sk-or-v1-abc...xyz"}}`))
		case "/or/v1/models":
			_, _ = rw.Write([]byte(`{"data":[{"id":"anthropic/claude-haiku-4.5","name":"Anthropic: Claude Haiku 4.5",` +
				`"context_length":200000,"pricing":{"prompt":"0.000001","completion":"0.000005"}}]}`))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	w := signInWorld(t)
	w.s.brainChecker = &brainsignin.Checker{OpenRouter: srv.URL + "/or", AddressRule: loopbackAllowed}
	signIn := `{"kind":"api_key","provider":"openrouter","secret":"` + key + `"}`

	code, out, raw := w.asOwner(t, "POST", "/api/mcp/brain-sign-in/models", signIn)
	if code != http.StatusOK || strings.Contains(raw, key) {
		t.Fatalf("listing before the key is kept: %d %s", code, raw)
	}
	models, _ := out["models"].([]any)
	if len(models) != 1 {
		t.Fatalf("the list: %s", raw)
	}
	m := models[0].(map[string]any)
	if m["id"] != "anthropic/claude-haiku-4.5" || m["context_length"] != float64(200000) || m["prompt_price"] != "0.000001" {
		t.Fatalf("the model: %v", m)
	}

	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in/models", ""); code != http.StatusNotFound {
		t.Fatalf("listing for an AI agent with no sign-in: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", signIn); code != http.StatusOK {
		t.Fatalf("keeping the key: %d %s", code, raw)
	}
	code, out, raw = w.asOwner(t, "POST", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in/models", "")
	if code != http.StatusOK || strings.Contains(raw, key) || len(out["models"].([]any)) != 1 {
		t.Fatalf("listing the kept key's models: %d %s", code, raw)
	}
	for _, a := range asked {
		if !strings.HasSuffix(a, "Bearer "+key) {
			t.Fatalf("the provider was asked without the key, or with another: %v", asked)
		}
	}
}

// Choosing another model for an AI agent, or what runs it, changes that and
// nothing else of its configuration; a program that does not fit its sign-in
// is refused, and the choice is recorded.
func TestChoosingAnAIAgentsModelChangesOnlyThat(t *testing.T) {
	w := signInWorld(t)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"role":"Reviews code","system_prompt":"Be brief.","brain":{"kind":"api_key","provider":"openrouter","model":"z-ai/glm-5"},"machine":{"provides":["toolchain"]}}`); code != http.StatusOK {
		t.Fatalf("setting it up: %d %s", code, raw)
	}
	code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"model":"anthropic/claude-haiku-4.5"}`)
	if code != http.StatusOK {
		t.Fatalf("choosing the model: %d %s", code, raw)
	}
	cfg := out["agent_config"].(map[string]any)
	brain := cfg["brain"].(map[string]any)
	if brain["model"] != "anthropic/claude-haiku-4.5" || brain["provider"] != "openrouter" || brain["kind"] != "api_key" ||
		cfg["role"] != "Reviews code" || cfg["system_prompt"] != "Be brief." || !strings.Contains(raw, "toolchain") {
		t.Fatalf("more than the model changed: %s", raw)
	}
	a, _ := w.s.aiAgentAsset(w.a.ID)
	if a.AgentConfig.Brain.Model != "anthropic/claude-haiku-4.5" || a.AgentConfig.Role != "Reviews code" {
		t.Fatalf("not kept: %+v", a.AgentConfig)
	}
	// With a key kept, only reads and answers; then a change of model alone
	// keeps that, and a program that is no program's name is refused.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"openrouter","secret":"sk-or-v1-a-key"}`); code != http.StatusOK {
		t.Fatalf("keeping a key: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"program":"none"}`); code != http.StatusOK {
		t.Fatalf("only reading and answering: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"model":"z-ai/glm-5"}`); code != http.StatusOK {
		t.Fatalf("changing only the model: %d %s", code, raw)
	}
	if a, _ := w.s.aiAgentAsset(w.a.ID); a.AgentConfig.Brain.Program != "none" || a.AgentConfig.Brain.Model != "z-ai/glm-5" {
		t.Fatalf("a change of model alone changed what runs it: %+v", a.AgentConfig.Brain)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain",
		`{"program":"`+strings.Repeat("x", 41)+`"}`); code != http.StatusBadRequest {
		t.Fatalf("a program name of 41 characters was kept: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"program":""}`); code != http.StatusOK {
		t.Fatalf("running its provider's program again: %d %s", code, raw)
	}
	// A subscription cannot only read and answer.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"subscription","provider":"claude-code","secret":"sk-ant-oat01-a-subscription"}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"program":"none"}`); code != http.StatusBadRequest {
		t.Fatalf("a program that does not fit the sign-in was chosen: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain", `{"model":"two\nlines"}`); code != http.StatusBadRequest {
		t.Fatalf("a model name of two lines was kept: %d %s", code, raw)
	}
	// Signed in with a Claude subscription, it cannot be said to think with another AI.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain",
		`{"kind":"api_key","provider":"openai","model":"gpt-5"}`); code != http.StatusBadRequest ||
		!strings.Contains(raw, "signed in with subscription claude-code") {
		t.Fatalf("a choice of another AI than its sign-in was kept: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain",
		`{"kind":"subscription","provider":"claude-code","model":"claude-sonnet-4-5"}`); code != http.StatusOK {
		t.Fatalf("a choice matching its sign-in was refused: %d %s", code, raw)
	}
	chosen := 0
	for _, r := range governanceRows(t, w, "agent.brain.chosen") {
		if strings.Contains(fmt.Sprintf("%+v", r), "model z-ai/glm-5, run by none") {
			chosen++
		}
	}
	if chosen != 1 {
		t.Fatalf("the change of model alone was recorded %d times", chosen)
	}
}
