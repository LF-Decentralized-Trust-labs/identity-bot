package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
)

const theOpenRouterKey = "sk-or-v1-THE-KEY-THAT-STAYS-HERE"

// openRouterStandIn stands in for OpenRouter: it answers the sign-in check,
// and answers each model call with the next of its steps, streamed in
// OpenAI's chat format. It records the calls.
type openRouterStandIn struct {
	mu    sync.Mutex
	calls []map[string]any
	auth  []string
	steps []func(call map[string]any) string
}

func (o *openRouterStandIn) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+theOpenRouterKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"no such key"}}`)
			return
		}
		switch r.URL.Path {
		case "/or/v1/key":
			_, _ = io.WriteString(w, `{"data":{"label":"sk-or-v1-the...here"}}`)
			return
		case "/or/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"id":"vendor/model-a"}]}`)
			return
		case "/or/v1/chat/completions":
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var call map[string]any
		_ = json.NewDecoder(r.Body).Decode(&call)
		o.mu.Lock()
		o.calls = append(o.calls, call)
		o.auth = append(o.auth, r.Header.Get("Authorization"))
		n := len(o.calls)
		o.mu.Unlock()
		if n > len(o.steps) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, `{"error":{"message":"no more steps"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, o.steps[n-1](call))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// toolStep is a streamed answer asking for one tool.
func toolStep(id, name string, args any) string {
	b, _ := json.Marshal(args)
	a, _ := json.Marshal(string(b))
	return fmt.Sprintf(`data: {"model":"vendor/model-a","choices":[{"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]}}]}`+"\n\n"+
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"+
		`data: {"choices":[],"usage":{"prompt_tokens":900,"completion_tokens":30,"cost":0.0042}}`+"\n\n"+
		"data: [DONE]\n\n", id, name, a)
}

// An AI agent signed in with an OpenRouter key does work with agent-host's
// own loop, with no program from anybody else: the loop runs a command on its
// machine, sees what it printed, and answers with reply. Every model call
// goes through the Identity Agent, which adds the key and records it; the
// machine never holds the key, and no call names any model but the chosen
// one.
func TestAnOpenRouterKeyDoesWorkWithAgentHostsOwnLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command is a POSIX shell's")
	}
	w := signInWorld(t)
	o := &openRouterStandIn{}
	var printed string
	o.steps = []func(map[string]any) string{
		func(map[string]any) string {
			return toolStep("c1", "run_command", map[string]string{"command": "echo built > made.txt && cat made.txt"})
		},
		func(c map[string]any) string {
			b, _ := json.Marshal(c["messages"])
			printed = string(b)
			return toolStep("c2", "reply", map[string]string{"text": "I made made.txt, which says built."})
		},
	}
	srv := o.serve(t)
	w.s.brainChecker = &brainsignin.Checker{OpenRouter: srv.URL + "/or", AddressRule: loopbackAllowed}
	if code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"openrouter","secret":"`+theOpenRouterKey+`"}`); code != http.StatusOK ||
		out["sign_in"].(map[string]any)["stays_with_identity_agent"] != true {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"brain":{"kind":"api_key","provider":"openrouter","model":"vendor/model-a"}}`); code != http.StatusOK {
		t.Fatalf("choosing the model: %d %s", code, raw)
	}
	conv, _ := w.openedWith(t)
	workspace := t.TempDir()
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{Once: true, Workspace: workspace}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(workspace, "made.txt")); err != nil || string(b) != "built\n" {
		t.Fatalf("the command did not run on the machine: %q %v", b, err)
	}
	if !strings.Contains(printed, `exit status 0\nbuilt`) {
		t.Fatalf("the model was not shown what the command printed: %s", printed)
	}
	var said []string
	for _, e := range w.read(t, conv) {
		said = append(said, e.Body)
	}
	if !strings.Contains(strings.Join(said, "|"), "I made made.txt, which says built.") {
		t.Fatalf("the AI agent did not answer with reply: %q", said)
	}
	if len(o.calls) != 2 {
		t.Fatalf("the provider was called %d times, not twice", len(o.calls))
	}
	for i, c := range o.calls {
		if c["model"] != "vendor/model-a" || c["stream"] != true || o.auth[i] != "Bearer "+theOpenRouterKey {
			t.Fatalf("call %d was not the chosen model's, with the key added here: %v", i, c["model"])
		}
	}
	noFileHolds(t, workspace, theOpenRouterKey)
	noFileHolds(t, w.hostA.DataDir, theOpenRouterKey)
	rows := governanceRows(t, w, "agent.model.call")
	if len(rows) != 2 {
		t.Fatalf("%d model calls recorded", len(rows))
	}
	if said := fmt.Sprintf("%+v", rows[0]); !strings.Contains(said, "model vendor/model-a") ||
		!strings.Contains(said, "900 tokens in, 30 out") || strings.Contains(said, theOpenRouterKey) {
		t.Fatalf("the record of the call: %s", said)
	}
}
