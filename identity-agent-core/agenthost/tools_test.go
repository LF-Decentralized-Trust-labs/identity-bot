package agenthost

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The MCP server the brain starts lists the host's tools and forwards a call
// to the host with the turn's token, answering in MCP's own shape.
func TestTheBrainsMCPServerForwardsToTheHost(t *testing.T) {
	var got toolCall
	var auth string
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"text": "sent"})
	}))
	defer host.Close()
	t.Setenv(envToolsURL, host.URL)
	t.Setenv(envToolsToken, "turn-token")

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reply","arguments":{"text":"done"}}}`,
	}, "\n")
	var out bytes.Buffer
	if err := ServeMCP(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	var replies []map[string]any
	for {
		var m map[string]any
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		replies = append(replies, m)
	}
	if len(replies) != 3 {
		t.Fatalf("expected three answers (the notification gets none), got %d", len(replies))
	}
	tools := replies[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != len(ToolNames) {
		t.Fatalf("listed %d tools", len(tools))
	}
	if got.Name != "reply" || auth != "Bearer turn-token" || !strings.Contains(string(got.Args), "done") {
		t.Fatalf("the call was not forwarded as made: %+v %q", got, auth)
	}
	content := replies[2]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	if content["text"] != "sent" {
		t.Fatalf("the host's answer did not reach the brain: %v", content)
	}
}

// A token is good for its turn only.
func TestAToolTokenEndsWithItsTurn(t *testing.T) {
	ts, err := newToolServer(&Host{})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.close()
	tok := ts.open(&toolTurn{Conversation: "c1"})
	call := func() int {
		req, _ := http.NewRequest("POST", ts.url(), strings.NewReader(`{"name":"list_agents"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	ts.shut(tok)
	if call() != http.StatusUnauthorized {
		t.Fatal("a token was honoured after its turn ended")
	}
}

// Both brains this host runs are known by name, and nothing else is.
func TestTheHostRunsTheBrainsItNames(t *testing.T) {
	if b, _ := BrainFor("grok", nil); b.Name() != "grok" {
		t.Fatal("grok is not a brain this host runs")
	}
	if b, _ := BrainFor("claude-code", nil); b.Name() != "claude-code" {
		t.Fatal("claude-code is not a brain this host runs")
	}
	if _, err := BrainFor("something-else", nil); err == nil {
		t.Fatal("an unknown brain was accepted")
	}
}
