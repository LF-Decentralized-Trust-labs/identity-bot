package agenthost

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
	"time"
)

// standInModel stands in for a model that does work: each call it is sent
// is answered by the next of its steps, as a stream, in OpenAI's chat format
// or Anthropic's. It records every call.
type standInModel struct {
	mu        sync.Mutex
	anthropic bool
	steps     []func(call map[string]any) standInStep
	paths     []string
	calls     []map[string]any
}

// standInStep is one answer: words, or tools asked for, or a refusal.
type standInStep struct {
	text   string
	tools  []chatToolCall
	status int
	why    string
}

func (m *standInModel) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call map[string]any
		_ = json.NewDecoder(r.Body).Decode(&call)
		m.mu.Lock()
		m.paths = append(m.paths, r.Method+" "+r.URL.Path)
		m.calls = append(m.calls, call)
		n := len(m.calls)
		var step standInStep
		if n <= len(m.steps) {
			step = m.steps[n-1](call)
		} else {
			step = standInStep{status: http.StatusTeapot, why: "no more steps"}
		}
		m.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer ahm-RUN" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if step.status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(step.status)
			fmt.Fprintf(w, `{"error":{"message":%q}}`, step.why)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		send := func(s string) { _, _ = io.WriteString(w, s); f.Flush() }
		if m.anthropic {
			send(`event: message_start` + "\n" + `data: {"type":"message_start","message":{"model":"stand-in","usage":{"input_tokens":100,"output_tokens":1}}}` + "\n\n")
			i := 0
			if step.text != "" {
				send(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n")
				for _, part := range halves(step.text) {
					b, _ := json.Marshal(part)
					send(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + string(b) + `}}` + "\n\n")
				}
				i++
			}
			for _, tc := range step.tools {
				send(fmt.Sprintf(`data: {"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%q,"name":%q,"input":{}}}`+"\n\n", i, tc.ID, tc.Name))
				for _, part := range halves(tc.Arguments) {
					b, _ := json.Marshal(part)
					send(fmt.Sprintf(`data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`+"\n\n", i, b))
				}
				i++
			}
			stop := "end_turn"
			if len(step.tools) > 0 {
				stop = "tool_use"
			}
			send(`data: {"type":"message_delta","delta":{"stop_reason":"` + stop + `"},"usage":{"output_tokens":20}}` + "\n\n")
			send(`data: {"type":"message_stop"}` + "\n\n")
			return
		}
		send(": OPENROUTER PROCESSING\n\n")
		for _, part := range halves(step.text) {
			b, _ := json.Marshal(part)
			send(`data: {"model":"stand-in","choices":[{"delta":{"content":` + string(b) + `}}]}` + "\n\n")
		}
		for i, tc := range step.tools {
			parts := halves(tc.Arguments)
			send(fmt.Sprintf(`data: {"choices":[{"delta":{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":""}}]}}]}`+"\n\n", i, tc.ID, tc.Name))
			for _, part := range parts {
				b, _ := json.Marshal(part)
				send(fmt.Sprintf(`data: {"choices":[{"delta":{"tool_calls":[{"index":%d,"function":{"arguments":%s}}]}}]}`+"\n\n", i, b))
			}
		}
		finish := "stop"
		if len(step.tools) > 0 {
			finish = "tool_calls"
		}
		send(`data: {"choices":[{"delta":{},"finish_reason":"` + finish + `"}]}` + "\n\n")
		send(`data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20}}` + "\n\n")
		send("data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// halves is s in two parts, as a stream may split it.
func halves(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s[:len(s)/2], s[len(s)/2:]}
}

func (m *standInModel) seen() ([]string, []map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.paths...), append([]map[string]any(nil), m.calls...)
}

// standInHost stands in for the host's tool server, and records the replies.
type standInHost struct {
	mu      sync.Mutex
	replies []string
}

func (h *standInHost) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer TOOLS" {
			http.Error(w, "this turn has ended", http.StatusUnauthorized)
			return
		}
		var c toolCall
		_ = json.NewDecoder(r.Body).Decode(&c)
		var a struct{ Text string }
		_ = json.Unmarshal(c.Args, &a)
		w.Header().Set("Content-Type", "application/json")
		switch c.Name {
		case "reply":
			h.mu.Lock()
			h.replies = append(h.replies, a.Text)
			h.mu.Unlock()
			_, _ = io.WriteString(w, `{"text":"Sent. That answers the one who asked you; end your turn now."}`)
		default:
			_, _ = io.WriteString(w, `{"text":"`+c.Name+` is not stood in for","is_error":true}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestLoop(t *testing.T, m *standInModel, h *standInHost) *loop {
	t.Helper()
	api := "openai"
	if m.anthropic {
		api = "anthropic"
	}
	return &loop{model: chatClient{URL: m.serve(t).URL, Token: "ahm-RUN", API: api},
		tools: hostTools{URL: h.serve(t).URL, Token: "TOOLS"}, dir: t.TempDir(),
		pause: func(time.Duration) <-chan time.Time { return time.After(0) }}
}

// toolResult is what the latest call says a tool gave, by the tool call's id,
// in either format.
func toolResult(call map[string]any, id string) string {
	msgs, _ := call["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if mm["tool_call_id"] == id {
			s, _ := mm["content"].(string)
			return s
		}
		blocks, _ := mm["content"].([]any)
		for _, b := range blocks {
			bb, _ := b.(map[string]any)
			if bb["type"] == "tool_result" && bb["tool_use_id"] == id {
				s, _ := bb["content"].(string)
				return s
			}
		}
	}
	return ""
}

func call(id, name string, args any) chatToolCall {
	b, _ := json.Marshal(args)
	return chatToolCall{ID: id, Name: name, Arguments: string(b)}
}

// agent-host's own loop does work: it writes a file, changes it, runs a
// command over it, searches for it, and answers with reply — each step the
// model's, each tool's result handed back before the next. Every call names
// the chosen model, at the one address an answer comes from, and none is made
// after the reply.
func TestTheLoopDoesWorkStepByStepWithItsTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command is a POSIX shell's")
	}
	for _, anthropic := range []bool{false, true} {
		t.Run(map[bool]string{false: "openai", true: "anthropic"}[anthropic], func(t *testing.T) {
			var ran string
			m := &standInModel{anthropic: anthropic}
			m.steps = []func(map[string]any) standInStep{
				func(map[string]any) standInStep {
					return standInStep{text: "I'll start.", tools: []chatToolCall{
						call("c1", "write_file", map[string]string{"path": "notes/hello.txt", "content": "draft one\n"})}}
				},
				func(c map[string]any) standInStep {
					if !strings.Contains(toolResult(c, "c1"), "Wrote 10 bytes") {
						return standInStep{status: 418, why: "the write was not handed back: " + toolResult(c, "c1")}
					}
					return standInStep{tools: []chatToolCall{
						call("c2", "replace_in_file", map[string]string{"path": "notes/hello.txt", "old_text": "draft", "new_text": "final"}),
						call("c3", "run_command", map[string]string{"command": "cat notes/hello.txt; echo exit-was-$?"})}}
				},
				func(c map[string]any) standInStep {
					ran = toolResult(c, "c3")
					return standInStep{tools: []chatToolCall{call("c4", "search_files", map[string]string{"regex": "^final"})}}
				},
				func(c map[string]any) standInStep {
					if !strings.Contains(toolResult(c, "c4"), "notes/hello.txt:1: final one") {
						return standInStep{status: 418, why: "the search was not handed back: " + toolResult(c, "c4")}
					}
					return standInStep{tools: []chatToolCall{call("c5", "reply", map[string]string{"text": "Done: final one."})}}
				},
			}
			h := &standInHost{}
			l := newTestLoop(t, m, h)
			res, err := l.run(context.Background(), loopTurn{Session: "s-1", Prompt: "Write the note.",
				Instructions: "You are Builder.", Model: "vendor/model-a"})
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(filepath.Join(l.dir, "notes", "hello.txt")); string(b) != "final one\n" {
				t.Fatalf("the file holds %q", b)
			}
			if !strings.Contains(ran, "exit status 0") || !strings.Contains(ran, "final one") || !strings.Contains(ran, "exit-was-0") {
				t.Fatalf("the command's output was not handed back: %q", ran)
			}
			if len(h.replies) != 1 || h.replies[0] != "Done: final one." {
				t.Fatalf("replies: %q", h.replies)
			}
			paths, calls := m.seen()
			if len(calls) != 4 || res.Calls != 4 {
				t.Fatalf("%d calls made, %d counted; no call should follow the reply", len(calls), res.Calls)
			}
			want := "POST /v1/chat/completions"
			if anthropic {
				want = "POST /v1/messages"
			}
			for i, c := range calls {
				if paths[i] != want || c["model"] != "vendor/model-a" || c["stream"] != true {
					t.Fatalf("call %d: %s %v %v", i, paths[i], c["model"], c["stream"])
				}
			}
			if res.TokensIn != 400 || res.TokensOut != 80 {
				t.Fatalf("what the calls used was not counted: %+v", res)
			}
			// The conversation is kept whole for the next turn.
			b, err := os.ReadFile(filepath.Join(l.dir, loopDir, "s-1.json"))
			if err != nil {
				t.Fatal(err)
			}
			var kept []chatMessage
			if err := json.Unmarshal(b, &kept); err != nil || len(whole(kept)) != len(kept) || len(kept) != 10 {
				t.Fatalf("kept %d messages (%v): %s", len(kept), err, b)
			}
		})
	}
}

// A turn that resumes its session carries on from what was done, and what a
// tool gave is sent again as it was first given.
func TestTheNextTurnCarriesOnFromTheLast(t *testing.T) {
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(map[string]any) standInStep {
			return standInStep{tools: []chatToolCall{call("c1", "list_files", map[string]string{})}}
		},
		func(map[string]any) standInStep { return standInStep{text: "Nothing here yet."} },
		func(c map[string]any) standInStep {
			b, _ := json.Marshal(c["messages"])
			if !strings.Contains(string(b), "(no files)") || !strings.Contains(string(b), "Nothing here yet.") ||
				!strings.Contains(string(b), "And now?") {
				return standInStep{status: 418, why: "the conversation did not carry on: " + string(b)}
			}
			return standInStep{text: "Still nothing."}
		},
	}
	l := newTestLoop(t, m, &standInHost{})
	if res, err := l.run(context.Background(), loopTurn{Session: "s", Prompt: "What is here?", Model: "m"}); err != nil ||
		res.Text != "Nothing here yet." {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err := l.run(context.Background(), loopTurn{Session: "s", Resume: true, Prompt: "And now?", Model: "m"}); err != nil ||
		res.Text != "Still nothing." {
		t.Fatalf("%+v %v", res, err)
	}
}

// A call refused because the provider was busy is made again; one refused
// for any other reason is not.
func TestABusyProviderIsAskedAgainAndARefusalIsNot(t *testing.T) {
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(map[string]any) standInStep { return standInStep{status: 503, why: "busy"} },
		func(map[string]any) standInStep { return standInStep{status: 429, why: "slow down"} },
		func(map[string]any) standInStep { return standInStep{text: "There."} },
		func(map[string]any) standInStep {
			return standInStep{status: 400, why: "this model does not take tools"}
		},
	}
	l := newTestLoop(t, m, &standInHost{})
	if res, err := l.run(context.Background(), loopTurn{Session: "a", Prompt: "hi", Model: "m"}); err != nil || res.Text != "There." {
		t.Fatalf("%+v %v", res, err)
	}
	_, err := l.run(context.Background(), loopTurn{Session: "b", Prompt: "hi", Model: "m"})
	if err == nil || !strings.Contains(err.Error(), "does not take tools") {
		t.Fatalf("a refusal: %v", err)
	}
	if _, calls := m.seen(); len(calls) != 4 {
		t.Fatalf("%d calls; a refusal was made again", len(calls))
	}
}

// A turn makes at most loopCallsMost model calls; past that it stops, and
// says so as its answer.
func TestATurnStopsAtItsLimitOfCalls(t *testing.T) {
	m := &standInModel{}
	for i := 0; i < loopCallsMost+5; i++ {
		id := fmt.Sprint("c", i)
		m.steps = append(m.steps, func(map[string]any) standInStep {
			return standInStep{text: "Still looking.", tools: []chatToolCall{call(id, "list_files", map[string]string{})}}
		})
	}
	l := newTestLoop(t, m, &standInHost{})
	res, err := l.run(context.Background(), loopTurn{Session: "s", Prompt: "Look forever.", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, calls := m.seen(); len(calls) != loopCallsMost {
		t.Fatalf("%d calls made, more than %d", len(calls), loopCallsMost)
	}
	if !strings.Contains(res.Text, "Still looking.") || !strings.Contains(res.Text, "limit of 60 model calls") {
		t.Fatalf("the answer does not say why it stopped: %q", res.Text)
	}
}

// A provider that says the conversation is too long is sent less of it, and
// the model is told the oldest part was let go.
func TestAConversationTooLongIsCutAndTheModelIsTold(t *testing.T) {
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(c map[string]any) standInStep {
			if b, _ := json.Marshal(c["messages"]); !strings.Contains(string(b), "OLDEST") {
				return standInStep{status: 418, why: "a conversation that fits was cut before the provider refused it"}
			}
			return standInStep{status: 400, why: "This model's maximum context length is 8192 tokens"}
		},
		func(c map[string]any) standInStep {
			b, _ := json.Marshal(c["messages"])
			if strings.Contains(string(b), "OLDEST") || !strings.Contains(string(b), "let go") {
				return standInStep{status: 418, why: "the oldest part was sent, or the model was not told: " + string(b)}
			}
			return standInStep{text: "Fits now."}
		},
	}
	l := newTestLoop(t, m, &standInHost{})
	big := strings.Repeat("x", loopConversationLargest/3)
	old := []chatMessage{{Role: "user", Content: "OLDEST " + big}, {Role: "assistant", Content: "ok"},
		{Role: "user", Content: "older " + big}, {Role: "assistant", Content: "ok"}}
	b, _ := json.Marshal(old)
	p, _ := loopHistory(l.dir, "s")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, b, 0o600)
	res, err := l.run(context.Background(), loopTurn{Session: "s", Resume: true, Prompt: "and now", Model: "m"})
	if err != nil || res.Text != "Fits now." || !res.LetGo {
		t.Fatalf("%+v %v", res, err)
	}
}

// The conversation kept is always whole: a request for a tool with no answer
// to it is let go, as every API refuses it.
func TestOnlyAWholeConversationIsKept(t *testing.T) {
	h := []chatMessage{{Role: "user", Content: "a"}, {Role: "assistant", ToolCalls: []chatToolCall{{ID: "1", Name: "x"}}},
		{Role: "tool", ToolCallID: "1", Content: "r"}, {Role: "assistant", Content: "done"},
		{Role: "user", Content: "b"}, {Role: "assistant", ToolCalls: []chatToolCall{{ID: "2", Name: "x"}, {ID: "3", Name: "y"}}},
		{Role: "tool", ToolCallID: "2", Content: "r"}}
	got := whole(h)
	if len(got) != 5 || got[4].Content != "b" {
		t.Fatalf("kept %+v", got)
	}
	if got := whole([]chatMessage{{Role: "tool", ToolCallID: "9"}, {Role: "user", Content: "a"}}); len(got) != 1 {
		t.Fatalf("an answer with no request was kept: %+v", got)
	}
}

// The oldest exchanges are let go whole, from something asked; and within
// one exchange too large alone, its oldest steps, keeping what was asked.
func TestALongConversationLetsItsOldestPartGoWhole(t *testing.T) {
	big := strings.Repeat("y", 1000)
	h := []chatMessage{{Role: "user", Content: "first " + big}, {Role: "assistant", Content: big},
		{Role: "user", Content: "second"}, {Role: "assistant", Content: "ok"}}
	got, letGo := fitted(h, 1500)
	if !letGo || len(got) != 2 || got[0].Content != "second" {
		t.Fatalf("got %+v", got)
	}
	if got, letGo := fitted(h, 1<<20); letGo || len(got) != 4 {
		t.Fatalf("a conversation that fits was cut: %+v", got)
	}
	steps := []chatMessage{{Role: "user", Content: "do it"}}
	for i := 0; i < 6; i++ {
		id := fmt.Sprint(i)
		steps = append(steps, chatMessage{Role: "assistant", ToolCalls: []chatToolCall{{ID: id, Name: "x"}}},
			chatMessage{Role: "tool", ToolCallID: id, Content: big})
	}
	got, letGo = fitted(steps, 3000)
	if !letGo || got[0].Content != "do it" || got[1].Role != "assistant" || len(whole(got)) != len(got) ||
		got[len(got)-1].ToolCallID != "5" {
		t.Fatalf("got %d messages: %+v", len(got), got)
	}
}

// The tools refuse the loop's own conversations, a file that is not regular,
// binary data, and an edit that is not exact.
func TestTheToolsRefuseWhatTheyShouldNotTouch(t *testing.T) {
	dir := t.TempDir()
	w := workTools{dir: dir}
	use := func(name string, args any) (string, error) {
		b, _ := json.Marshal(args)
		return w.use(context.Background(), name, b)
	}
	if _, err := use("write_file", map[string]string{"path": loopDir + "/s.json", "content": "[]"}); err == nil {
		t.Error("the loop's own conversation was written by a tool")
	}
	if _, err := use("read_file", map[string]string{"path": filepath.Join(dir, loopDir, "..", loopDir, "s.json")}); err == nil {
		t.Error("the loop's own conversation was read by a tool")
	}
	_ = os.WriteFile(filepath.Join(dir, "b.bin"), []byte("a\x00b"), 0o644)
	if _, err := use("read_file", map[string]string{"path": "b.bin"}); err == nil {
		t.Error("binary data was read as text")
	}
	if _, err := use("read_file", map[string]string{"path": "."}); err == nil {
		t.Error("a folder was read as a file")
	}
	_ = os.WriteFile(filepath.Join(dir, "t.txt"), []byte("one one\n"), 0o644)
	if _, err := use("replace_in_file", map[string]string{"path": "t.txt", "old_text": "one", "new_text": "two"}); err == nil ||
		!strings.Contains(err.Error(), "2 times") {
		t.Errorf("an edit that was not exact: %v", err)
	}
	if out, err := use("read_file", map[string]any{"path": "t.txt"}); err != nil || !strings.Contains(out, "     1\tone one") {
		t.Errorf("read: %q %v", out, err)
	}
	if out, err := use("search_files", map[string]string{"regex": "one", "pattern": "*.bin"}); err != nil || out != "(nothing matches)" {
		t.Errorf("binary data was searched: %q %v", out, err)
	}
}

// A command runs without what only the loop uses, with nothing to answer a
// prompt, and ends with everything it started, even what it left running.
func TestACommandRunsAloneAndLeavesNothingBehind(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command is a POSIX shell's")
	}
	t.Setenv(envDirectToken, "ahm-SECRET")
	t.Setenv(envToolsToken, "TOOLS-SECRET")
	dir := t.TempDir()
	w := workTools{dir: dir}
	out, err := w.run(context.Background(), "env; echo prompt=$GIT_TERMINAL_PROMPT", 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "SECRET") || !strings.Contains(out, "prompt=0") {
		t.Fatalf("the command's environment: %s", out)
	}
	marker := filepath.Join(dir, "left-running")
	start := time.Now()
	out, err = w.run(context.Background(), "(sleep 3; touch "+marker+") & echo started", 0)
	if err != nil || !strings.Contains(out, "started") {
		t.Fatalf("%q %v", out, err)
	}
	if time.Since(start) > 2900*time.Millisecond {
		t.Fatalf("a command waited on what it left running: %s", time.Since(start))
	}
	out, err = w.run(context.Background(), "sleep 30", 1)
	if err != nil || !strings.Contains(out, "stopped after 1s") {
		t.Fatalf("a command that ran out of time: %q %v", out, err)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("what a command left running was not ended with it")
	}
}

// The host runs the loop as a program of its own; a turn that runs out of
// time asks it to stop, and the command under way ends with everything it
// started, before it could finish.
func TestATurnOutOfTimeEndsTheLoopAndItsCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command is a POSIX shell's")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "finished")
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(map[string]any) standInStep {
			return standInStep{tools: []chatToolCall{call("c1", "run_command",
				map[string]string{"command": "sleep 4; touch " + marker})}}
		},
	}
	srv := m.serve(t)
	h := (&standInHost{}).serve(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := BuiltIn{}.Run(ctx, Turn{Session: "s", Prompt: "wait", Model: "m", Workspace: dir,
		ToolsURL: h.URL, ToolsToken: "TOOLS",
		Credentials: []string{envDirectURL + "=" + srv.URL, envDirectToken + "=ahm-RUN", envDirectAPI + "=openai"}})
	if err == nil {
		t.Fatal("a turn out of time finished")
	}
	if time.Since(start) > 3500*time.Millisecond {
		t.Fatalf("the loop took %s to stop", time.Since(start))
	}
	time.Sleep(4 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command went on after its turn ended")
	}
	if _, err := os.Stat(filepath.Join(dir, loopDir, "s.json")); err != nil {
		t.Fatalf("the conversation was not kept: %v", err)
	}
}

// A provider that asks to be left longer than the loop may wait is not asked
// again in the turn.
func TestAProviderAskingForALongWaitIsNotAskedAgain(t *testing.T) {
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(map[string]any) standInStep { return standInStep{status: 429, why: "come back in five minutes"} },
		func(map[string]any) standInStep { return standInStep{text: "too soon"} },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "300")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"come back in five minutes"}}`)
	}))
	defer srv.Close()
	l := newTestLoop(t, m, &standInHost{})
	l.model.URL = srv.URL
	waited := 0
	l.pause = func(time.Duration) <-chan time.Time { waited++; return time.After(0) }
	_, err := l.run(context.Background(), loopTurn{Session: "s", Prompt: "hi", Model: "m"})
	if err == nil || waited != 0 {
		t.Fatalf("asked again %d times: %v", waited, err)
	}
}

// The conversation's folder is refused through a link to it, even for a file
// not made yet, and whatever the case of its name where the file system
// ignores case.
func TestTheConversationIsRefusedThroughALinkOrAnotherCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, loopDir), 0o700)
	if err := os.Symlink(loopDir, filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}
	w := workTools{dir: dir}
	b, _ := json.Marshal(map[string]string{"path": "evil/s.json", "content": "[]"})
	if _, err := w.use(context.Background(), "write_file", b); err == nil {
		t.Fatal("the conversation was written through a link to its folder")
	}
	if runtime.GOOS == "darwin" {
		b, _ := json.Marshal(map[string]string{"path": strings.ToUpper(loopDir) + "/s.json", "content": "[]"})
		if _, err := w.use(context.Background(), "write_file", b); err == nil {
			t.Fatal("the conversation was written under its folder's name in capitals")
		}
	}
}

// Only one answer to each of a step's own requests is kept: an answer to
// something it did not ask would be refused by the next call.
func TestAnAnswerToNothingAskedIsNotKept(t *testing.T) {
	h := []chatMessage{{Role: "user", Content: "a"}, {Role: "assistant", ToolCalls: []chatToolCall{{ID: "1", Name: "x"}}},
		{Role: "tool", ToolCallID: "1", Content: "r"}, {Role: "tool", ToolCallID: "9", Content: "stray"},
		{Role: "tool", ToolCallID: "1", Content: "again"}}
	got := whole(h)
	if len(got) != 3 || got[2].Content != "r" {
		t.Fatalf("kept %+v", got)
	}
}

// A search stops when its turn is asked to stop.
func TestASearchStopsWhenItsTurnDoes(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x\n"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (workTools{dir: dir}).search(ctx, ".", "x", ""); err == nil {
		t.Fatal("a search went on after its turn ended")
	}
}

// A conversation file larger than the loop ever keeps is not read.
func TestAConversationTooLargeToHaveBeenKeptIsNotRead(t *testing.T) {
	l := newTestLoop(t, &standInModel{}, &standInHost{})
	p, _ := loopHistory(l.dir, "s")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, make([]byte, 2*loopKeptLargest), 0o600)
	if _, err := l.run(context.Background(), loopTurn{Session: "s", Resume: true, Prompt: "hi", Model: "m"}); err == nil ||
		!strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
}

// A provider that says nothing of what a call used is still counted, so the
// turn's bound on tokens holds; and what was replied is the turn's words.
func TestACallWithNoUsageIsStillCountedAndTheReplyIsTheAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"m","choices":[{"message":{"content":"","tool_calls":[{"id":"r1",`+
			`"function":{"name":"reply","arguments":"{\"text\":\"the answer\"}"}}]},"finish_reason":"tool_calls"}]}`)
	}))
	defer srv.Close()
	l := newTestLoop(t, &standInModel{}, &standInHost{})
	l.model.URL = srv.URL
	res, err := l.run(context.Background(), loopTurn{Session: "s", Prompt: strings.Repeat("p", 4000), Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if res.TokensIn < 1000 || res.TokensOut == 0 || res.Text != "the answer" {
		t.Fatalf("%+v", res)
	}
}

// A turn that ends while waiting to ask again says it ran out of time, not
// that the model refused.
func TestATurnEndingWhileWaitingSaysSo(t *testing.T) {
	m := &standInModel{}
	m.steps = []func(map[string]any) standInStep{
		func(map[string]any) standInStep { return standInStep{status: 503, why: "busy"} },
	}
	l := newTestLoop(t, m, &standInHost{})
	ctx, cancel := context.WithCancel(context.Background())
	l.pause = func(time.Duration) <-chan time.Time { cancel(); return make(chan time.Time) }
	_, err := l.run(ctx, loopTurn{Session: "s", Prompt: "hi", Model: "m"})
	if err == nil || strings.Contains(err.Error(), "busy") {
		t.Fatalf("%v", err)
	}
}

// What a turn is asked is sent whole with every call, so one larger than the
// loop sends a model is refused before any call is made.
func TestATurnAskedMoreThanTheLoopSendsIsRefused(t *testing.T) {
	m := &standInModel{}
	l := newTestLoop(t, m, &standInHost{})
	_, err := l.run(context.Background(), loopTurn{Session: "s", Prompt: strings.Repeat("p", loopConversationLargest), Model: "m"})
	if _, calls := m.seen(); err == nil || len(calls) != 0 {
		t.Fatalf("%d calls: %v", len(calls), err)
	}
}

// Ids Anthropic would refuse are replaced, and two that differ only in such
// characters stay apart.
func TestToolCallIdsAreMadeFitForAnthropicWithoutColliding(t *testing.T) {
	a, b := anthropicID("functions.read:0"), anthropicID("functions_read_0")
	if a == b || b != "functions_read_0" || strings.ContainsAny(a, ".:") {
		t.Fatalf("%q %q", a, b)
	}
}

// Every call agent-host makes says how long an answer it wants, as each API
// names it, so an Identity Agent capping what a run spends can bound each
// call (ADR-057): OpenAI's own API as max_completion_tokens, which its
// reasoning models require, xAI and OpenRouter as max_tokens, Anthropic as
// max_tokens.
func TestEveryModelCallSaysHowLongAnAnswerItWants(t *testing.T) {
	for api, key := range map[string]string{"openai": "max_completion_tokens", "openrouter": "max_tokens",
		"xai": "max_tokens", "anthropic": "max_tokens"} {
		for _, asked := range []int{0, loopAnswerLongest} {
			var req map[string]any
			if err := json.Unmarshal(chatClient{API: api}.body(chatRequest{Model: "m", MaxTokens: asked}), &req); err != nil {
				t.Fatal(err)
			}
			want := float64(asked)
			if asked == 0 {
				want = chatMaxTokens
			}
			if req[key] != want {
				t.Fatalf("%s, asking %d: %s is %v in %v", api, asked, key, req[key], req)
			}
			for _, other := range []string{"max_tokens", "max_completion_tokens"} {
				if other != key && req[other] != nil {
					t.Fatalf("%s names the answer's length twice: %v", api, req)
				}
			}
		}
	}
}
