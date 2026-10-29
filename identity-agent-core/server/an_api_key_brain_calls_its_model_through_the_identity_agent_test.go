package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
	"identity-agent-core/brainsignin"
)

const theOrganisationsKey = "sk-ant-api03-THE-KEY-THAT-STAYS-HERE"

// modelProvider stands in for a model's provider. It answers a model call as
// a stream, in parts, and records what it was sent.
type modelProvider struct {
	mu     sync.Mutex
	seen   []http.Header
	bodies []string
	// hold, when set, keeps the answer open after its first part until it is
	// closed.
	hold chan struct{}
	// cancelled is closed when a held answer's call is given up by the
	// Identity Agent.
	cancelled     chan struct{}
	cancelledOnce sync.Once
	// keyAnswer is what it says the key is.
	keyAnswer string
}

func (p *modelProvider) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.Header.Clone())
		hold := p.hold
		p.mu.Unlock()
		if r.URL.Path == "/x/v1/api-key" && r.Header.Get("Authorization") == "Bearer "+theOrganisationsKey {
			_, _ = io.WriteString(rw, p.keyAnswer)
			return
		}
		if r.Header.Get("x-api-key") != theOrganisationsKey {
			rw.WriteHeader(http.StatusUnauthorized)
			_, _ = rw.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
			return
		}
		if r.URL.Path != "/a/v1/messages" {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.bodies = append(p.bodies, string(body))
		p.mu.Unlock()
		if !strings.Contains(string(body), `"stream":true`) {
			rw.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(rw, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-stand-in",`+
				`"content":[{"type":"text","text":"Answered without a program"}],"stop_reason":"end_turn",`+
				`"usage":{"input_tokens":12,"output_tokens":4}}`)
			return
		}
		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Request-Id", "req_stand_in")
		rw.WriteHeader(http.StatusOK)
		f := rw.(http.Flusher)
		parts := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-stand-in\",\"usage\":{\"input_tokens\":120,\"cache_read_input_tokens\":30,\"output_tokens\":1}}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello \"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"from the model\"}}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for i, part := range parts {
			_, _ = io.WriteString(rw, part)
			f.Flush()
			if i == 0 && hold != nil {
				select {
				case <-hold:
				case <-r.Context().Done():
					p.cancelledOnce.Do(func() { close(p.cancelled) })
					return
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (p *modelProvider) calls() []http.Header {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]http.Header(nil), p.seen...)
}

// keyWorld is a sign-in world whose first AI agent's brain is an Anthropic key
// kept in the vault, with its provider stood in for.
func keyWorld(t *testing.T) (*talkWorld, *modelProvider) {
	t.Helper()
	w := signInWorld(t)
	p := &modelProvider{cancelled: make(chan struct{})}
	srv := p.serve(t)
	w.s.brainChecker = &brainsignin.Checker{Anthropic: srv.URL + "/a", OpenAI: srv.URL + "/oa", XAI: srv.URL + "/x",
		OpenRouter: srv.URL + "/or", AddressRule: loopbackAllowed}
	if code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"anthropic","account":"Engineering key","secret":"`+theOrganisationsKey+`"}`); code != http.StatusOK ||
		out["sign_in"].(map[string]any)["stays_with_identity_agent"] != true {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	return w, p
}

// startModelCall makes a model call as a body does, citing lease.
func startModelCall(t *testing.T, h *agenthost.Host, lease, path string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"lease_id": lease, "method": "POST", "path": path,
		"header":   map[string]string{"Content-Type": "application/json", "Anthropic-Version": "2023-06-01"},
		"body_b64": base64.StdEncoding.EncodeToString([]byte(`{"model":"claude-stand-in","stream":true,"messages":[]}`))})
	code, out, err := h.CallContext(context.Background(), "POST", "/api/agent-host/model-calls", body)
	if err != nil {
		// Refused before the envelope was opened: a revoked AI agent's body is
		// no longer admitted at all.
		return http.StatusForbidden, map[string]any{"error": err.Error()}
	}
	var a map[string]any
	_ = json.Unmarshal(out, &a)
	return code, a
}

// collectAll collects a call's answer to its end, as a body does.
func collectAll(t *testing.T, h *agenthost.Host, first map[string]any) string {
	t.Helper()
	var got strings.Builder
	a := first
	for i := 0; ; i++ {
		if d, _ := a["data_b64"].(string); d != "" {
			b, _ := base64.StdEncoding.DecodeString(d)
			got.Write(b)
		}
		if a["done"] == true {
			return got.String()
		}
		if i > 50 {
			t.Fatal("the answer never ended")
		}
		code, out, err := h.CallContext(context.Background(), "GET",
			fmt.Sprintf("/api/agent-host/model-calls/%s?from=%d&head=1", a["call_id"], int64(a["next"].(float64))), nil)
		if err != nil || code != http.StatusOK {
			t.Fatalf("collecting: %d %s %v", code, out, err)
		}
		a = map[string]any{}
		_ = json.Unmarshal(out, &a)
	}
}

// fakeBrainCallingItsModel is a stand-in for Claude Code that makes one
// streaming model call at the address its environment names, with the token
// it names, and records its environment, its arguments and the answer.
func fakeBrainCallingItsModel(t *testing.T) (path, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is not installed")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "claude")
	script := "#!/bin/sh\ncat >/dev/null\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\" >> " + record + "; done\n" +
		"env | sed 's/^/ENV:/' >> " + record + "\n" +
		curl + " -sN -H \"Authorization: Bearer $ANTHROPIC_AUTH_TOKEN\" -H 'content-type: application/json' " +
		"-H 'anthropic-version: 2023-06-01' -d '{\"model\":\"claude-stand-in\",\"stream\":true,\"messages\":[]}' " +
		"\"$ANTHROPIC_BASE_URL/v1/messages\" | sed 's/^/ANSWER:/' >> " + record + "\n" +
		"echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"done\",\"session_id\":\"s\",\"modelUsage\":{}}'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

// An API key kept in the vault is never lent to a body. The brain is pointed
// at its body's model address with a token for its run, and its model call
// reaches the provider through the Identity Agent, which adds the key; the
// answer streams back to the brain. The key is in no part of what the brain
// or its machine was given, and the call is recorded with what it used.
func TestAnAPIKeyBrainCallsItsModelThroughTheIdentityAgent(t *testing.T) {
	w, p := keyWorld(t)
	w.openedWith(t)
	path, record := fakeBrainCallingItsModel(t)
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
	if strings.Contains(got, theOrganisationsKey) {
		t.Fatalf("the brain was given the key:\n%s", got)
	}
	var base, token string
	for _, l := range strings.Split(got, "\n") {
		if v, ok := strings.CutPrefix(l, "ENV:ANTHROPIC_BASE_URL="); ok {
			base = v
		}
		if v, ok := strings.CutPrefix(l, "ENV:ANTHROPIC_AUTH_TOKEN="); ok {
			token = v
		}
		if strings.HasPrefix(l, "ENV:ANTHROPIC_API_KEY=") {
			t.Fatalf("the brain was given an API key variable: %s", l)
		}
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/model") || token == "" {
		t.Fatalf("the brain was not pointed at its body's model address: base %q, token set %v", base, token != "")
	}
	for _, want := range []string{"ANSWER:data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello \"}}",
		"ANSWER:data: {\"type\":\"message_stop\"}"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the brain did not get the model's answer (%q):\n%s", want, got)
		}
	}
	calls := p.calls()
	if len(calls) != 1 {
		t.Fatalf("the provider was called %d times", len(calls))
	}
	if h := calls[0]; h.Get("x-api-key") != theOrganisationsKey || h.Get("Authorization") != "" ||
		strings.Contains(fmt.Sprint(h), token) {
		t.Fatalf("the provider was not sent the key alone: %v", h)
	}
	noFileHolds(t, workspace, theOrganisationsKey)
	noFileHolds(t, w.hostA.DataDir, theOrganisationsKey)
	rows := governanceRows(t, w, "agent.model.call")
	if len(rows) != 1 {
		t.Fatalf("%d model calls recorded", len(rows))
	}
	said := fmt.Sprintf("%+v", rows[0])
	for _, want := range []string{"model claude-stand-in", "answered 200", "120 tokens in, 42 out", "30 read from cache"} {
		if !strings.Contains(said, want) {
			t.Fatalf("the record does not say %q: %s", want, said)
		}
	}
	if strings.Contains(said, theOrganisationsKey) {
		t.Fatal("the record holds the key")
	}
	lent := governanceRows(t, w, "agent.brain.sign_in.lent")
	if len(lent) != 1 || !strings.Contains(fmt.Sprintf("%+v", lent[0]), "the key stays here") {
		t.Fatalf("the lend does not say the key stayed here: %+v", lent)
	}
	// The run's token ended with the run: the lease it cited is given back.
	if code, _ := startModelCall(t, w.hostA, "any-lease", "/v1/messages"); code != http.StatusForbidden {
		t.Fatalf("a model call citing no open lease was made: %d", code)
	}
}

// A body that does not say it makes its brain's model calls through the
// Identity Agent — one from before — is refused the sign-in rather than lent
// the key.
func TestABodyThatCannotCallThroughHereIsNotLentTheKey(t *testing.T) {
	w, _ := keyWorld(t)
	code, out, err := w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/brain-sign-in", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusConflict || strings.Contains(string(out), theOrganisationsKey) || !strings.Contains(string(out), "update agent-host") {
		t.Fatalf("an older body borrowing a key that stays here: %d %s", code, out)
	}
	if n := len(w.lendsOf(t)); n != 0 {
		t.Fatalf("%d lends made for a body that was refused", n)
	}
	// A body that does say so is lent a lease, and not the key.
	code, out, err = w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/brain-sign-in",
		[]byte(`{"model_calls":"through_identity_agent"}`))
	if err != nil || code != http.StatusOK || strings.Contains(string(out), theOrganisationsKey) ||
		!strings.Contains(string(out), `"model_calls":"through_identity_agent"`) {
		t.Fatalf("borrowing a key that stays here: %d %s %v", code, out, err)
	}
}

func (w *talkWorld) lendsOf(t *testing.T) []string {
	t.Helper()
	all, err := w.s.lends().Open(lendBrainSignIn, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, x := range all {
		ids = append(ids, x.ID)
	}
	return ids
}

// A model call is made only while the run's lease on the sign-in is open, by
// the body holding it, for a call a model's key is for. Removing the sign-in
// refuses the next call; so does giving the lease back, and so does revoking
// the AI agent.
func TestAModelCallIsMadeOnlyWhileTheRunMayMakeIt(t *testing.T) {
	w, p := keyWorld(t)
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if env, err := held.Env("claude-code"); err == nil {
		t.Fatalf("a key that stays here was made into an environment without a model address: %v", env)
	}
	code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK {
		t.Fatalf("a model call: %d %v", code, a)
	}
	if got := collectAll(t, w.hostA, a); !strings.Contains(got, "from the model") {
		t.Fatalf("the answer: %q", got)
	}
	// Another AI agent's body cannot use this run's lease.
	if code, a := startModelCall(t, w.hostB, held.LeaseID, "/v1/messages"); code != http.StatusForbidden {
		t.Fatalf("another body used the lease: %d %v", code, a)
	}
	// Only a model call: nothing else the key could do.
	for _, path := range []string{"/v1/organizations/api_keys", "/v1/../v1/messages", "v1/messages", "/v1/files"} {
		if code, a := startModelCall(t, w.hostA, held.LeaseID, path); code != http.StatusForbidden {
			t.Fatalf("%s was made: %d %v", path, code, a)
		}
	}
	before := len(p.calls())

	// Removing the sign-in refuses the next call.
	if code, _, raw := w.asOwner(t, "DELETE", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", ""); code != http.StatusOK {
		t.Fatalf("removing the sign-in: %d %s", code, raw)
	}
	if code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages"); code != http.StatusForbidden {
		t.Fatalf("a call after the sign-in was removed: %d %v", code, a)
	}

	// Giving the lease back refuses the next call.
	w2, p2 := keyWorld(t)
	held2, err := w2.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.hostA.Return(ctx, held2); err != nil {
		t.Fatal(err)
	}
	if code, a := startModelCall(t, w2.hostA, held2.LeaseID, "/v1/messages"); code != http.StatusForbidden {
		t.Fatalf("a call on a returned lease: %d %v", code, a)
	}

	// Revoking the AI agent refuses the next call.
	w3, p3 := keyWorld(t)
	held3, err := w3.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, raw := w3.asOwner(t, "POST", "/api/mcp/agents/"+w3.a.ID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	if code, a := startModelCall(t, w3.hostA, held3.LeaseID, "/v1/messages"); code == http.StatusOK {
		t.Fatalf("a call after revoking: %d %v", code, a)
	}
	if len(p.calls()) != before || len(p2.calls()) != 0 || len(p3.calls()) != 0 {
		t.Fatal("a refused call reached the provider")
	}
	if n := len(governanceRows(t, w, "agent.model.call")); n < 6 {
		t.Fatalf("refused calls were not recorded: %d rows", n)
	}
}

// The answer reaches the body as it arrives: the first part is collected
// while the provider is still answering, not once it has finished. An answer
// under way ends when the AI agent's sign-in is removed.
func TestAModelsAnswerArrivesAsItStreams(t *testing.T) {
	quickRecheck(t)
	w, p := keyWorld(t)
	hold := make(chan struct{})
	p.hold = hold
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
		}
	}
	defer release()
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK || a["status"] != float64(200) || a["done"] == true {
		t.Fatalf("starting: %d %v", code, a)
	}
	// Collect while the provider is still answering: the first part arrives
	// on its own.
	var first strings.Builder
	for i := 0; !strings.Contains(first.String(), "message_start"); i++ {
		if d, _ := a["data_b64"].(string); d != "" {
			b, _ := base64.StdEncoding.DecodeString(d)
			first.Write(b)
			continue
		}
		if i > 1 || a["done"] == true {
			t.Fatalf("the first part never arrived on its own: %v", a)
		}
		code, out, err := w.hostA.CallContext(ctx, "GET", fmt.Sprintf("/api/agent-host/model-calls/%s?from=%d&head=1",
			a["call_id"], int64(a["next"].(float64))), nil)
		if err != nil || code != http.StatusOK {
			t.Fatalf("collecting: %d %s %v", code, out, err)
		}
		a = map[string]any{}
		_ = json.Unmarshal(out, &a)
	}
	if strings.Contains(first.String(), "message_stop") || a["done"] == true {
		t.Fatalf("the whole answer came at once: %q", first.String())
	}
	release()
	a["data_b64"] = ""
	if got := collectAll(t, w.hostA, a); !strings.Contains(got, "message_stop") || strings.Contains(got, "message_start") {
		t.Fatalf("the rest: %q", got)
	}

	// An answer under way, and the sign-in removed: the next collection is
	// refused, and the call stopped.
	second := make(chan struct{})
	p.mu.Lock()
	p.hold = second
	p.mu.Unlock()
	defer close(second)
	code, a = startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK {
		t.Fatalf("starting again: %d %v", code, a)
	}
	if code, _, raw := w.asOwner(t, "DELETE", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in", ""); code != http.StatusOK {
		t.Fatalf("removing the sign-in: %d %s", code, raw)
	}
	// Nobody collects it: the call is stopped all the same, and so is the
	// provider's answer, which is what costs.
	select {
	case <-p.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("the provider kept answering a call whose sign-in was removed")
	}
	code, out, err := w.hostA.CallContext(ctx, "GET", fmt.Sprintf("/api/agent-host/model-calls/%s?from=%d&head=1",
		a["call_id"], int64(a["next"].(float64))), nil)
	if err != nil || code == http.StatusOK && !strings.Contains(string(out), `"done":true`) {
		t.Fatalf("collecting an answer whose sign-in was removed: %d %s %v", code, out, err)
	}
}

// An AI agent that only reads and answers runs no program: its body calls the
// model itself, through its own model address and so through the Identity
// Agent, which adds the key. Its words are its answer, and the next turn of
// the conversation carries on from what was said.
func TestAnAIAgentThatOnlyAnswersCallsTheModelWithNoProgram(t *testing.T) {
	w, p := keyWorld(t)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"brain":{"kind":"api_key","provider":"anthropic","model":"claude-stand-in","program":"none"}}`); code != http.StatusOK {
		t.Fatalf("making it answer only: %d %s", code, raw)
	}
	conv, _ := w.openedWith(t)
	workspace := t.TempDir()
	run := func() {
		t.Helper()
		if err := w.hostA.Run(context.Background(), agenthost.RunOptions{Once: true, Workspace: workspace}); err != nil {
			t.Fatal(err)
		}
	}
	run()
	var said []string
	for _, e := range w.read(t, conv) {
		said = append(said, e.Body)
	}
	if !strings.Contains(strings.Join(said, "|"), "Answered without a program") {
		t.Fatalf("the AI agent did not answer with the model's words: %q", said)
	}
	if bs := p.bodies; len(bs) != 1 || !strings.Contains(bs[0], `"system":"You are Desk assistant`) ||
		!strings.Contains(bs[0], "You have no tools") || !strings.Contains(bs[0], `"model":"claude-stand-in"`) {
		t.Fatalf("the model was not called as an AI agent that only answers: %q", bs)
	}
	noFileHolds(t, workspace, theOrganisationsKey)
	noFileHolds(t, w.hostA.DataDir, theOrganisationsKey)
	if rows := governanceRows(t, w, "agent.model.call"); len(rows) != 1 {
		t.Fatalf("%d model calls recorded", len(rows))
	}
	// The next message in the conversation carries on from the first.
	if code, out := w.personSays(t, w.a, conv, "and again"); code != http.StatusCreated {
		t.Fatalf("saying more: %d %v", code, out)
	}
	run()
	p.mu.Lock()
	second := p.bodies[len(p.bodies)-1]
	p.mu.Unlock()
	if !strings.Contains(second, "Answered without a program") || !strings.Contains(second, "and again") {
		t.Fatalf("the second turn did not carry on the conversation: %s", second)
	}
}

// Only a key the Identity Agent uses for it can be run with no program: a
// subscription is for its provider's own program.
func TestOnlyAKeyKeptHereRunsWithNoProgram(t *testing.T) {
	w := signInWorld(t)
	for _, c := range []struct {
		brain string
		ok    bool
	}{
		{`{"kind":"api_key","provider":"openrouter","model":"m","program":"none"}`, true},
		{`{"kind":"subscription","provider":"claude-code","program":"none"}`, false},
		{`{"kind":"local","provider":"local","endpoint":"http://10.0.0.5","program":"none"}`, false},
		{`{"kind":"api_key","provider":"anthropic","program":"a-program-nobody-knows"}`, false},
	} {
		code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID, `{"brain":`+c.brain+`}`)
		if (code == http.StatusOK) != c.ok {
			t.Errorf("%s: %d %s", c.brain, code, raw)
		}
	}
}

// quickRecheck makes calls under way check again at once, and collections
// wait only a moment, for the length of a test.
func quickRecheck(t *testing.T) {
	t.Helper()
	was, wait, idle := modelCallRecheck, modelCallWait, modelCallIdle.Load()
	modelCallRecheck, modelCallWait = 50*time.Millisecond, 2*time.Second
	t.Cleanup(func() { modelCallRecheck, modelCallWait = was, wait; modelCallIdle.Store(idle) })
}

// startModelCallWith is startModelCall with the headers and body a body sends.
func startModelCallWith(t *testing.T, h *agenthost.Host, lease, method, path string, header map[string]string,
	body []byte) (int, map[string]any) {
	t.Helper()
	q, _ := json.Marshal(map[string]any{"lease_id": lease, "method": method, "path": path, "header": header,
		"body_b64": base64.StdEncoding.EncodeToString(body)})
	code, out, err := h.CallContext(context.Background(), "POST", "/api/agent-host/model-calls", q)
	if err != nil {
		return http.StatusForbidden, map[string]any{"error": err.Error()}
	}
	var a map[string]any
	_ = json.Unmarshal(out, &a)
	return code, a
}

// What a body sends is checked here again, whatever the body did: only a
// plain model path, only the headers that describe the call, never one the
// brain authenticated with, and never an answer that carries the key.
func TestTheIdentityAgentChecksEveryCallItIsSent(t *testing.T) {
	w, p := keyWorld(t)
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/models/../organizations"}, {"GET", "/v1/models/%2e%2e/organizations"},
		{"GET", "/v1/models/a%2fb"}, {"POST", "/v1/messages?beta=1"}, {"POST", "/v1/messages#x"},
		{"POST", "/v1//messages"}, {"POST", "/v1/messages/"}, {"GET", "/v1/api-key"},
	} {
		if code, a := startModelCallWith(t, w.hostA, held.LeaseID, c.method, c.path, nil, nil); code != http.StatusForbidden {
			t.Errorf("%s %s was made: %d %v", c.method, c.path, code, a)
		}
	}
	if len(p.calls()) != 0 {
		t.Fatal("a refused call reached the provider")
	}
	// A body that sends its own authentication: the provider sees only the key.
	code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages", map[string]string{
		"Authorization": "Bearer ahm-THE-RUNS-TOKEN", "X-Api-Key": "ahm-THE-RUNS-TOKEN", "Cookie": "c=1",
		"Content-Type": "application/json", "X-Forwarded-For": "10.0.0.1"},
		[]byte(`{"model":"m","stream":true,"messages":[]}`))
	if code != http.StatusOK {
		t.Fatalf("a call: %d %v", code, a)
	}
	collectAll(t, w.hostA, a)
	h := p.calls()[0]
	if h.Get("x-api-key") != theOrganisationsKey || h.Get("Authorization") != "" || h.Get("Cookie") != "" ||
		h.Get("X-Forwarded-For") != "" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("the provider was sent what the body sent: %v", h)
	}

	// An xAI key's answer about itself is passed on, unless it carries the key.
	wx, px := keyWorld(t)
	if code, _, raw := wx.asOwner(t, "PUT", "/api/mcp/agents/"+wx.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"xai","secret":"`+theOrganisationsKey+`"}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	heldX, err := wx.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	px.keyAnswer = `{"name":"Support team key","acls":["api-key:model:*"]}`
	code, a = startModelCallWith(t, wx.hostA, heldX.LeaseID, "GET", "/v1/api-key", nil, nil)
	if got := collectAll(t, wx.hostA, a); code != http.StatusOK || !strings.Contains(got, "Support team key") {
		t.Fatalf("the key's own answer: %d %q", code, got)
	}
	px.keyAnswer = `{"name":"k","api_key":"` + theOrganisationsKey + `"}`
	code, a = startModelCallWith(t, wx.hostA, heldX.LeaseID, "GET", "/v1/api-key", nil, nil)
	if got := collectAll(t, wx.hostA, a); strings.Contains(got, theOrganisationsKey) {
		t.Fatalf("an answer carrying the key was passed on: %d %q %v", code, got, a)
	}
}

// The largest call a body may make travels whole; a larger one is refused by
// the Identity Agent too. A long answer comes in parts no larger than one
// sealed envelope can carry.
func TestTheLargestModelCallTravelsSealed(t *testing.T) {
	w, p := keyWorld(t)
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	big := []byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"` +
		strings.Repeat("x", modelRequestLargest-200) + `"}]}`)
	code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages",
		map[string]string{"Content-Type": "application/json"}, big)
	if code != http.StatusOK {
		t.Fatalf("the largest call: %d %v", code, a)
	}
	collectAll(t, w.hostA, a)
	p.mu.Lock()
	got := len(p.bodies[len(p.bodies)-1])
	p.mu.Unlock()
	if got != len(big) {
		t.Fatalf("the provider was sent %d bytes of %d", got, len(big))
	}
	if code, _ := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages", nil,
		make([]byte, modelRequestLargest+1)); code == http.StatusOK {
		t.Fatal("a call larger than one may be was made")
	}
	c := &modelCall{changed: make(chan struct{}), status: 200, buf: make([]byte, 3*modelCallChunk), done: true}
	first, err := c.collect(ctx, 0, false, 0)
	if err != nil || first.Done || first.Next != modelCallChunk {
		t.Fatalf("a long answer came at once: next %d done %v %v", first.Next, first.Done, err)
	}
	if _, err := c.collect(ctx, 0, true, 0); err == nil {
		// What was collected and let go is not given again.
	}
	second, _ := c.collect(ctx, first.Next, true, 0)
	if second.Next != 2*modelCallChunk {
		t.Fatalf("the second part: %d", second.Next)
	}
	if _, err := c.collect(ctx, 0, true, 0); err == nil {
		t.Fatal("a part collected and let go was given again")
	}
}

// One body may hold only so many calls at once for its AI agent, whichever
// leases they cite and whether or not they have finished, until their answers
// are collected or swept; and a run whose lease lapsed and was taken again
// carries on the call it was making.
func TestABodysCallsAreBoundedAndOutliveARenewedLease(t *testing.T) {
	quickRecheck(t)
	w, p := keyWorld(t)
	hold := make(chan struct{})
	p.hold = hold
	defer close(hold)
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	for i := 0; i < modelCallsPerBody; i++ {
		code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
		if code != http.StatusOK {
			t.Fatalf("call %d: %d %v", i, code, a)
		}
		if first == nil {
			first = a
		}
	}
	// Another lease of the same body's is no way round the bound.
	if code, a := startModelCall(t, w.hostA, second.LeaseID, "/v1/messages"); code != http.StatusTooManyRequests {
		t.Fatalf("a call past the bound, under a second lease: %d %v", code, a)
	}
	// The run takes another lease and the first ends, as when its lease
	// lapsed; the call carries on under the new one.
	if err := w.hostA.Return(ctx, held); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * modelCallRecheck)
	code, out, err := w.hostA.CallContext(ctx, "GET", fmt.Sprintf("/api/agent-host/model-calls/%s?from=%d&head=1&lease=%s",
		first["call_id"], int64(first["next"].(float64)), second.LeaseID), nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("collecting under the new lease: %d %s %v", code, out, err)
	}
	// A lease that is not this body's is not taken.
	code, _, _ = w.hostA.CallContext(ctx, "GET", fmt.Sprintf("/api/agent-host/model-calls/%s?from=%d&head=1&lease=bl_not_this_run",
		first["call_id"], int64(first["next"].(float64))), nil)
	if code != http.StatusForbidden {
		t.Fatalf("collecting under a lease it does not hold: %d", code)
	}
}

// Answers finished but never collected still count against a body's bound,
// and are swept on a timer, not only when the body next asks.
func TestUncollectedAnswersCountUntilTheyAreSwept(t *testing.T) {
	quickRecheck(t)
	w, p := keyWorld(t)
	hold := make(chan struct{})
	p.hold = hold
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < modelCallsPerBody; i++ {
		// Started, and its first part collected; then nothing collects the
		// rest once the provider finishes.
		if code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages",
			map[string]string{"Content-Type": "application/json"}, []byte(`{"model":"m","stream":true}`)); code != http.StatusOK {
			t.Fatalf("call %d: %d %v", i, code, a)
		}
	}
	close(hold)
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := 0
		w.s.modelCalls.mu.Lock()
		for _, c := range w.s.modelCalls.calls {
			c.mu.Lock()
			if c.done {
				n++
			}
			c.mu.Unlock()
		}
		total := len(w.s.modelCalls.calls)
		w.s.modelCalls.mu.Unlock()
		if total != modelCallsPerBody {
			t.Fatalf("%d calls kept, not %d", total, modelCallsPerBody)
		}
		if n == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the answers never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages"); code != http.StatusTooManyRequests {
		t.Fatalf("finished, uncollected answers did not count: %d %v", code, a)
	}
	modelCallIdle.Store(100 * time.Millisecond)
	deadline = time.Now().Add(5 * time.Second)
	for {
		w.s.modelCalls.mu.Lock()
		left := len(w.s.modelCalls.calls)
		w.s.modelCalls.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d uncollected answers were never swept", left)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b := w.s.modelCalls.buffered.Load(); b != 0 {
		t.Fatalf("%d bytes still counted as held after every call was swept", b)
	}
}

// What every answer holds here is bounded across all calls: a call whose
// answer would pass the bound is stopped.
func TestWhatAllAnswersHoldIsBounded(t *testing.T) {
	var tb modelCallTable
	c := &modelCall{id: "a", host: "h", agent: "x", changed: make(chan struct{})}
	if !tb.add(c) {
		t.Fatal("not kept")
	}
	tb.buffered.Store(modelCallsBuffered - 10)
	if c.add(make([]byte, 5)) != true {
		t.Fatal("an answer within the bound was stopped")
	}
	if c.add(make([]byte, 10)) {
		t.Fatal("an answer past the bound across all calls was kept going")
	}
	tb.remove("a")
	if got := tb.buffered.Load(); got != modelCallsBuffered-10 {
		t.Fatalf("forgetting a call let go of %d bytes, not what it held", modelCallsBuffered+5-got)
	}
}

// The key is never passed on in an answer, however the provider sends it:
// in an error the provider quotes it in, or split across the parts of an
// answer.
func TestTheKeyIsNeverPassedOnInAnAnswer(t *testing.T) {
	w, _ := keyWorld(t)
	echo := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		f := rw.(http.Flusher)
		// Quoted, and split across two writes.
		k := r.Header.Get("x-api-key")
		_, _ = io.WriteString(rw, `{"type":"error","error":{"message":"bad request for key `+k[:10])
		f.Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(rw, k[10:]+`"}}`)
	}))
	t.Cleanup(echo.Close)
	w.s.brainChecker.Anthropic = echo.URL
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK {
		t.Fatalf("a call: %d %v", code, a)
	}
	got := collectAll(t, w.hostA, a)
	if strings.Contains(got, theOrganisationsKey) || strings.Contains(got, theOrganisationsKey[:10]) {
		t.Fatalf("the brain was given the key, or part of it: %q", got)
	}
	for _, c := range []struct {
		key   string
		parts []string
	}{
		{"SECRET", []string{"abcSEC", "RETdef"}},
		{"SECRET", []string{"S", "E", "C", "R", "E", "T"}},
		{"SECRET", []string{"no key here", " at all"}},
	} {
		k := keyWatch{key: []byte(c.key)}
		var passed strings.Builder
		var failed bool
		for _, p := range c.parts {
			out, err := k.next([]byte(p))
			if err != nil {
				failed = true
				break
			}
			passed.Write(out)
		}
		if !failed {
			passed.Write(k.rest())
		}
		if strings.Contains(passed.String(), "SEC") && strings.Contains(strings.Join(c.parts, ""), c.key) {
			t.Fatalf("%q: passed on %q", c.parts, passed.String())
		}
		if !strings.Contains(strings.Join(c.parts, ""), c.key) && passed.String() != strings.Join(c.parts, "") {
			t.Fatalf("%q: an answer with no key was changed: %q", c.parts, passed.String())
		}
	}
}

// What a body sends cannot fill or forge the record: a long path is refused,
// a model's name is kept to one short line, a query carries only what a model
// call may, and refusals are recorded at most so many a minute.
func TestWhatABodySendsCannotFillOrForgeTheRecord(t *testing.T) {
	w, p := keyWorld(t)
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := startModelCallWith(t, w.hostA, held.LeaseID, "GET", "/v1/models/"+strings.Repeat("a", 400), nil, nil); code != http.StatusForbidden {
		t.Fatalf("a long path: %d", code)
	}
	// A call whose answer names no model is recorded under the model it asked
	// for, which is the body's to say.
	code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages/count_tokens",
		map[string]string{"Content-Type": "application/json"},
		[]byte(`{"model":"m\n2026/10/28 [lent] agent.model.call forged`+strings.Repeat("x", 500)+`"}`))
	if code != http.StatusOK {
		t.Fatalf("a call: %d %v", code, a)
	}
	collectAll(t, w.hostA, a)
	for _, r := range governanceRows(t, w, "agent.model.call") {
		if said := fmt.Sprintf("%+v", r); strings.Contains(said, "\n") || len(said) > 4000 {
			t.Fatalf("the record carries what the body sent as it was: %.300q", said)
		}
	}
	// A query: Claude Code's beta=true is passed on, anything else refused.
	q, _ := json.Marshal(map[string]any{"lease_id": held.LeaseID, "method": "POST", "path": "/v1/messages",
		"query": "beta=true", "header": map[string]string{"Content-Type": "application/json"},
		"body_b64": base64.StdEncoding.EncodeToString([]byte(`{"model":"m","stream":true}`))})
	code2, out, err := w.hostA.CallContext(ctx, "POST", "/api/agent-host/model-calls", q)
	if err != nil || code2 != http.StatusOK {
		t.Fatalf("beta=true: %d %s %v", code2, out, err)
	}
	var started map[string]any
	_ = json.Unmarshal(out, &started)
	collectAll(t, w.hostA, started)
	for _, bad := range []string{"redirect=http://x", "beta=false", "beta=true&beta=true"} {
		q, _ := json.Marshal(map[string]any{"lease_id": held.LeaseID, "method": "POST", "path": "/v1/messages",
			"query": bad, "body_b64": ""})
		if code, _, _ := w.hostA.CallContext(ctx, "POST", "/api/agent-host/model-calls", q); code != http.StatusForbidden {
			t.Fatalf("query %q: %d", bad, code)
		}
	}
	_ = p
	// Many refusals: at most so many recorded.
	before := len(governanceRows(t, w, "agent.model.call"))
	for i := 0; i < 3*modelDenialsRecorded; i++ {
		startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/files", nil, nil)
	}
	if n := len(governanceRows(t, w, "agent.model.call")) - before; n > modelDenialsRecorded {
		t.Fatalf("%d refusals recorded in a minute", n)
	}
}

// An answer under way is stopped, and with it the provider's answer, when
// the AI agent's grant lapses or is no longer in force, even with nobody
// collecting it: what the AI agent may do is asked afresh each time.
func TestAnAnswerUnderWayEndsWhenTheGrantDoes(t *testing.T) {
	for _, how := range []string{"lapsed", "no longer in force"} {
		t.Run(how, func(t *testing.T) {
			quickRecheck(t)
			w, p := keyWorld(t)
			hold := make(chan struct{})
			p.hold = hold
			defer close(hold)
			held, err := w.hostA.Borrow(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages"); code != http.StatusOK {
				t.Fatalf("starting: %d %v", code, a)
			}
			grants := w.s.grantsHeldBy(w.a.PairwiseAID, true)
			if len(grants) == 0 {
				t.Fatal("the AI agent holds no grant")
			}
			for _, g := range grants {
				if how == "lapsed" {
					g.ExpiryDate = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
					if err := w.s.DataStore.SaveCredential(g); err != nil {
						t.Fatal(err)
					}
				} else if err := w.s.DataStore.DeleteCredential(g.SAID); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-p.cancelled:
			case <-time.After(5 * time.Second):
				t.Fatalf("the provider kept answering after the grant %s", how)
			}
		})
	}
}

// An AI agent that only reads and answers is lent no GitHub access and asks
// no other AI agent, whatever its body tries.
func TestAnAnswerOnlyAIAgentIsHeldToItAtTheIdentityAgent(t *testing.T) {
	w, _ := keyWorld(t)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID, `{"brain":{"program":"none","model":"m"}}`); code != http.StatusOK {
		t.Fatalf("making it answer only: %d %s", code, raw)
	}
	code, out, err := w.hostA.CallContext(context.Background(), "POST", "/api/agent-host/github", []byte("{}"))
	if err != nil || code != http.StatusForbidden || !strings.Contains(string(out), "only reads and answers") {
		t.Fatalf("GitHub for an AI agent that only answers: %d %s %v", code, out, err)
	}
	conv, msg := w.openedWith(t)
	if _, err := w.hostA.Say(context.Background(), "ask", conv, w.b.PairwiseAID, msg, "what do you run?",
		agentmessage.Brain{Provider: "model"}); err == nil || !strings.Contains(err.Error(), "only reads and answers") {
		t.Fatalf("an AI agent that only answers asked another: %v", err)
	}
}

// An AI agent that only reads and answers keeps a sign-in it can run with:
// one it cannot is refused rather than kept.
func TestAnAnswerOnlyAIAgentIsNotGivenASubscription(t *testing.T) {
	w, _ := keyWorld(t)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID, `{"brain":{"program":"none","model":"m"}}`); code != http.StatusOK {
		t.Fatalf("making it answer only: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"subscription","provider":"claude-code","secret":"sk-ant-oat01-T"}`); code != http.StatusBadRequest {
		t.Fatalf("a subscription for an AI agent that only answers: %d %s", code, raw)
	}
}

// However many machines ask, only so many calls are kept at once, and the
// count of each machine's refusals is let go once its minute is over.
func TestTheCallTableIsBoundedAcrossMachines(t *testing.T) {
	var tb modelCallTable
	for i := 0; i < modelCallsHeld; i++ {
		if !tb.add(&modelCall{id: fmt.Sprint(i), host: fmt.Sprint("h", i), agent: "x", changed: make(chan struct{}),
			collected: time.Now()}) {
			t.Fatalf("call %d of %d was not kept", i, modelCallsHeld)
		}
	}
	if tb.add(&modelCall{id: "one-more", host: "another", agent: "x", changed: make(chan struct{})}) {
		t.Fatal("a call past the bound across every machine was kept")
	}
	long := time.Now().Add(-2 * time.Minute)
	for i := 0; i < 50; i++ {
		tb.mayRecordDenial(fmt.Sprint("h", i), long)
	}
	tb.sweep(time.Now())
	if len(tb.denied) != 0 {
		t.Fatalf("%d machines' refusal counts kept after their minute", len(tb.denied))
	}
}
