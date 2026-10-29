package agenthost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentmessage"
)

// The host's tools, as the brain reaches them.
//
// The brain is a separate process, possibly as another operating-system user,
// and never holds the machine key. So the tools live in the host, behind a
// server on this machine's loopback address, and the brain reaches them
// through `agent-host mcp`: an MCP server over stdio that the brain starts,
// which forwards each call to the host with the turn's token. A token is good
// for one turn, and names the conversation and message the turn is about —
// the brain cannot point a tool at a different conversation.

const (
	envToolsURL   = "AGENT_HOST_TOOLS_URL"
	envToolsToken = "AGENT_HOST_TOOLS_TOKEN"
)

// toolTurn is what a token is good for.
type toolTurn struct {
	Conversation string
	// ActingOn is the message the brain was handed this turn: an ask names it.
	ActingOn string
	// Serving is the ask this AI agent owes an answer to, and AskedBy who
	// sent it: a reply answers it.
	Serving, AskedBy string
	Brain            func() string

	mu       sync.Mutex
	replied  bool
	asked    int
	failures []string
}

// toolServer serves the host's tools to the brain.
type toolServer struct {
	h    *Host
	ln   net.Listener
	srv  *http.Server
	mu   sync.Mutex
	turn map[string]*toolTurn
	// model are the runs whose brain makes its model calls through this
	// body, by the token each run's brain was given (model.go).
	model map[string]*Borrowed
}

func newToolServer(h *Host) (*toolServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ts := &toolServer{h: h, ln: ln, turn: map[string]*toolTurn{}}
	ts.srv = &http.Server{Handler: http.HandlerFunc(ts.serve), ReadHeaderTimeout: 10 * time.Second}
	go ts.srv.Serve(ln)
	return ts, nil
}

func (ts *toolServer) url() string { return "http://" + ts.ln.Addr().String() }

func (ts *toolServer) close() { _ = ts.srv.Close() }

// open issues a token for one turn.
func (ts *toolServer) open(t *toolTurn) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	ts.mu.Lock()
	ts.turn[tok] = t
	ts.mu.Unlock()
	return tok
}

// shut withdraws a turn's token once the turn has ended.
func (ts *toolServer) shut(tok string) {
	ts.mu.Lock()
	delete(ts.turn, tok)
	ts.mu.Unlock()
}

func (ts *toolServer) turnFor(r *http.Request) *toolTurn {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for k, t := range ts.turn {
		if subtle.ConstantTimeCompare([]byte(k), []byte(tok)) == 1 {
			return t
		}
	}
	return nil
}

type toolCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"arguments"`
}

func (ts *toolServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == modelPath || strings.HasPrefix(r.URL.Path, modelPath+"/") {
		ts.serveModel(w, r)
		return
	}
	t := ts.turnFor(r)
	if t == nil {
		http.Error(w, "this turn has ended", http.StatusUnauthorized)
		return
	}
	var call toolCall
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&call); err != nil {
		http.Error(w, "unreadable call", http.StatusBadRequest)
		return
	}
	text, err := ts.call(r.Context(), t, call)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"text": err.Error(), "is_error": true})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"text": text})
}

func (ts *toolServer) call(ctx context.Context, t *toolTurn, c toolCall) (string, error) {
	var a struct {
		To   string `json:"to"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(c.Args, &a)
	switch c.Name {
	case "reply":
		if strings.TrimSpace(a.Text) == "" {
			return "", errors.New("a reply needs text")
		}
		t.mu.Lock()
		done := t.replied
		t.mu.Unlock()
		if done {
			return "", errors.New("you have already replied in this turn")
		}
		if _, err := ts.h.Say(ctx, "reply", t.Conversation, t.AskedBy, t.Serving, a.Text, ts.h.brainFingerprint(t)); err != nil {
			return "", err
		}
		t.mu.Lock()
		t.replied = true
		t.mu.Unlock()
		return "Sent. That answers the one who asked you; end your turn now.", nil
	case "ask_agent":
		if strings.TrimSpace(a.Text) == "" || strings.TrimSpace(a.To) == "" {
			return "", errors.New("ask_agent needs who to ask (name or identifier) and what to ask")
		}
		to, err := ts.h.resolveAgent(ctx, a.To)
		if err != nil {
			return "", err
		}
		if _, err := ts.h.Say(ctx, "ask", t.Conversation, to.AID, t.ActingOn, a.Text, ts.h.brainFingerprint(t)); err != nil {
			return "", err
		}
		t.mu.Lock()
		t.asked++
		t.mu.Unlock()
		return fmt.Sprintf("Asked %s. Its answer will come to you as a new message in this conversation. "+
			"Unless you have something else to do now, end your turn without replying.", to.Name), nil
	case "list_agents":
		list, err := ts.h.Agents(ctx)
		if err != nil {
			return "", err
		}
		if len(list) == 0 {
			return "You may not ask any other AI agent.", nil
		}
		var b strings.Builder
		for _, ag := range list {
			fmt.Fprintf(&b, "- %s", ag.Name)
			if ag.Role != "" {
				fmt.Fprintf(&b, " (%s)", ag.Role)
			}
			fmt.Fprintf(&b, ": %s\n", ag.AID)
		}
		return b.String(), nil
	case "conversation_history":
		code, b, err := ts.h.CallContext(ctx, "GET", "/api/agent-host/conversations/"+t.Conversation, nil)
		if err != nil {
			return "", err
		}
		if code != http.StatusOK {
			return "", fmt.Errorf("the conversation could not be read (%d)", code)
		}
		var out struct {
			Said []struct {
				Kind, From, To, Body string
			} `json:"said"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			return "", err
		}
		var sb strings.Builder
		for _, m := range out.Said {
			fmt.Fprintf(&sb, "%s (%s to %s): %s\n\n", m.From, m.Kind, m.To, m.Body)
		}
		return sb.String(), nil
	case "system_info":
		info, err := SystemInfo(ctx)
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(info, "", "  ")
		return string(b), nil
	}
	return "", fmt.Errorf("there is no tool called %q", c.Name)
}

// resolveAgent finds an AI agent this one may ask, by name or identifier.
func (h *Host) resolveAgent(ctx context.Context, who string) (Agent, error) {
	list, err := h.Agents(ctx)
	if err != nil {
		return Agent{}, err
	}
	var names []string
	for _, ag := range list {
		if ag.AID == who || strings.EqualFold(ag.Name, strings.TrimSpace(who)) {
			return ag, nil
		}
		names = append(names, ag.Name)
	}
	if len(names) == 0 {
		return Agent{}, errors.New("this AI agent may not ask any other AI agent")
	}
	return Agent{}, fmt.Errorf("no AI agent called %q that you may ask; you may ask: %s", who, strings.Join(names, ", "))
}

// brainFingerprint is what the host reports about the brain mid-turn, before
// its run is finished and can be hashed.
func (h *Host) brainFingerprint(t *toolTurn) agentmessage.Brain {
	b := agentmessage.Brain{Provider: h.brainName, Model: h.brainModel}
	if t.Brain != nil {
		b.Session = t.Brain()
	}
	return b
}

// ── The MCP server the brain starts ──────────────────────────────────────────

// toolDescriptions are the tools as the brain is told about them.
var toolDescriptions = []map[string]any{
	{"name": "reply", "description": "Answer the person or AI agent that asked you, in this conversation. Use it once, with your complete answer.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"text": map[string]any{"type": "string", "description": "your answer"}}, "required": []string{"text"}}},
	{"name": "ask_agent", "description": "Ask another AI agent of your organisation something. Its answer arrives later, as a new message to you; end your turn after asking.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"to":   map[string]any{"type": "string", "description": "the AI agent's name, as list_agents gives it"},
			"text": map[string]any{"type": "string", "description": "what to ask"}}, "required": []string{"to", "text"}}},
	{"name": "list_agents", "description": "List the AI agents you may ask.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "conversation_history", "description": "Everything said so far in this conversation, by whom, in order.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "system_info", "description": "Facts about the machine you run on: operating system and version, hardware model, processor, memory, disk, uptime, and developer tools installed.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
}

// ServeMCP is `agent-host mcp`: an MCP server over stdin and stdout that
// forwards the host's tools to the running host.
func ServeMCP(in io.Reader, out io.Writer) error {
	url, token := os.Getenv(envToolsURL), os.Getenv(envToolsToken)
	if url == "" || token == "" {
		return errors.New("agent-host mcp is started by the brain during a turn, never by hand")
	}
	host := hostTools{URL: url, Token: token}
	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification
		}
		var result any
		var rpcErr map[string]any
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(req.Params, &p)
			result = map[string]any{
				"protocolVersion": firstNonEmpty(p.ProtocolVersion, "2025-06-18"),
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": mcpServerName, "version": "1"},
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			result = map[string]any{"tools": toolDescriptions}
		case "tools/call":
			var p toolCall
			_ = json.Unmarshal(req.Params, &p)
			text, isErr := host.call(context.Background(), p.Name, p.Args)
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
		default:
			rpcErr = map[string]any{"code": -32601, "message": "method not found"}
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// hostTools reaches the host's tools for a turn: from `agent-host mcp`, which
// a brain's program starts, or from agent-host's own loop.
type hostTools struct {
	URL, Token string
	HTTP       *http.Client
}

// hostToolAnswerLargest bounds what one of the host's tools gives back.
const hostToolAnswerLargest = 1 << 20

// call forwards one call of the host's tools to the host, with the turn's
// token, and says what it gave and whether it failed.
func (h hostTools) call(ctx context.Context, name string, args json.RawMessage) (string, bool) {
	body, _ := json.Marshal(toolCall{Name: name, Args: args})
	hr, err := http.NewRequestWithContext(ctx, "POST", h.URL, bytes.NewReader(body))
	if err != nil {
		return err.Error(), true
	}
	hr.Header.Set("Authorization", "Bearer "+h.Token)
	hr.Header.Set("Content-Type", "application/json")
	client := h.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(hr)
	if err != nil {
		return "the host could not be reached: " + err.Error(), true
	}
	defer resp.Body.Close()
	var r struct {
		Text    string `json:"text"`
		IsError bool   `json:"is_error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, hostToolAnswerLargest))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &r) != nil {
		return strings.TrimSpace(string(b)), true
	}
	return r.Text, r.IsError
}
