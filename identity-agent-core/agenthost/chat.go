package agenthost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A model call made by agent-host itself: by an AI agent that only reads and
// answers (DirectModel), and by agent-host's own loop (ServeLoop). Both reach
// the model at the body's model address, and so through the Identity Agent,
// which adds the key (ADR-057). The conversation is held in one shape, and
// sent in the shape the provider speaks: Anthropic's messages, or OpenAI's
// chat, which OpenAI, xAI and OpenRouter all take.

// chatMessage is one message of a conversation. A message from the model may
// ask for tools to be used (ToolCalls); what a tool gave back is a message of
// its own, with role "tool", naming the call it answers. A conversation kept
// before tools existed is the same shape without them.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

// chatToolCall is the model asking for one tool, with its arguments as the
// JSON text the model wrote.
type chatToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// chatTool is a tool the model is told it may use.
type chatTool struct {
	Name        string
	Description string
	// Schema is the JSON schema of its arguments.
	Schema map[string]any
}

// chatRequest is one call: the model, its instructions, the conversation so
// far, and the tools it may use.
type chatRequest struct {
	Model        string
	Instructions string
	Messages     []chatMessage
	Tools        []chatTool
	Stream       bool
	// MaxTokens bounds the answer; zero is chatMaxTokens.
	MaxTokens int
}

// chatMaxTokens is how long an answer may be, where the API needs to be told.
const chatMaxTokens = 8192

// chatAnswer is what the model answered: its words, the tools it asked for,
// the model it names, and what the call used.
type chatAnswer struct {
	Message   chatMessage
	Model     string
	TokensIn  int
	TokensOut int
	// Stop is why the model stopped, as its provider says it.
	Stop string
	// Sent is the call as it was sent, for the digest of the run.
	Sent []byte
}

// chatClient makes model calls at one model address.
type chatClient struct {
	URL, Token string
	// API is "anthropic" for Anthropic's messages, anything else for OpenAI's
	// chat.
	API  string
	HTTP *http.Client
}

// chatAnswerLargest bounds what one answer may hold.
const chatAnswerLargest = 4 << 20

// chatError is a call the model's provider, or the Identity Agent, refused.
type chatError struct {
	Status int
	Why    string
	// RetryAfter is how long the provider asked to be left, when it said.
	RetryAfter time.Duration
}

func (e *chatError) Error() string {
	return fmt.Sprintf("the model refused the call (%d): %s", e.Status, firstNonEmpty(e.Why, "no reason given"))
}

// worthRetrying reports whether a refused call may succeed if made again:
// the provider or the Identity Agent was busy, or failed on its side.
func (e *chatError) worthRetrying() bool {
	switch e.Status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return true
	}
	return false
}

// tooLong reports whether the provider refused the call because the
// conversation is more than the model can read.
func (e *chatError) tooLong() bool {
	if e.Status != http.StatusBadRequest && e.Status != http.StatusRequestEntityTooLarge {
		return false
	}
	w := strings.ToLower(e.Why)
	for _, s := range []string{"context length", "context_length", "context window", "too long", "too many tokens",
		"maximum context", "prompt is too long", "reduce the length", "larger than"} {
		if strings.Contains(w, s) {
			return true
		}
	}
	return e.Status == http.StatusRequestEntityTooLarge
}

func (c chatClient) anthropic() bool { return c.API == "anthropic" }

// body is the call as the provider's API takes it.
func (c chatClient) body(r chatRequest) []byte {
	max := r.MaxTokens
	if max <= 0 {
		max = chatMaxTokens
	}
	req := map[string]any{"model": r.Model}
	if c.anthropic() {
		req["max_tokens"] = max
		if r.Instructions != "" {
			req["system"] = r.Instructions
		}
		req["messages"] = anthropicMessages(r.Messages)
		if len(r.Tools) > 0 {
			var tools []map[string]any
			for _, t := range r.Tools {
				tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.Schema})
			}
			req["tools"] = tools
		}
	} else {
		var msgs []any
		if r.Instructions != "" {
			msgs = append(msgs, map[string]any{"role": "system", "content": r.Instructions})
		}
		for _, m := range r.Messages {
			msgs = append(msgs, openAIMessage(m))
		}
		req["messages"] = msgs
		if len(r.Tools) > 0 {
			var tools []map[string]any
			for _, t := range r.Tools {
				tools = append(tools, map[string]any{"type": "function", "function": map[string]any{
					"name": t.Name, "description": t.Description, "parameters": t.Schema}})
			}
			req["tools"] = tools
		}
	}
	if r.Stream {
		req["stream"] = true
		if !c.anthropic() {
			req["stream_options"] = map[string]any{"include_usage": true}
		}
	}
	b, _ := json.Marshal(req)
	return b
}

// openAIMessage is one message as OpenAI's chat takes it.
func openAIMessage(m chatMessage) map[string]any {
	out := map[string]any{"role": m.Role, "content": m.Content}
	switch {
	case m.Role == "tool":
		out["tool_call_id"] = m.ToolCallID
	case len(m.ToolCalls) > 0:
		var calls []map[string]any
		for _, tc := range m.ToolCalls {
			calls = append(calls, map[string]any{"id": tc.ID, "type": "function",
				"function": map[string]any{"name": tc.Name, "arguments": firstNonEmpty(tc.Arguments, "{}")}})
		}
		out["tool_calls"] = calls
		if m.Content == "" {
			out["content"] = nil
		}
	}
	return out
}

// anthropicMessages is the conversation as Anthropic's messages take it: what
// a tool gave back is the person's side of the conversation, and one side
// never speaks twice in a row, so neighbouring messages from one side are
// joined.
func anthropicMessages(ms []chatMessage) []map[string]any {
	var out []map[string]any
	for _, m := range ms {
		role := m.Role
		var blocks []map[string]any
		switch {
		case m.Role == "tool":
			role = "user"
			blocks = append(blocks, map[string]any{"type": "tool_result", "tool_use_id": anthropicID(m.ToolCallID),
				"content": m.Content})
		default:
			if m.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var input any = map[string]any{}
				if tc.Arguments != "" {
					var v map[string]any
					if json.Unmarshal([]byte(tc.Arguments), &v) == nil {
						input = v
					}
				}
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": anthropicID(tc.ID), "name": tc.Name,
					"input": input})
			}
		}
		if len(blocks) == 0 {
			continue
		}
		if n := len(out); n > 0 && out[n-1]["role"] == role {
			out[n-1]["content"] = append(out[n-1]["content"].([]map[string]any), blocks...)
			continue
		}
		out = append(out, map[string]any{"role": role, "content": blocks})
	}
	return out
}

// anthropicID is a tool call's id as Anthropic takes one: letters, digits,
// underscores and hyphens. Another provider's ids, from earlier in the
// conversation, may hold other characters; such an id is replaced by a digest
// of it, so two ids that differ only in those characters stay apart.
func anthropicID(id string) string {
	for _, r := range id {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			sum := sha256.Sum256([]byte(id))
			return "id_" + hex.EncodeToString(sum[:12])
		}
	}
	return id
}

// Call makes one model call, and reads its answer whole, as it streams when
// it was asked to stream.
func (c chatClient) Call(ctx context.Context, r chatRequest) (chatAnswer, error) {
	endpoint := c.URL + "/v1/chat/completions"
	if c.anthropic() {
		endpoint = c.URL + "/v1/messages"
	}
	sent := c.body(r)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(sent))
	if err != nil {
		return chatAnswer{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+c.Token)
	if c.anthropic() {
		hr.Header.Set("Anthropic-Version", "2023-06-01")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{}
	}
	resp, err := client.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return chatAnswer{}, ctx.Err()
		}
		return chatAnswer{}, fmt.Errorf("the model could not be reached: %w", err)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, chatAnswerLargest)
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(body)
		e := &chatError{Status: resp.StatusCode, Why: errorIn(out)}
		if v := resp.Header.Get("Retry-After"); v != "" {
			if s, err := strconv.Atoi(v); err == nil && s > 0 {
				e.RetryAfter = time.Duration(s) * time.Second
			} else if at, err := http.ParseTime(v); err == nil && time.Until(at) > 0 {
				e.RetryAfter = time.Until(at)
			}
		}
		return chatAnswer{}, e
	}
	var a chatAnswer
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		a, err = c.readStream(body)
	} else {
		var out []byte
		if out, err = io.ReadAll(body); err == nil {
			a, err = c.readWhole(out)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return chatAnswer{}, ctx.Err()
		}
		return chatAnswer{}, err
	}
	a.Message.Role, a.Sent = "assistant", sent
	return a, nil
}

// errorIn is the reason an answer gives for refusing a call, in either shape.
func errorIn(out []byte) string {
	var a struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(out, &a) != nil || len(a.Error) == 0 {
		return strings.TrimSpace(printable(string(out), 300))
	}
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(a.Error, &e) == nil && e.Message != "" {
		return e.Message
	}
	return strings.Trim(string(a.Error), `"`)
}

// printable is s with what is not printable dropped, cut to n bytes.
func printable(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= ' ' && r != 0x7f {
			return r
		}
		return -1
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// readWhole reads an answer that came in one piece.
func (c chatClient) readWhole(out []byte) (chatAnswer, error) {
	var a chatAnswer
	if c.anthropic() {
		var r struct {
			Model   string `json:"model"`
			Content []struct {
				Type  string          `json:"type"`
				Text  string          `json:"text"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				In  int `json:"input_tokens"`
				Out int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(out, &r); err != nil {
			return a, errors.New("the model's answer is unreadable")
		}
		var text strings.Builder
		for _, b := range r.Content {
			switch b.Type {
			case "text":
				text.WriteString(b.Text)
			case "tool_use":
				a.Message.ToolCalls = append(a.Message.ToolCalls, chatToolCall{ID: b.ID, Name: b.Name, Arguments: string(b.Input)})
			}
		}
		a.Message.Content, a.Model, a.Stop, a.TokensIn, a.TokensOut = text.String(), r.Model, r.StopReason, r.Usage.In, r.Usage.Out
		return a, nil
	}
	var r struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			In  int `json:"prompt_tokens"`
			Out int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return a, errors.New("the model's answer is unreadable")
	}
	if len(r.Choices) == 0 {
		return a, errors.New("the model gave no answer")
	}
	ch := r.Choices[0]
	a.Message.Content = ch.Message.Content
	for _, tc := range ch.Message.ToolCalls {
		a.Message.ToolCalls = append(a.Message.ToolCalls, chatToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
	}
	a.Model, a.Stop, a.TokensIn, a.TokensOut = r.Model, ch.FinishReason, r.Usage.In, r.Usage.Out
	return a, nil
}

// readStream reads an answer as it streams, as server-sent events, putting
// its words and tool calls together from their parts.
func (c chatClient) readStream(body io.Reader) (chatAnswer, error) {
	var a chatAnswer
	var text strings.Builder
	type partial struct {
		id, name string
		args     strings.Builder
	}
	var calls []*partial
	callAt := func(i int) *partial {
		for len(calls) <= i {
			calls = append(calls, &partial{})
		}
		return calls[i]
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), chatAnswerLargest)
	ended := false
	for sc.Scan() {
		line := sc.Bytes()
		data, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue // an event's name, a comment, or the blank line between events
		}
		data = bytes.TrimSpace(data)
		if string(data) == "[DONE]" {
			ended = true
			break
		}
		if len(data) == 0 {
			continue
		}
		var ev map[string]json.RawMessage
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		if raw, ok := ev["error"]; ok && string(raw) != "null" {
			return a, &chatError{Status: http.StatusBadGateway, Why: errorIn(data)}
		}
		if c.anthropic() {
			var e struct {
				Type    string `json:"type"`
				Index   int    `json:"index"`
				Message struct {
					Model string `json:"model"`
					Usage struct {
						In  int `json:"input_tokens"`
						Out int `json:"output_tokens"`
					} `json:"usage"`
				} `json:"message"`
				ContentBlock struct {
					Type string `json:"type"`
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"content_block"`
				Delta struct {
					Type        string `json:"type"`
					Text        string `json:"text"`
					PartialJSON string `json:"partial_json"`
					StopReason  string `json:"stop_reason"`
				} `json:"delta"`
				Usage struct {
					Out int `json:"output_tokens"`
				} `json:"usage"`
			}
			if json.Unmarshal(data, &e) != nil {
				continue
			}
			switch e.Type {
			case "message_start":
				a.Model, a.TokensIn, a.TokensOut = e.Message.Model, e.Message.Usage.In, e.Message.Usage.Out
			case "content_block_start":
				if e.ContentBlock.Type == "tool_use" && e.Index >= 0 && e.Index < 1024 {
					p := callAt(e.Index)
					p.id, p.name = e.ContentBlock.ID, e.ContentBlock.Name
				}
			case "content_block_delta":
				switch e.Delta.Type {
				case "text_delta":
					text.WriteString(e.Delta.Text)
				case "input_json_delta":
					if e.Index >= 0 && e.Index < 1024 {
						callAt(e.Index).args.WriteString(e.Delta.PartialJSON)
					}
				}
			case "message_delta":
				if e.Delta.StopReason != "" {
					a.Stop = e.Delta.StopReason
				}
				if e.Usage.Out > 0 {
					a.TokensOut = e.Usage.Out
				}
			case "message_stop":
				ended = true
			}
			continue
		}
		var e struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				In  int `json:"prompt_tokens"`
				Out int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(data, &e) != nil {
			continue
		}
		if e.Model != "" {
			a.Model = e.Model
		}
		if e.Usage != nil {
			a.TokensIn, a.TokensOut = e.Usage.In, e.Usage.Out
		}
		for _, ch := range e.Choices {
			text.WriteString(ch.Delta.Content)
			for _, tc := range ch.Delta.ToolCalls {
				if tc.Index < 0 || tc.Index >= 1024 {
					continue
				}
				p := callAt(tc.Index)
				if tc.ID != "" {
					p.id = tc.ID
				}
				if tc.Function.Name != "" {
					p.name = tc.Function.Name
				}
				p.args.WriteString(tc.Function.Arguments)
			}
			if ch.FinishReason != "" {
				a.Stop = ch.FinishReason
			}
		}
	}
	if err := sc.Err(); err != nil {
		return a, fmt.Errorf("the model's answer was cut off: %w", err)
	}
	if !ended && a.Stop == "" {
		return a, &chatError{Status: http.StatusBadGateway, Why: "the model's answer ended before it was complete"}
	}
	a.Message.Content = text.String()
	for i, p := range calls {
		if p.name == "" {
			continue
		}
		id := p.id
		if id == "" {
			id = "call_" + strconv.Itoa(i)
		}
		a.Message.ToolCalls = append(a.Message.ToolCalls, chatToolCall{ID: id, Name: p.name, Arguments: p.args.String()})
	}
	return a, nil
}
