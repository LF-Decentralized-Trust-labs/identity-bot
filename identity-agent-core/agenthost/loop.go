package agenthost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

// agent-host's own loop (ADR-058): the brain's program when an AI agent's
// program is "built-in". It runs as `agent-host loop`, started like every
// brain's program — as the brain's own user, through brain-env, in its
// workspace — and so never holds the machine key. It asks the model what to
// do, uses the tools the model asks for, hands back what they gave, and asks
// again, until the model answers.
//
// It reaches the model at the body's model address, so through the Identity
// Agent, which adds the key; and the host's tools at the host's tool server.
// Both come in its environment. The turn — its words, instructions, session
// and model — comes on stdin, and what it answered goes to stdout as one JSON
// object.

// loopTurn is a turn as the host hands it to the loop.
type loopTurn struct {
	Session      string `json:"session"`
	Resume       bool   `json:"resume"`
	Prompt       string `json:"prompt"`
	Instructions string `json:"instructions"`
	Model        string `json:"model"`
}

// loopResult is what the loop tells the host when a turn is done.
type loopResult struct {
	Text      string `json:"text"`
	Model     string `json:"model,omitempty"`
	Calls     int    `json:"calls"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	// LetGo says the oldest part of the conversation was let go to fit.
	LetGo bool `json:"let_go,omitempty"`
}

// The loop's bounds on one turn.
const (
	// loopCallsMost is how many model calls one turn may make.
	loopCallsMost = 60
	// loopTokensMost is how many tokens one turn may use, as the provider
	// counts them, reasoning included.
	loopTokensMost = 1_000_000
	// loopConversationLargest is how much of the conversation is sent with a
	// call, before the oldest exchanges are let go: about a hundred thousand
	// tokens, within what the models that do work can read, and well within
	// what one model call may carry to the Identity Agent.
	loopConversationLargest = 400 << 10
	// loopKeptLargest bounds the conversation kept for the next turn.
	loopKeptLargest = 1 << 20
	// loopRetries is how many times a call refused for being busy is made
	// again, and loopWaitLongest the longest a provider may ask it to wait.
	loopRetries     = 4
	loopWaitLongest = 30 * time.Second
	// loopAnswerLongest bounds one answer where the API must be told: long
	// enough for a file written whole in one step.
	loopAnswerLongest = 16384
)

// loopDir is where the loop keeps its conversations, in the workspace.
const loopDir = ".agent-host-loop"

// loopEnv are the variables only the loop itself uses, never a command it
// runs.
var loopEnv = []string{envDirectURL, envDirectToken, envDirectAPI, envToolsURL, envToolsToken}

// ServeLoop is `agent-host loop`.
func ServeLoop(stdin io.Reader, stdout, stderr io.Writer) int {
	// Nothing else running as this user may read this process or trace it:
	// its environment and memory hold the run's tokens.
	if err := notReadable(); err != nil {
		fmt.Fprintf(stderr, "agent-host loop: this process could not be kept from other processes: %v\n", err)
		return 1
	}
	vars := map[string]string{}
	for _, n := range loopEnv {
		vars[n] = os.Getenv(n)
		_ = os.Unsetenv(n)
	}
	var t loopTurn
	if err := json.NewDecoder(io.LimitReader(stdin, 16<<20)).Decode(&t); err != nil {
		fmt.Fprintln(stderr, "agent-host loop: started without a turn; it is started by agent-host, never by hand")
		return 2
	}
	workspace, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "agent-host loop: %v\n", err)
		return 1
	}
	l := &loop{
		model: chatClient{URL: vars[envDirectURL], Token: vars[envDirectToken], API: vars[envDirectAPI]},
		tools: hostTools{URL: vars[envToolsURL], Token: vars[envToolsToken]},
		dir:   workspace,
	}
	ctx, stop := signal.NotifyContext(context.Background(), interruptSignals()...)
	defer stop()
	res, err := l.run(ctx, t)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(res)
	return 0
}

// loop is one turn of agent-host's own loop.
type loop struct {
	model chatClient
	tools hostTools
	// dir is the workspace.
	dir string
	// pause waits before a call is made again; nil is time.After.
	pause func(time.Duration) <-chan time.Time
}

// run runs one turn.
func (l *loop) run(ctx context.Context, t loopTurn) (loopResult, error) {
	if l.model.URL == "" || l.model.Token == "" {
		return loopResult{}, errors.New("agent-host's own loop needs an API key its Identity Agent uses for it, " +
			"and none was lent for this run")
	}
	if t.Model == "" {
		return loopResult{}, errors.New("agent-host's own loop needs the name of the model to use; set it on the AI agent")
	}
	path, err := loopHistory(l.dir, t.Session)
	if err != nil {
		return loopResult{}, err
	}
	var history []chatMessage
	if t.Resume {
		b, err := readBounded(path, loopKeptLargest+loopKeptLargest/4)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return loopResult{}, fmt.Errorf("the conversation so far could not be read: %w", err)
		}
		if err == nil && json.Unmarshal(b, &history) != nil {
			return loopResult{}, errors.New("the conversation so far is unreadable")
		}
	}
	if len(t.Prompt)+len(t.Instructions) > loopConversationLargest/2 {
		// What was asked is sent whole with every call; past this it would be
		// most of what the model can read.
		return loopResult{}, fmt.Errorf("what this turn was asked, with the AI agent's instructions, is larger "+
			"than %d KB, more than agent-host's own loop sends a model", loopConversationLargest/2>>10)
	}
	history = append(whole(history), chatMessage{Role: "user", Content: t.Prompt})
	tools := l.toolList()
	var res loopResult
	budget := loopConversationLargest
	// keep saves the conversation, up to its last whole step, whatever became
	// of the turn.
	keep := func() error {
		kept, _ := fitted(whole(history), loopKeptLargest)
		b, _ := json.Marshal(kept)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("the conversation could not be kept for its next turn: %w", err)
		}
		// Written aside and moved into place, so a turn ended mid-write leaves
		// the conversation as it was rather than half of it.
		tmp := path + ".new"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return fmt.Errorf("the conversation could not be kept for its next turn: %w", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("the conversation could not be kept for its next turn: %w", err)
		}
		return nil
	}
	for {
		if res.Calls >= loopCallsMost || res.TokensIn+res.TokensOut >= loopTokensMost {
			// Its words so far are its answer, and it says why it stopped.
			res.Text = strings.TrimSpace(lastWords(history) + "\n\n" + fmt.Sprintf("(I stopped before finishing: "+
				"this turn reached its limit of %d model calls or %d tokens.)", loopCallsMost, loopTokensMost))
			return res, keep()
		}
		sent, letGo := fitted(history, budget)
		if letGo {
			res.LetGo = true
		}
		instructions := t.Instructions + "\n\n" + l.guidance()
		if letGo {
			instructions += "\n\nThe oldest part of this conversation was let go to fit what you can read; " +
				"what remains is all you are shown of it."
		}
		a, err := l.call(ctx, chatRequest{Model: t.Model, Instructions: instructions, Messages: sent,
			Tools: tools, Stream: true, MaxTokens: loopAnswerLongest}, &res)
		var ce *chatError
		if errors.As(err, &ce) && ce.tooLong() && budget > loopConversationLargest/4 {
			budget /= 2
			continue
		}
		if err != nil {
			_ = keep()
			return res, err
		}
		if a.Model != "" {
			res.Model = a.Model
		}
		history = append(history, a.Message)
		if len(a.Message.ToolCalls) == 0 {
			res.Text = strings.TrimSpace(a.Message.Content)
			return res, keep()
		}
		replied, said := false, ""
		for _, tc := range a.Message.ToolCalls {
			text, ok := l.use(ctx, tc)
			if tc.Name == "reply" && ok {
				var r struct {
					Text string `json:"text"`
				}
				_ = json.Unmarshal([]byte(tc.Arguments), &r)
				replied, said = true, r.Text
			}
			history = append(history, chatMessage{Role: "tool", ToolCallID: tc.ID, Content: text})
		}
		if replied {
			// The answer is given: no call is made only to hear the model say it
			// is done.
			res.Text = strings.TrimSpace(said)
			return res, keep()
		}
		if ctx.Err() != nil {
			_ = keep()
			return res, errors.New("the brain did not finish in time")
		}
	}
}

// call makes one model call, again when it was refused for being busy.
func (l *loop) call(ctx context.Context, r chatRequest, res *loopResult) (chatAnswer, error) {
	wait := 2 * time.Second
	for try := 0; ; try++ {
		res.Calls++
		a, err := l.model.Call(ctx, r)
		in, out := a.TokensIn, a.TokensOut
		if err == nil && in == 0 && out == 0 {
			// The provider said nothing of what the call used: it is counted
			// as about a token for every four bytes each way, so the turn's
			// bound still holds.
			in = len(a.Sent) / 4
			out = len(a.Message.Content) / 4
			for _, tc := range a.Message.ToolCalls {
				out += len(tc.Arguments) / 4
			}
		}
		res.TokensIn += in
		res.TokensOut += out
		if err != nil && ctx.Err() != nil {
			return a, ctx.Err()
		}
		var ce *chatError
		if err == nil || try >= loopRetries || res.Calls >= loopCallsMost ||
			(errors.As(err, &ce) && (!ce.worthRetrying() || ce.RetryAfter > loopWaitLongest)) {
			// A provider that asks to be left longer is not asked again now.
			return a, err
		}
		pause := wait
		if ce != nil && ce.RetryAfter > pause {
			pause = ce.RetryAfter
		}
		after := time.After
		if l.pause != nil {
			after = l.pause
		}
		select {
		case <-after(pause):
		case <-ctx.Done():
			// The turn ended while waiting: that, not the refusal, is why.
			return a, ctx.Err()
		}
		wait *= 2
	}
}

// guidance is what the loop tells the model about how it works.
func (l *loop) guidance() string {
	return "You work by using tools: run_command runs a command in the system shell, read_file, write_file " +
		"and replace_in_file work on files, and list_files and search_files find them. Your working directory is " +
		l.dir + "; a path that is not absolute is taken from it. Work step by step, look at what each tool gives " +
		"you, and when you are done, answer with reply, once, as the last thing you do."
}

// lastWords is the model's latest words in the conversation.
func lastWords(h []chatMessage) string {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Role == "assistant" && strings.TrimSpace(h[i].Content) != "" {
			return h[i].Content
		}
		if h[i].Role == "user" {
			break
		}
	}
	return ""
}

// readBounded reads a file of at most most bytes.
func readBounded(path string, most int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(most)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > most {
		return nil, fmt.Errorf("it is larger than %d KB", most>>10)
	}
	return b, nil
}

// loopHistory is where a session's conversation is kept.
func loopHistory(workspace, session string) (string, error) {
	if _, err := directHistory(workspace, session); err != nil {
		return "", err
	}
	return filepath.Join(workspace, loopDir, session+".json"), nil
}

// whole is the conversation up to its last whole step: every tool the model
// asked for followed by what it gave. A step cut off — by a failure, or a
// conversation kept by an older version — is let go, so no API refuses it.
func whole(h []chatMessage) []chatMessage {
	out := make([]chatMessage, 0, len(h))
	for i := 0; i < len(h); {
		m := h[i]
		if m.Role == "tool" {
			i++ // what a tool gave, with no request for it
			continue
		}
		if m.Role != "assistant" || len(m.ToolCalls) == 0 {
			out = append(out, m)
			i++
			continue
		}
		asked := map[string]bool{}
		for _, tc := range m.ToolCalls {
			asked[tc.ID] = true
		}
		// Only one answer to each of the step's own requests is kept: an
		// answer to nothing it asked is refused by every API.
		answers := []chatMessage{}
		answered := map[string]bool{}
		j := i + 1
		for ; j < len(h) && h[j].Role == "tool"; j++ {
			if id := h[j].ToolCallID; asked[id] && !answered[id] {
				answered[id] = true
				answers = append(answers, h[j])
			}
		}
		if len(answered) != len(asked) {
			break
		}
		out = append(append(out, m), answers...)
		i = j
	}
	return out
}

// fitted is the conversation within size bytes: the oldest exchanges are let
// go, whole and several at once — down to three quarters of size, so the
// start of what is sent stays the same for several calls and a provider can
// serve it from its cache — always starting at something asked. The newest
// exchange is always kept. It reports whether anything was let go.
func fitted(h []chatMessage, size int) ([]chatMessage, bool) {
	total := 0
	sizes := make([]int, len(h))
	for i, m := range h {
		sizes[i] = len(m.Content) + 64
		for _, tc := range m.ToolCalls {
			sizes[i] += len(tc.Name) + len(tc.Arguments) + len(tc.ID) + 32
		}
		total += sizes[i]
	}
	if total <= size {
		return h, false
	}
	// Each exchange starts at something asked.
	var starts []int
	for i, m := range h {
		if m.Role == "user" {
			starts = append(starts, i)
		}
	}
	target := size * 3 / 4
	from := 0
	if len(starts) > 1 {
		for _, s := range starts[1:] {
			for _, n := range sizes[from:s] {
				total -= n
			}
			from = s
			if total <= target {
				break
			}
		}
	}
	if total <= size || len(starts) == 0 {
		return h[from:], from > 0
	}
	// The newest exchange alone is too large: its oldest steps are let go,
	// each one the model's request and what its tools gave, keeping what was
	// asked and the newest step.
	asked := starts[len(starts)-1]
	var steps []int
	for i := asked + 1; i < len(h); i++ {
		if h[i].Role == "assistant" {
			steps = append(steps, i)
		}
	}
	cut := asked + 1
	for _, s := range steps {
		if total <= target {
			break
		}
		if s == steps[len(steps)-1] {
			break
		}
		for _, n := range sizes[cut:s] {
			total -= n
		}
		cut = s
	}
	if cut == asked+1 {
		return h[from:], from > 0
	}
	out := append([]chatMessage{h[asked]}, h[cut:]...)
	return out, true
}

// use runs one tool the model asked for, and says what it gave and whether
// it worked. A tool that fails says why, and the model carries on.
func (l *loop) use(ctx context.Context, tc chatToolCall) (string, bool) {
	args := json.RawMessage(tc.Arguments)
	if strings.TrimSpace(tc.Arguments) == "" {
		args = json.RawMessage("{}")
	}
	if !json.Valid(args) {
		return "Error: the arguments are not valid JSON; send them again as one JSON object.", false
	}
	for _, d := range toolDescriptions {
		if d["name"] == tc.Name {
			text, isErr := l.tools.call(ctx, tc.Name, args)
			if isErr {
				return "Error: " + cut(text, toolShown), false
			}
			return cut(text, toolShown), true
		}
	}
	w := workTools{dir: l.dir}
	text, err := w.use(ctx, tc.Name, args)
	if err != nil {
		return "Error: " + err.Error(), false
	}
	return text, true
}

// toolList is every tool the model may use: the host's, and the loop's own.
func (l *loop) toolList() []chatTool {
	var out []chatTool
	for _, d := range toolDescriptions {
		out = append(out, chatTool{Name: d["name"].(string), Description: d["description"].(string),
			Schema: d["inputSchema"].(map[string]any)})
	}
	return append(out, workToolList...)
}
