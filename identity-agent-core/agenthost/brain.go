package agenthost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/iacrypto"
)

// A brain is the model that decides what an AI agent says. The host runs it on
// this machine, gives it the host's tools and nothing else, and hands it one
// message at a time. Changing the brain does not change who the AI agent is.

// Turn is one run of the brain: a prompt, in a conversation's session.
type Turn struct {
	// Session is the conversation's session id; Resume says whether the brain
	// has already run in it.
	Session string
	Resume  bool
	Prompt  string
	// Instructions are added to the brain's own system prompt.
	Instructions string
	// Workspace is the directory the brain runs in, and the only one it should
	// write to.
	Workspace string
	// Tools is how the brain reaches the host's tools: the local address of the
	// host's tool server, and this turn's token for it.
	ToolsURL, ToolsToken string
	// Model, when set, names the model to use.
	Model string
}

// Outcome is what a turn produced.
type Outcome struct {
	// Text is the brain's final words for the turn.
	Text string
	// Brain is what the host reports, signed, about what produced the words.
	Brain agentmessage.Brain
}

// Brain runs turns.
type Brain interface {
	// Name is the provider, as the record names it.
	Name() string
	Run(ctx context.Context, t Turn) (Outcome, error)
}

// ToolNames are the host's tools as a brain addresses them over MCP.
var ToolNames = []string{"reply", "ask_agent", "list_agents", "conversation_history", "system_info"}

// mcpServerName is what the host's tool server is called in a brain's config.
const mcpServerName = "agenthost"

// Runner starts a brain's process: directly, or as another operating-system
// user, so that a brain talked into misusing a tool still cannot reach the
// person's own files.
type Runner interface {
	Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error)
}

// Isolated is a Runner that starts the brain as a user of its own, so the
// brain sees only that user's files and configuration.
type Isolated interface {
	Isolated() bool
}

// SameUser runs the brain as the user running the host: right on a machine
// that is only the AI agent's, where there is nobody else's keys to keep it
// from.
type SameUser struct{}

// Command builds the command.
func (SameUser) Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd, nil
}

// executable is this agent-host program, which the brain starts as its MCP
// server.
func executable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// runHash is a digest of everything a run was sent and returned.
func runHash(parts ...[]byte) string {
	return iacrypto.Blake3QB64Must(bytes.Join(parts, []byte{0}))
}

// NewSession is a fresh session id, in the UUID form both CLIs take.
func NewSession() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// runCLI runs a brain's command, giving it stdin, and returns what it
// printed. A brain that fails says why: its own error output, trimmed, which
// becomes the failure notice's reason.
//
// Nothing secret goes on the command line, which any user on the machine can
// read while it runs and sudo writes to the system log, and nothing goes in a
// file another user might find: the words and instructions travel on stdin,
// and the tool token in the environment.
func runCLI(ctx context.Context, r Runner, dir string, env []string, stdin string, name string, args ...string) ([]byte, error) {
	cmd, err := r.Command(ctx, dir, env, name, args...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Stdin = strings.NewReader(stdin)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("the brain did not finish in time")
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, fmt.Errorf("the brain stopped: %v: %s", err, msg)
	}
	return stdout.Bytes(), nil
}

// ── Claude Code ──────────────────────────────────────────────────────────────

// ClaudeCode runs `claude -p` with the full use of its machine, and the host's
// tools as its only way to the Identity Agent.
//
// The machine is the AI agent's to use, so the brain keeps Claude Code's own
// tools and is never stopped to ask (bypassPermissions). What it does not get
// is any other route to the Identity Agent: --strict-mcp-config loads no MCP
// server but the host's, so it reaches the Identity Agent only as its AI agent,
// under that AI agent's grant — never through a connection a person set up
// with their own token. On a machine a person also uses, the brain runs as its
// own user so it cannot use that person's keys either.
type ClaudeCode struct {
	Path   string
	Runner Runner
}

// Name is the provider.
func (ClaudeCode) Name() string { return "claude-code" }

// Run runs one turn. The prompt goes on stdin, led on the first turn by the
// instructions — the session keeps them for the turns after — and the tool
// token reaches the host's MCP server through the environment it inherits.
func (c ClaudeCode) Run(ctx context.Context, t Turn) (Outcome, error) {
	self, err := executable()
	if err != nil {
		return Outcome{}, err
	}
	mcp, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		mcpServerName: map[string]any{"command": self, "args": []string{"mcp"}},
	}})
	args := []string{"-p", "--output-format", "json",
		"--mcp-config", string(mcp), "--strict-mcp-config",
		"--permission-mode", "bypassPermissions"}
	if t.Resume {
		args = append(args, "--resume", t.Session)
	} else {
		args = append(args, "--session-id", t.Session)
	}
	if t.Model != "" {
		args = append(args, "--model", t.Model)
	}
	prompt := withInstructions(t)
	out, err := runCLI(ctx, c.runner(), t.Workspace, toolsEnv(t), prompt, c.path(), args...)
	if err != nil {
		return Outcome{}, err
	}
	var res struct {
		Result     string         `json:"result"`
		IsError    bool           `json:"is_error"`
		SessionID  string         `json:"session_id"`
		Subtype    string         `json:"subtype"`
		ModelUsage map[string]any `json:"modelUsage"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return Outcome{}, fmt.Errorf("the brain's answer is unreadable: %w", err)
	}
	if res.IsError {
		return Outcome{}, fmt.Errorf("the brain reported an error (%s): %s", res.Subtype, res.Result)
	}
	model := t.Model
	for m := range res.ModelUsage {
		model = m
		break
	}
	return Outcome{Text: strings.TrimSpace(res.Result), Brain: agentmessage.Brain{
		Provider: c.Name(), Model: model, Session: firstNonEmpty(res.SessionID, t.Session),
		RunHash: runHash([]byte(prompt), out),
	}}, nil
}

// withInstructions is the turn's prompt, led on a session's first turn by the
// instructions. Neither CLI can be given its system prompt from stdin, and a
// file holding it would be a file another user might read.
func withInstructions(t Turn) string {
	if t.Instructions == "" || t.Resume {
		return t.Prompt
	}
	return t.Instructions + "\n\n---\n\n" + t.Prompt
}

func (c ClaudeCode) path() string {
	if c.Path != "" {
		return c.Path
	}
	return "claude"
}

func (c ClaudeCode) runner() Runner {
	if c.Runner != nil {
		return c.Runner
	}
	return SameUser{}
}

// ── Grok CLI ─────────────────────────────────────────────────────────────────

// GrokCLI runs `grok -p` with the full use of its machine, and the host's
// tools as its only way to the Identity Agent.
//
// Grok CLI loads the MCP servers of whoever runs it and has no flag to ignore
// them, so a person's own connections to the Identity Agent would come with
// it. It therefore runs only as the brain's own operating-system user
// (AsUser), whose configuration holds nothing but what the host gives it: the
// host's MCP server, configured for the workspace before each turn. Every tool
// is approved without asking.
type GrokCLI struct {
	Path   string
	Runner Runner
}

// Name is the provider.
func (GrokCLI) Name() string { return "grok" }

// Run runs one turn.
func (g GrokCLI) Run(ctx context.Context, t Turn) (Outcome, error) {
	if r, ok := g.runner().(Isolated); !ok || !r.Isolated() {
		return Outcome{}, errors.New("Grok CLI loads the MCP servers and permissions of whoever runs it, so it runs " +
			"only as the brain's own user: run agent-host with --brain-user (see agent-host brain-user)")
	}
	self, err := executable()
	if err != nil {
		return Outcome{}, err
	}
	if _, err := runCLI(ctx, g.runner(), t.Workspace, nil, "", g.path(), "mcp", "add", "--scope", "project",
		mcpServerName, self, "--", "mcp"); err != nil {
		return Outcome{}, fmt.Errorf("the host's tools could not be given to Grok: %w", err)
	}
	prompt := withInstructions(t)
	// The prompt is read from the brain's own stdin: no file, and nothing on
	// the command line.
	args := []string{"--prompt-file", "/dev/stdin", "--output-format", "json",
		"--always-approve"}
	if t.Resume {
		args = append(args, "--resume", t.Session)
	} else {
		args = append(args, "--session-id", t.Session)
	}
	if t.Model != "" {
		args = append(args, "--model", t.Model)
	}
	out, err := runCLI(ctx, g.runner(), t.Workspace, toolsEnv(t), prompt, g.path(), args...)
	if err != nil {
		return Outcome{}, err
	}
	text, model, session := readGrokOutput(out)
	if text == "" {
		return Outcome{}, errors.New("the brain gave no answer")
	}
	return Outcome{Text: text, Brain: agentmessage.Brain{
		Provider: g.Name(), Model: firstNonEmpty(model, t.Model), Session: firstNonEmpty(session, t.Session),
		RunHash: runHash([]byte(prompt), out),
	}}, nil
}

// readGrokOutput reads `grok --output-format json`: the final words under
// "text", the session under "sessionId", and the model as the key of
// "modelUsage". A run that stopped without finishing is a failed turn.
func readGrokOutput(out []byte) (text, model, session string) {
	var res struct {
		Text       string         `json:"text"`
		StopReason string         `json:"stopReason"`
		SessionID  string         `json:"sessionId"`
		ModelUsage map[string]any `json:"modelUsage"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
		return "", "", ""
	}
	for m := range res.ModelUsage {
		model = m
		break
	}
	if res.StopReason == "cancelled" {
		return "", model, res.SessionID
	}
	return strings.TrimSpace(res.Text), model, res.SessionID
}

func (g GrokCLI) path() string {
	if g.Path != "" {
		return g.Path
	}
	return "grok"
}

func (g GrokCLI) runner() Runner {
	if g.Runner != nil {
		return g.Runner
	}
	return SameUser{}
}

// toolsEnv is how the host's MCP server, started by the brain, finds the
// host's tools for this turn: in the environment it inherits, never on a
// command line.
func toolsEnv(t Turn) []string {
	return []string{envToolsURL + "=" + t.ToolsURL, envToolsToken + "=" + t.ToolsToken}
}

// BrainFor is the brain an AI agent was created with, by its provider.
func BrainFor(provider string, r Runner) (Brain, error) {
	switch provider {
	case "", "claude-code":
		return ClaudeCode{Runner: r}, nil
	case "grok":
		return GrokCLI{Runner: r}, nil
	}
	return nil, fmt.Errorf("this host does not run %q as a brain; it runs claude-code and grok", provider)
}

// turnTimeout bounds one turn of the brain.
const turnTimeout = 10 * time.Minute

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
