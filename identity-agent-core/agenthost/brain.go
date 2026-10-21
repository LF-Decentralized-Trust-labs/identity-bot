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
var ToolNames = []string{"reply", "ask_agent", "list_agents", "system_info"}

// mcpServerName is what the host's tool server is called in a brain's config.
const mcpServerName = "agenthost"

// qualifiedTools are the tool names as Claude Code and Grok CLI address an MCP
// server's tools in an allow rule.
func qualifiedTools() []string {
	out := make([]string, len(ToolNames))
	for i, n := range ToolNames {
		out[i] = "mcp__" + mcpServerName + "__" + n
	}
	return out
}

// Runner starts a brain's process: directly, or as another operating-system
// user, so that a brain talked into misusing a tool still cannot reach the
// person's own files.
type Runner interface {
	Command(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error)
}

// SameUser runs the brain as the user running the host. The tool allow list
// is then the only thing keeping it to the host's tools.
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

// runCLI runs a brain's command and returns what it printed. A brain that
// fails says why: its own error output, trimmed, which becomes the failure
// notice's reason.
func runCLI(ctx context.Context, r Runner, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd, err := r.Command(ctx, dir, env, name, args...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Stdin = nil
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

// ClaudeCode runs `claude -p` with the host's tools as its only tools.
//
// --permission-mode dontAsk refuses every tool not on --allowedTools, so the
// built-in file, shell and web tools are refused by Claude Code's own
// permission system, not by asking the model nicely. --strict-mcp-config means
// no MCP server but the host's is loaded.
type ClaudeCode struct {
	Path   string
	Runner Runner
}

// Name is the provider.
func (ClaudeCode) Name() string { return "claude-code" }

// Run runs one turn.
func (c ClaudeCode) Run(ctx context.Context, t Turn) (Outcome, error) {
	self, err := executable()
	if err != nil {
		return Outcome{}, err
	}
	mcp, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{
		mcpServerName: map[string]any{
			"command": self, "args": []string{"mcp"},
			"env": map[string]string{envToolsURL: t.ToolsURL, envToolsToken: t.ToolsToken},
		},
	}})
	args := []string{"-p", t.Prompt, "--output-format", "json",
		"--mcp-config", string(mcp), "--strict-mcp-config",
		"--allowedTools", strings.Join(qualifiedTools(), ","),
		"--permission-mode", "dontAsk"}
	if t.Resume {
		args = append(args, "--resume", t.Session)
	} else {
		args = append(args, "--session-id", t.Session)
	}
	if t.Instructions != "" {
		args = append(args, "--append-system-prompt", t.Instructions)
	}
	if t.Model != "" {
		args = append(args, "--model", t.Model)
	}
	out, err := runCLI(ctx, c.runner(), t.Workspace, nil, c.path(), args...)
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
		RunHash: runHash([]byte(t.Prompt), out),
	}}, nil
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

// GrokCLI runs `grok -p` the same way: the host's tools as its only tools,
// built-in tools removed, permission mode dontAsk.
//
// Grok CLI takes MCP servers from a config file rather than a flag, so the
// host writes the workspace's project config before each turn, with that
// turn's token, using Grok CLI's own command so the file is in its format.
type GrokCLI struct {
	Path   string
	Runner Runner
}

// Name is the provider.
func (GrokCLI) Name() string { return "grok" }

// Run runs one turn.
func (g GrokCLI) Run(ctx context.Context, t Turn) (Outcome, error) {
	self, err := executable()
	if err != nil {
		return Outcome{}, err
	}
	if _, err := runCLI(ctx, g.runner(), t.Workspace, nil, g.path(), "mcp", "add", "--scope", "project",
		"-e", envToolsURL+"="+t.ToolsURL, "-e", envToolsToken+"="+t.ToolsToken,
		mcpServerName, self, "--", "mcp"); err != nil {
		return Outcome{}, fmt.Errorf("the host's tools could not be given to Grok: %w", err)
	}
	prompt := t.Prompt
	if t.Instructions != "" && !t.Resume {
		// Grok CLI replaces rather than extends a system prompt, so the
		// instructions lead the first message instead.
		prompt = t.Instructions + "\n\n" + t.Prompt
	}
	args := []string{"-p", prompt, "--output-format", "json",
		"--permission-mode", "dontAsk", "--tools", "", "--disable-web-search", "--no-subagents"}
	for _, q := range qualifiedTools() {
		args = append(args, "--allow", q)
	}
	if t.Resume {
		args = append(args, "--resume", t.Session)
	} else {
		args = append(args, "--session-id", t.Session)
	}
	if t.Model != "" {
		args = append(args, "--model", t.Model)
	}
	out, err := runCLI(ctx, g.runner(), t.Workspace, nil, g.path(), args...)
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

// readGrokOutput reads `grok -p --output-format json`. The format is read
// leniently — the final text under any of the names it has used — because a
// brain whose words cannot be read is a failed turn, and the host says so
// rather than guessing.
func readGrokOutput(out []byte) (text, model, session string) {
	var res map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
		return strings.TrimSpace(string(out)), "", ""
	}
	for _, k := range []string{"result", "text", "content", "response", "message"} {
		if v, ok := res[k].(string); ok && strings.TrimSpace(v) != "" {
			text = strings.TrimSpace(v)
			break
		}
	}
	model, _ = res["model"].(string)
	for _, k := range []string{"session_id", "sessionId", "session"} {
		if v, ok := res[k].(string); ok {
			session = v
			break
		}
	}
	return text, model, session
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
