package agenthost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"identity-agent-core/agentmessage"
)

// Codex runs `codex exec --json` with the full use of its machine, and the
// host's tools as its only way to the Identity Agent.
//
// It is told about the host's tool server on its command line (-c), which
// carries the program's path and the names of the variables holding the tool
// address and token, never their values. It does not read the settings of
// whoever runs it (--ignore-user-config), so a person's own connections to
// the Identity Agent do not come with it. A sign-in borrowed from the Identity
// Agent is put in a home of the host's making for the run (brainHome); with
// none, Codex uses whatever this machine signed it in with.
//
// Codex names its own sessions, so the first turn of a conversation reports
// the session Codex started and later turns resume that one.
//
// Unlike Claude Code, Codex has no local setting for the credit line it asks
// its model to add to commits ("Co-authored-by: Codex") and pull requests: it
// reads the signed-in ChatGPT account's commit-attribution preference from
// OpenAI on each session, and asks for none under an API key. So the host
// cannot turn it off per run; the account's own preference does.
type Codex struct {
	Path   string
	Runner Runner
}

// Name is the provider.
func (Codex) Name() string { return "codex" }

// Run runs one turn.
func (c Codex) Run(ctx context.Context, t Turn) (Outcome, error) {
	self, err := executable()
	if err != nil {
		return Outcome{}, err
	}
	flags := []string{"--json", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
		"--ignore-user-config",
		"-c", "mcp_servers." + mcpServerName + ".command=" + strconv.Quote(self),
		"-c", "mcp_servers." + mcpServerName + `.args=["mcp"]`,
		"-c", "mcp_servers." + mcpServerName + `.env_vars=["` + envToolsURL + `","` + envToolsToken + `"]`}
	home, creds := homeIn(t.Credentials)
	if home != nil {
		// The lent sign-in is a file in the run's home, never the keyring.
		flags = append(flags, "-c", `cli_auth_credentials_store="file"`)
	}
	if t.Model != "" {
		flags = append(flags, "--model", t.Model)
	}
	args := []string{"exec"}
	if t.Resume {
		args = append(append(append(args, "resume"), flags...), t.Session, "-")
	} else {
		args = append(append(args, flags...), "-")
	}
	prompt := withInstructions(t)
	var out []byte
	var refreshed string
	if home != nil {
		out, refreshed, err = runInHome(ctx, c.runner(), t.Workspace, append(toolsEnv(t), creds...), *home, prompt,
			c.path(), args...)
	} else {
		out, err = runCLI(ctx, c.runner(), t.Workspace, brainEnv(t), prompt, c.path(), args...)
	}
	if err != nil {
		return Outcome{refreshed: refreshed}, err
	}
	text, session, failed := readCodexOutput(out)
	if failed != "" {
		return Outcome{refreshed: refreshed}, fmt.Errorf("the brain reported an error: %s", failed)
	}
	if text == "" {
		return Outcome{refreshed: refreshed}, errors.New("the brain gave no answer")
	}
	return Outcome{Text: text, refreshed: refreshed, Brain: agentmessage.Brain{
		Provider: c.Name(), Model: t.Model, Session: firstNonEmpty(session, t.Session),
		RunHash: runHash([]byte(prompt), out),
	}}, nil
}

// readCodexOutput reads `codex exec --json`, one event a line: the session
// from "thread.started", the last of the brain's messages, and why a turn
// failed.
func readCodexOutput(out []byte) (text, session, failed string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type     string `json:"type"`
			ThreadID string `json:"thread_id"`
			Message  string `json:"message"`
			Item     struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"item"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "thread.started":
			session = ev.ThreadID
		case "item.completed":
			if ev.Item.Type == "agent_message" {
				text = strings.TrimSpace(ev.Item.Text)
			}
		case "turn.failed":
			failed = firstNonEmpty(ev.Error.Message, "the turn failed")
		case "error":
			failed = firstNonEmpty(ev.Message, "the turn failed")
		}
	}
	if text != "" {
		failed = ""
	}
	return text, session, failed
}

func (c Codex) path() string {
	if c.Path != "" {
		return c.Path
	}
	return "codex"
}

func (c Codex) runner() Runner {
	if c.Runner != nil {
		return c.Runner
	}
	return SameUser{}
}
