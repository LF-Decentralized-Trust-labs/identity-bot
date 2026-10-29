package agenthost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"identity-agent-core/agentmessage"
	"identity-agent-core/brainsignin"
)

// BuiltIn runs agent-host's own loop (ADR-058): `agent-host loop`, started as
// every brain's program is, by its Runner — as the brain's own user, through
// brain-env, when the host runs brains that way. It needs no program from
// anybody else, so it runs on every machine that is a body.
type BuiltIn struct {
	// Path is the agent-host program to run the loop with; empty is this one.
	Path   string
	Runner Runner
}

// builtInBrain is the name the loop is recorded under.
const builtInBrain = brainsignin.HarnessBuiltIn

// Name is the program, as the record names it.
func (BuiltIn) Name() string { return builtInBrain }

// Run runs one turn. The turn goes on stdin; the model address, the host's
// tools and anything else lent for the run go in the loop's environment.
func (b BuiltIn) Run(ctx context.Context, t Turn) (Outcome, error) {
	if credential(t.Credentials, envDirectURL) == "" || credential(t.Credentials, envDirectToken) == "" {
		return Outcome{}, errors.New("agent-host's own loop needs an API key its Identity Agent uses for it, and " +
			"none was lent for this run")
	}
	if t.Model == "" {
		return Outcome{}, errors.New("agent-host's own loop needs the name of the model to use; set it on the AI agent")
	}
	self := b.Path
	if self == "" {
		var err error
		if self, err = executable(); err != nil {
			return Outcome{}, err
		}
	}
	in, _ := json.Marshal(loopTurn{Session: t.Session, Resume: t.Resume, Prompt: t.Prompt,
		Instructions: t.Instructions, Model: t.Model})
	runner := b.Runner
	if runner == nil {
		runner = SameUser{}
	}
	// A turn out of time asks the loop to stop: it ends the command under
	// way, with everything that command started, and keeps the conversation.
	out, err := runCLIStopping(ctx, runner, t.Workspace, brainEnv(t), string(in), true, self, "loop")
	if err != nil {
		return Outcome{}, err
	}
	var res loopResult
	if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
		return Outcome{}, fmt.Errorf("the loop's answer is unreadable: %w", err)
	}
	return Outcome{Text: strings.TrimSpace(res.Text), Brain: agentmessage.Brain{
		Provider: builtInBrain, Model: firstNonEmpty(res.Model, t.Model), Session: t.Session,
		RunHash: runHash(in, out),
	}}, nil
}
