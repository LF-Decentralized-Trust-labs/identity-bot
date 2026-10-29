package agenthost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"identity-agent-core/agentmessage"
	"identity-agent-core/brainsignin"
)

// DirectModel is the brain of an AI agent that only reads and answers. No
// program runs: the host itself calls the model, at this body's model address
// and so through the Identity Agent, which adds the key. It has no tools and
// cannot use the machine; its words are its answer.
//
// The conversation so far is kept in the workspace, one file per session, so
// the next turn of the conversation carries on from it.
type DirectModel struct {
	// HTTP sends the model calls; nil is a client with no time limit beyond
	// the turn's.
	HTTP *http.Client
}

// directBrain is the name a DirectModel is recorded under.
const directBrain = "model"

// Name is the provider, as the record names it.
func (DirectModel) Name() string { return directBrain }

// The variables a DirectModel finds its model address in, among the turn's
// credentials (Borrowed.envThroughIdentityAgent).
const (
	envDirectURL   = "AGENT_HOST_MODEL_URL"
	envDirectToken = "AGENT_HOST_MODEL_TOKEN"
	envDirectAPI   = "AGENT_HOST_MODEL_API"
)

// directHistoryLargest bounds the conversation sent with each turn, and kept:
// the oldest turns are let go first. It is well under what one model call
// may carry to the Identity Agent.
const directHistoryLargest = 1 << 20

func credential(creds []string, name string) string {
	for _, kv := range creds {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

// directHistory is where a session's conversation is kept.
func directHistory(workspace, session string) (string, error) {
	if session == "" || len(session) > 128 || strings.Trim(session, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return "", fmt.Errorf("not a session: %q", session)
	}
	return filepath.Join(workspace, ".agent-host-model", session+".json"), nil
}

// Run runs one turn.
func (d DirectModel) Run(ctx context.Context, t Turn) (Outcome, error) {
	url, token, api := credential(t.Credentials, envDirectURL), credential(t.Credentials, envDirectToken),
		credential(t.Credentials, envDirectAPI)
	if url == "" || token == "" {
		return Outcome{}, errors.New("an AI agent that only reads and answers needs an API key its Identity Agent " +
			"uses for it, and none was lent for this run")
	}
	if t.Model == "" {
		return Outcome{}, errors.New("an AI agent that only reads and answers needs the name of the model to use; set it on the AI agent")
	}
	path, err := directHistory(t.Workspace, t.Session)
	if err != nil {
		return Outcome{}, err
	}
	var history []chatMessage
	if t.Resume {
		b, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Outcome{}, fmt.Errorf("the conversation so far could not be read: %w", err)
		}
		if err == nil && json.Unmarshal(b, &history) != nil {
			return Outcome{}, errors.New("the conversation so far is unreadable")
		}
	}
	history = trimHistory(append(history, chatMessage{Role: "user", Content: t.Prompt}))

	c := chatClient{URL: url, Token: token, API: api, HTTP: d.HTTP}
	a, err := c.Call(ctx, chatRequest{Model: t.Model, Instructions: t.Instructions, Messages: history})
	if err != nil {
		return Outcome{}, err
	}
	text := a.Message.Content
	if text == "" {
		return Outcome{}, errors.New("the model gave no answer")
	}
	history = trimHistory(append(history, chatMessage{Role: "assistant", Content: text}))
	b, _ := json.Marshal(history)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Outcome{}, fmt.Errorf("the conversation could not be kept for its next turn: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return Outcome{}, fmt.Errorf("the conversation could not be kept for its next turn: %w", err)
	}
	answer, _ := json.Marshal(a.Message)
	return Outcome{Text: strings.TrimSpace(text), Brain: agentmessage.Brain{
		Provider: directBrain, Model: firstNonEmpty(a.Model, t.Model), Session: t.Session,
		RunHash: runHash(a.Sent, answer),
	}}, nil
}

// trimHistory lets the oldest turns go until the conversation is within
// directHistoryLargest, keeping at least the newest message. Only words are
// kept here: an AI agent that only answers uses no tools.
func trimHistory(h []chatMessage) []chatMessage {
	words := h[:0:0]
	for _, m := range h {
		if (m.Role == "user" || m.Role == "assistant") && m.Content != "" {
			words = append(words, chatMessage{Role: m.Role, Content: m.Content})
		}
	}
	h = words
	size := 0
	for _, m := range h {
		size += len(m.Content) + 32
	}
	for len(h) > 1 && (size > directHistoryLargest || h[0].Role != "user") {
		// A conversation starts with what was asked: both APIs require it.
		size -= len(h[0].Content) + 32
		h = h[1:]
	}
	return h
}

// envForDirect is the environment of a model call agent-host makes itself — a
// DirectModel's, or its own loop's (BuiltIn): its body's model address, the
// run's token for it, and which API its provider speaks.
func (b *Borrowed) envForDirect() ([]string, error) {
	if !b.throughIdentityAgent {
		return nil, fmt.Errorf("agent-host calls a model itself only with an API key its Identity Agent uses "+
			"for it, not a %s for %s", b.Kind, b.Provider)
	}
	if b.modelURL == "" || b.modelToken == "" {
		return nil, errors.New("this machine gave the run no model address")
	}
	// OpenAI, xAI and OpenRouter all take OpenAI's chat; which of them it is
	// decides only how the answer's length is named.
	api := b.Provider
	switch b.Provider {
	case brainsignin.Anthropic:
		api = "anthropic"
	case brainsignin.OpenAI, brainsignin.XAI, brainsignin.OpenRouter:
	default:
		return nil, fmt.Errorf("agent-host cannot call %s itself", b.Provider)
	}
	return []string{envDirectURL + "=" + b.modelURL, envDirectToken + "=" + b.modelToken, envDirectAPI + "=" + api}, nil
}
