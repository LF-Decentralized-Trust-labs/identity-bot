package agenthost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// directAnswerLargest bounds the words of an answer.
const directAnswerLargest = 8 << 20

// directMessage is one message of the conversation, as both APIs take it.
type directMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

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
	if session == "" || strings.ContainsAny(session, `/\`) || session == "." || session == ".." {
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
	var history []directMessage
	if t.Resume {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &history)
		}
	}
	history = append(history, directMessage{Role: "user", Content: t.Prompt})

	var req []byte
	var endpoint string
	if api == "anthropic" {
		endpoint = url + "/v1/messages"
		req, _ = json.Marshal(map[string]any{"model": t.Model, "max_tokens": 8192, "system": t.Instructions,
			"messages": history})
	} else {
		endpoint = url + "/v1/chat/completions"
		msgs := append([]directMessage{{Role: "system", Content: t.Instructions}}, history...)
		req, _ = json.Marshal(map[string]any{"model": t.Model, "messages": msgs})
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(req))
	if err != nil {
		return Outcome{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+token)
	if api == "anthropic" {
		hr.Header.Set("Anthropic-Version", "2023-06-01")
	}
	client := d.HTTP
	if client == nil {
		client = &http.Client{}
	}
	resp, err := client.Do(hr)
	if err != nil {
		return Outcome{}, fmt.Errorf("the model could not be reached: %w", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, directAnswerLargest))
	if err != nil {
		return Outcome{}, fmt.Errorf("the model's answer was cut off: %w", err)
	}
	text, model, why := readDirectAnswer(api, out)
	if resp.StatusCode != http.StatusOK {
		return Outcome{}, fmt.Errorf("the model refused the call (%d): %s", resp.StatusCode, firstNonEmpty(why, "no reason given"))
	}
	if text == "" {
		return Outcome{}, errors.New("the model gave no answer")
	}
	history = append(history, directMessage{Role: "assistant", Content: text})
	if b, err := json.Marshal(history); err == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			_ = os.WriteFile(path, b, 0o600)
		}
	}
	return Outcome{Text: strings.TrimSpace(text), Brain: agentmessage.Brain{
		Provider: directBrain, Model: firstNonEmpty(model, t.Model), Session: t.Session,
		RunHash: runHash(req, out),
	}}, nil
}

// readDirectAnswer is the words of a model's answer, the model it names, and
// the reason it gives for refusing, in Anthropic's shape or OpenAI's.
func readDirectAnswer(api string, out []byte) (text, model, why string) {
	var a struct {
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Choices []struct {
			Message directMessage `json:"message"`
		} `json:"choices"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(out, &a) != nil {
		return "", "", ""
	}
	if len(a.Error) > 0 {
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(a.Error, &e) == nil && e.Message != "" {
			why = e.Message
		} else {
			why = strings.Trim(string(a.Error), `"`)
		}
	}
	var b strings.Builder
	if api == "anthropic" {
		for _, c := range a.Content {
			if c.Type == "text" {
				b.WriteString(c.Text)
			}
		}
	} else if len(a.Choices) > 0 {
		b.WriteString(a.Choices[0].Message.Content)
	}
	return b.String(), a.Model, why
}

// envForDirect is the environment of a DirectModel: its body's model address,
// the run's token for it, and which API its provider speaks.
func (b *Borrowed) envForDirect() ([]string, error) {
	if !b.throughIdentityAgent {
		return nil, fmt.Errorf("an AI agent that only reads and answers needs an API key its Identity Agent uses "+
			"for it, not a %s for %s", b.Kind, b.Provider)
	}
	if b.modelURL == "" || b.modelToken == "" {
		return nil, errors.New("this machine gave the run no model address")
	}
	api := "openai"
	switch b.Provider {
	case brainsignin.Anthropic:
		api = "anthropic"
	case brainsignin.OpenAI, brainsignin.XAI, brainsignin.OpenRouter:
	default:
		return nil, fmt.Errorf("an AI agent that only reads and answers cannot call %s", b.Provider)
	}
	return []string{envDirectURL + "=" + b.modelURL, envDirectToken + "=" + b.modelToken, envDirectAPI + "=" + api}, nil
}
