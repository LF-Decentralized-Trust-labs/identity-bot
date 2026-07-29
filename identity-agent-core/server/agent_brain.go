package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/asset"
)

// The agent brain — how a provisioned AI agent actually answers. This is the "use"
// half of the agent: given a question, reach the agent's configured LLM (one of the
// three connect mechanisms) and return the answer.
//
// Egress note: this is the AGENT'S OWN owner-configured brain, an intentional egress
// the owner set up at creation — distinct from the sandboxed-app third-party egress the
// governance strip-gate defers. A local brain has no third-party egress at all.

func (s *CoreServer) agentConfigByAID(aid string) *asset.AgentConfig {
	if s.assetHandler == nil {
		return nil
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.AssetType == "ai_agent" && a.PairwiseAID == aid {
			return a.AgentConfig
		}
	}
	return nil
}

// runAgentBrain answers question as the agent identified by aid, using its configured
// brain (cli | remote | local). Returns the answer text and the model used.
func (s *CoreServer) runAgentBrain(aid, question string) (answer, model string, err error) {
	system := "You are an AI agent acting for this organization. Answer the question " +
		"you are asked concisely and directly."
	var brain asset.BrainConfig
	if cfg := s.agentConfigByAID(aid); cfg != nil {
		brain = cfg.Brain
		if strings.TrimSpace(cfg.SystemPrompt) != "" {
			system = cfg.SystemPrompt
		}
	}

	switch brain.Kind {
	case "local":
		base := strings.TrimRight(brain.Endpoint, "/")
		if base == "" {
			return "", "", fmt.Errorf("local brain has no endpoint configured")
		}
		m := orDefault(brain.Model, "local-model")
		a, e := s.chatOpenAICompatible(base, m, brain.CredentialRef, system, question)
		return a, m, e

	case "cli":
		// A subscription CLI (Claude Code / Codex / Grok CLI) is a session-based tool,
		// not a single-shot API — wiring it for one-shot Q&A is a separate integration.
		return "", brain.Provider, fmt.Errorf("cli brains (%s) are not wired for one-shot Q&A in v0", orDefault(brain.Provider, "cli"))

	default: // "remote" or unset → a hosted provider
		provider := strings.ToLower(orDefault(brain.Provider, "openrouter"))
		key := brain.CredentialRef
		switch provider {
		case "anthropic":
			if key == "" {
				key = s.SandboxManager.GetLLMAPIKey("anthropic")
			}
			m := orDefault(brain.Model, "claude-3-5-haiku-latest")
			a, e := s.chatAnthropic(m, key, system, question)
			return a, m, e
		case "xai":
			if key == "" {
				key = s.SandboxManager.GetLLMAPIKey("xai")
			}
			m := orDefault(brain.Model, "grok-2-latest")
			a, e := s.chatOpenAICompatible("https://api.x.ai/v1", m, key, system, question)
			return a, m, e
		default: // openrouter
			if key == "" {
				key = s.SandboxManager.GetLLMAPIKey("openrouter")
			}
			if key == "" {
				return "", "", fmt.Errorf("no API key for %s (configure the agent's brain or the org's key)", provider)
			}
			m := orDefault(brain.Model, "openai/gpt-4o-mini")
			a, e := s.chatOpenAICompatible("https://openrouter.ai/api/v1", m, key, system, question)
			return a, m, e
		}
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// chatOpenAICompatible calls any OpenAI-compatible /chat/completions endpoint
// (OpenRouter, xAI, a local model server).
func (s *CoreServer) chatOpenAICompatible(base, model, key, system, question string) (string, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": question},
		},
		"max_tokens": 512,
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("HTTP-Referer", "https://identity-agent.local")
	req.Header.Set("X-Title", "Identity Agent")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("brain HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("unexpected brain response: %s", truncate(string(body), 200))
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

// chatAnthropic calls the Anthropic Messages API.
func (s *CoreServer) chatAnthropic(model, key, system, question string) (string, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 512,
		"system":     system,
		"messages":   []map[string]string{{"role": "user", "content": question}},
	})
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("brain HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Content) == 0 {
		return "", fmt.Errorf("unexpected anthropic response: %s", truncate(string(body), 200))
	}
	return strings.TrimSpace(out.Content[0].Text), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
