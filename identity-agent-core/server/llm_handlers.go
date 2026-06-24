package server

import (
        "bytes"
        "crypto/sha256"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net/http"
        "strings"
        "time"

        "identity-agent-core/store"

        "github.com/go-chi/chi/v5"
)

// ── Chat completion types (OpenAI-compatible) ─────────────────────────────────

type chatCompletionRequest struct {
        Model    string        `json:"model"`
        Messages []chatMessage `json:"messages"`
        Stream   bool          `json:"stream"`
}

type chatMessage struct {
        Role    string `json:"role"`
        Content string `json:"content"`
}

// SSE chunk from a streaming chat completion response.
type chatCompletionChunk struct {
        ID      string `json:"id"`
        Choices []struct {
                Delta struct {
                        Role    string `json:"role,omitempty"`
                        Content string `json:"content,omitempty"`
                } `json:"delta"`
        } `json:"choices"`
}

// Non-streaming chat completion response.
type chatCompletionResponse struct {
        ID      string `json:"id"`
        Choices []struct {
                Message chatMessage `json:"message"`
        } `json:"choices"`
}

const openRouterBaseURL = "https://openrouter.ai/api/v1"

type llmModel struct {
        ID      string `json:"id"`
        Object  string `json:"object"`
        Created int64  `json:"created"`
        OwnedBy string `json:"owned_by"`
}

var llmModelCatalog = []llmModel{
        {ID: "openai/gpt-3.5-turbo", Object: "model", Created: 1677610602, OwnedBy: "openai"},
        {ID: "openai/gpt-4", Object: "model", Created: 1687882411, OwnedBy: "openai"},
        {ID: "openai/gpt-4o", Object: "model", Created: 1715367049, OwnedBy: "openai"},
        {ID: "openai/gpt-4o-mini", Object: "model", Created: 1721172717, OwnedBy: "openai"},
        {ID: "anthropic/claude-3-haiku", Object: "model", Created: 1709251200, OwnedBy: "anthropic"},
        {ID: "anthropic/claude-3.5-sonnet", Object: "model", Created: 1718841600, OwnedBy: "anthropic"},
        {ID: "google/gemini-flash-1.5", Object: "model", Created: 1718841600, OwnedBy: "google"},
        {ID: "meta-llama/llama-3.1-8b-instruct:free", Object: "model", Created: 1721347200, OwnedBy: "meta-llama"},
}

func (s *CoreServer) llmRoutes(r chi.Router) {
        r.Get("/api/settings/llm", s.handleGetLLMSettings)
        r.Post("/api/settings/llm", s.handleSaveLLMKey)
        r.Delete("/api/settings/llm/{service}", s.handleDeleteLLMKey)
        // /sandbox/llm/v1/* — container egress namespace: LLM proxy for sandboxed apps.
        // Containers call http://agent.internal:5050/sandbox/llm/v1 as their OpenAI-compatible base URL.
        r.HandleFunc("/sandbox/llm/v1", s.handleLLMProxy)
        r.HandleFunc("/sandbox/llm/v1/*", s.handleLLMProxy)
}

func (s *CoreServer) handleGetLLMSettings(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                writeJSON(w, map[string]interface{}{"services": []string{}, "available": false})
                return
        }
        services := s.SandboxManager.ListLLMServices()
        if services == nil {
                services = []string{}
        }
        serviceStatus := make(map[string]bool)
        for _, svc := range services {
                serviceStatus[svc] = s.SandboxManager.GetLLMAPIKey(svc) != ""
        }
        models := make([]string, len(llmModelCatalog))
        for i, m := range llmModelCatalog {
                models[i] = m.ID
        }
        writeJSON(w, map[string]interface{}{
                "services":       services,
                "service_status": serviceStatus,
                "available":      true,
                "models":         models,
        })
}

func (s *CoreServer) handleSaveLLMKey(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                writeError(w, http.StatusServiceUnavailable, "Sandbox not available", "")
                return
        }
        var req struct {
                Service string `json:"service"`
                APIKey  string `json:"api_key"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }
        if req.Service == "" || req.APIKey == "" {
                writeError(w, http.StatusBadRequest, "service and api_key are required", "")
                return
        }
        if err := s.SandboxManager.SetLLMAPIKey(req.Service, req.APIKey); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save key", err.Error())
                return
        }
        log.Printf("[llm] Stored API key for service: %s", req.Service)
        writeJSON(w, map[string]interface{}{"saved": true, "service": req.Service})
}

func (s *CoreServer) handleDeleteLLMKey(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                writeError(w, http.StatusServiceUnavailable, "Sandbox not available", "")
                return
        }
        service := chi.URLParam(r, "service")
        if err := s.SandboxManager.DeleteLLMAPIKey(service); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to delete key", err.Error())
                return
        }
        writeJSON(w, map[string]interface{}{"deleted": true, "service": service})
}

func llmCORSHeaders(w http.ResponseWriter) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
}

func (s *CoreServer) handleLLMProxy(w http.ResponseWriter, r *http.Request) {
        llmCORSHeaders(w)
        if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
        }

        subPath := strings.TrimPrefix(r.URL.Path, "/sandbox/llm/v1")
        if subPath == "" {
                subPath = "/"
        }

        // /models is always served from the static catalog — no key or sandbox needed.
        // Open WebUI calls this on startup to verify the connection and populate the dropdown.
        if r.Method == http.MethodGet && (subPath == "/models" || subPath == "/models/") {
                s.handleLLMModels(w, r)
                return
        }

        if s.SandboxManager == nil {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusServiceUnavailable)
                w.Write([]byte(`{"error":{"message":"Sandbox not initialized","code":"unavailable","type":"server_error"}}`))
                return
        }

        // Structurally deny third-party LLM egress until the governance gateway strip-gate exists.
        // Third-party inference (OpenRouter etc.) MUST pass credential/PII stripping + explicit consent gate.
        // Until the governance gateway strip-gate is implemented, all non-/models LLM proxy requests are rejected by design.
        // /models remains available for sandbox plugin discovery/UI population (no PII leaves).
        if !(r.Method == http.MethodGet && (subPath == "/models" || subPath == "/models/")) {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusServiceUnavailable)
                w.Write([]byte(`{"error":{"message":"Third-party LLM egress is deferred until the governance gateway strip-gate is implemented. Use local models or wait for the governed path.","code":"llm_egress_deferred","type":"server_error"}}`))
                return
        }

        apiKey := s.SandboxManager.GetLLMAPIKey("openrouter")
        if apiKey == "" {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusUnauthorized)
                w.Write([]byte(`{"error":{"message":"OpenRouter API key not configured. Open the Identity Agent, go to Settings, and enter your OpenRouter key under AI KEYS.","code":"missing_api_key","type":"authentication_error"}}`))
                return
        }

        upstreamURL := openRouterBaseURL + subPath
        if r.URL.RawQuery != "" {
                upstreamURL += "?" + r.URL.RawQuery
        }

        body, err := io.ReadAll(r.Body)
        if err != nil {
                http.Error(w, "Failed to read request body", http.StatusInternalServerError)
                return
        }

        // Parse the request for conversation capture (chat/completions only).
        isChatCompletion := subPath == "/chat/completions" || subPath == "/chat/completions/"
        var chatReq chatCompletionRequest
        if isChatCompletion {
                _ = json.Unmarshal(body, &chatReq) // best-effort; capture failures are non-fatal
        }

        upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
        if err != nil {
                http.Error(w, "Failed to build upstream request", http.StatusInternalServerError)
                return
        }

        for key, vals := range r.Header {
                lk := strings.ToLower(key)
                if lk == "host" || lk == "proxy-connection" || lk == "proxy-authorization" || lk == "authorization" {
                        continue
                }
                for _, val := range vals {
                        upReq.Header.Add(key, val)
                }
        }
        upReq.Header.Set("HTTP-Referer", "https://identity-agent.local")
        upReq.Header.Set("X-Title", "Identity Agent")

        log.Printf("[llm-proxy] %s %s -> %s", r.Method, r.URL.Path, upstreamURL)

        // MakeTrackedRequest injects the API key via the credential vault and records
        // the call in the proxy log and trace stream alongside container-originated traffic.
        // No client-level timeout — streaming LLM responses can take many minutes.
        resp, err := s.SandboxManager.MakeTrackedRequest(r.Context(), upReq)
        if err != nil {
                log.Printf("[llm-proxy] Upstream error: %v", err)
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusBadGateway)
                w.Write([]byte(`{"error":{"message":"Upstream request to OpenRouter failed","code":"upstream_error","type":"server_error"}}`))
                return
        }
        defer resp.Body.Close()

        for key, vals := range resp.Header {
                lk := strings.ToLower(key)
                if lk == "transfer-encoding" || lk == "content-length" {
                        continue
                }
                for _, val := range vals {
                        w.Header().Add(key, val)
                }
        }
        // Enforce SSE-friendly headers regardless of what OpenRouter sends.
        // Open WebUI's WebView needs these to keep the stream open.
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")
        w.Header().Set("X-Accel-Buffering", "no")
        w.WriteHeader(resp.StatusCode)

        // Stream the response to the client while capturing content for ai-memory.db.
        var captureBuffer bytes.Buffer
        flusher, canFlush := w.(http.Flusher)
        buf := make([]byte, 4096)
        for {
                n, readErr := resp.Body.Read(buf)
                if n > 0 {
                        w.Write(buf[:n])
                        if isChatCompletion && resp.StatusCode == http.StatusOK {
                                captureBuffer.Write(buf[:n])
                        }
                        if canFlush {
                                flusher.Flush()
                        }
                }
                if readErr == io.EOF {
                        break
                }
                if readErr != nil {
                        log.Printf("[llm-proxy] Stream read error: %v", readErr)
                        break
                }
        }

        // Capture the conversation asynchronously — never delay the client response.
        if isChatCompletion && resp.StatusCode == http.StatusOK && s.AIMemory != nil && len(chatReq.Messages) > 0 {
                captured := captureBuffer.Bytes()
                go s.captureConversation(chatReq, captured)
        }
}

func (s *CoreServer) handleLLMModels(w http.ResponseWriter, _ *http.Request) {
        type modelsResponse struct {
                Object string     `json:"object"`
                Data   []llmModel `json:"data"`
        }
        writeJSON(w, modelsResponse{
                Object: "list",
                Data:   llmModelCatalog,
        })
}

func writeJSON(w http.ResponseWriter, v interface{}) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(v)
}

// ── Conversation capture ──────────────────────────────────────────────────────

// captureConversation extracts the new user message and the assistant response
// from a chat completion exchange and saves them to ai-memory.db.
//
// This runs in a goroutine — errors are logged, never surfaced to the client.
func (s *CoreServer) captureConversation(req chatCompletionRequest, rawResponse []byte) {
        // 1. Derive a stable conversation ID from the first system + first user messages.
        convID := deriveConversationID(req.Messages)
        if convID == "" {
                return
        }

        // 2. Extract the assistant's response from the raw bytes.
        assistantContent := extractAssistantResponse(rawResponse)
        if assistantContent == "" {
                log.Printf("[llm-capture] No assistant content found in response for conv=%s", convID)
                return
        }

        // 3. The last user message in the request is the new prompt.
        var lastUserMsg string
        var lastUserIdx int
        for i := len(req.Messages) - 1; i >= 0; i-- {
                if req.Messages[i].Role == "user" {
                        lastUserMsg = req.Messages[i].Content
                        lastUserIdx = i
                        break
                }
        }
        if lastUserMsg == "" {
                return
        }

        now := time.Now().Unix()

        // 4. Upsert the conversation.
        title := truncateTitle(lastUserMsg, 80)
        conv := store.Conversation{
                ID:        convID,
                SourceApp: "llm-proxy",
                Title:     title,
                Model:     req.Model,
        }
        if err := s.AIMemory.SaveConversation(conv); err != nil {
                log.Printf("[llm-capture] Failed to save conversation %s: %v", convID, err)
                return
        }

        // 5. Save the new user message.
        userMsgID := hashMessageID(convID, "user", lastUserMsg, lastUserIdx)
        if err := s.AIMemory.SaveMessage(store.Message{
                ID:             userMsgID,
                ConversationID: convID,
                Role:           "user",
                Content:        lastUserMsg,
                Model:          req.Model,
                Timestamp:      now,
        }); err != nil {
                log.Printf("[llm-capture] Failed to save user message: %v", err)
        }

        // 6. Save the assistant response.
        assistantIdx := lastUserIdx + 1
        assistantMsgID := hashMessageID(convID, "assistant", assistantContent, assistantIdx)
        if err := s.AIMemory.SaveMessage(store.Message{
                ID:             assistantMsgID,
                ConversationID: convID,
                Role:           "assistant",
                Content:        assistantContent,
                Model:          req.Model,
                Timestamp:      now,
        }); err != nil {
                log.Printf("[llm-capture] Failed to save assistant message: %v", err)
        }

        log.Printf("[llm-capture] Saved conv=%s model=%s user_len=%d assistant_len=%d",
                convID, req.Model, len(lastUserMsg), len(assistantContent))
}

// deriveConversationID creates a stable conversation ID by hashing the first
// system message (if any) and the first user message. This stays constant
// across all turns of the same conversation because the OpenAI API sends the
// full message history with every request.
func deriveConversationID(messages []chatMessage) string {
        var systemContent, firstUserContent string
        for _, m := range messages {
                if m.Role == "system" && systemContent == "" {
                        systemContent = m.Content
                }
                if m.Role == "user" && firstUserContent == "" {
                        firstUserContent = m.Content
                        break
                }
        }
        if firstUserContent == "" {
                return ""
        }
        h := sha256.Sum256([]byte(systemContent + "|" + firstUserContent))
        return fmt.Sprintf("%x", h[:8]) // 16-char hex ID
}

// hashMessageID creates a deterministic message ID for deduplication.
func hashMessageID(convID, role, content string, index int) string {
        h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", convID, role, content, index)))
        return fmt.Sprintf("%x", h[:8])
}

// extractAssistantResponse handles both streaming (SSE) and non-streaming responses.
func extractAssistantResponse(raw []byte) string {
        rawStr := string(raw)

        // Streaming response: lines prefixed with "data: "
        if strings.Contains(rawStr, "data: ") {
                var contentParts []string
                for _, line := range strings.Split(rawStr, "\n") {
                        line = strings.TrimSpace(line)
                        if !strings.HasPrefix(line, "data: ") {
                                continue
                        }
                        data := strings.TrimPrefix(line, "data: ")
                        if data == "[DONE]" {
                                break
                        }
                        var chunk chatCompletionChunk
                        if err := json.Unmarshal([]byte(data), &chunk); err != nil {
                                continue
                        }
                        if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
                                contentParts = append(contentParts, chunk.Choices[0].Delta.Content)
                        }
                }
                return strings.Join(contentParts, "")
        }

        // Non-streaming response: single JSON object
        var resp chatCompletionResponse
        if err := json.Unmarshal(raw, &resp); err != nil {
                return ""
        }
        if len(resp.Choices) > 0 {
                return resp.Choices[0].Message.Content
        }
        return ""
}

// truncateTitle shortens a string to maxLen characters for use as a conversation title.
func truncateTitle(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen-3] + "..."
}
