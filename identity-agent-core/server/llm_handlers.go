package server

import (
        "bytes"
        "encoding/json"
        "io"
        "log"
        "net/http"
        "strings"

        "github.com/go-chi/chi/v5"
)

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
        r.HandleFunc("/llm/v1", s.handleLLMProxy)
        r.HandleFunc("/llm/v1/*", s.handleLLMProxy)
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

        subPath := strings.TrimPrefix(r.URL.Path, "/llm/v1")
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
        upReq.Header.Set("Authorization", "Bearer "+apiKey)
        upReq.Header.Set("HTTP-Referer", "https://identity-agent.local")
        upReq.Header.Set("X-Title", "Identity Agent")

        log.Printf("[llm-proxy] %s %s -> %s", r.Method, r.URL.Path, upstreamURL)

        // No client-level timeout — streaming LLM responses can take many minutes.
        // The request context (tied to the client connection) handles cancellation if
        // the browser disconnects.
        client := &http.Client{}
        resp, err := client.Do(upReq)
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

        flusher, canFlush := w.(http.Flusher)
        buf := make([]byte, 4096)
        for {
                n, readErr := resp.Body.Read(buf)
                if n > 0 {
                        w.Write(buf[:n])
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
