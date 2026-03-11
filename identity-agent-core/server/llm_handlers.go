package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

const openRouterBaseURL = "https://openrouter.ai/api/v1"

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
	writeJSON(w, map[string]interface{}{
		"services":       services,
		"service_status": serviceStatus,
		"available":      true,
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

func (s *CoreServer) handleLLMProxy(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		http.Error(w, `{"error":{"message":"Sandbox not initialized","code":"unavailable"}}`, http.StatusServiceUnavailable)
		return
	}

	apiKey := s.SandboxManager.GetLLMAPIKey("openrouter")
	if apiKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"OpenRouter API key not configured. Go to Identity Agent Settings and enter your OpenRouter key.","code":"missing_api_key","type":"authentication_error"}}`))
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/llm/v1")
	if path == "" {
		path = "/"
	}
	upstreamURL := openRouterBaseURL + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to build upstream request", http.StatusInternalServerError)
		return
	}

	for key, vals := range r.Header {
		lk := strings.ToLower(key)
		if lk == "host" || lk == "proxy-connection" || lk == "proxy-authorization" {
			continue
		}
		for _, val := range vals {
			upReq.Header.Add(key, val)
		}
	}
	upReq.Header.Set("Authorization", "Bearer "+apiKey)
	upReq.Header.Set("HTTP-Referer", "https://identity-agent.local")
	upReq.Header.Set("X-Title", "Identity Agent")

	client := &http.Client{}
	resp, err := client.Do(upReq)
	if err != nil {
		log.Printf("[llm-proxy] Upstream error for %s %s: %v", r.Method, upstreamURL, err)
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
