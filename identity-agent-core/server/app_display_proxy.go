package server

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// handleAppDisplayProxy reverse-proxies browser requests to the container's
// display port, but intercepts specific API paths and serves from the Identity
// Agent's data stores instead.
//
// Route: /apps/{app_id}/*
//
// This ensures the container never stores conversation data — the Identity
// Agent owns all data and the container is fully ephemeral. Any chat app
// (Open WebUI, LibreChat, etc.) gets its inbox populated from ai-memory.db
// without any app-specific integration beyond the API schema document.
func (s *CoreServer) handleAppDisplayProxy(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	if appID == "" {
		http.Error(w, "Missing app_id", http.StatusBadRequest)
		return
	}

	if s.SandboxManager == nil {
		http.Error(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	// Strip the /apps/{app_id} prefix to get the path the container expects.
	prefix := fmt.Sprintf("/apps/%s", appID)
	containerPath := strings.TrimPrefix(r.URL.Path, prefix)
	if containerPath == "" {
		containerPath = "/"
	}

	// ── Intercept: Open WebUI chat data API ──────────────────────────────
	// These paths are normally served by Open WebUI's internal database.
	// We intercept them and serve from ai-memory.db instead.

	if r.Method == http.MethodGet && (containerPath == "/api/v1/chats" || containerPath == "/api/v1/chats/") {
		s.serveConversationList(w, r)
		return
	}

	// GET /api/v1/chats/{chat_id} — single conversation with messages
	if r.Method == http.MethodGet && strings.HasPrefix(containerPath, "/api/v1/chats/") {
		chatID := strings.TrimPrefix(containerPath, "/api/v1/chats/")
		chatID = strings.TrimSuffix(chatID, "/")
		if chatID != "" && !strings.Contains(chatID, "/") {
			s.serveConversationDetail(w, r, chatID)
			return
		}
	}

	// ── Forward everything else to the container ─────────────────────────
	displayURL, err := s.SandboxManager.GetDisplayURL(appID)
	if err != nil {
		http.Error(w, fmt.Sprintf("App not running: %s", err), http.StatusNotFound)
		return
	}

	target, err := url.Parse(displayURL)
	if err != nil {
		http.Error(w, "Invalid display URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[display-proxy] Error proxying to %s: %v", displayURL, err)
		http.Error(w, "Container unreachable", http.StatusBadGateway)
	}

	// Rewrite the request URL to the container's expected path.
	r.URL.Path = containerPath
	r.URL.Host = target.Host
	r.Host = target.Host

	proxy.ServeHTTP(w, r)
}

// ── Open WebUI API format translators ─────────────────────────────────────────
//
// Open WebUI's frontend expects specific JSON shapes. We translate from
// ai-memory.db's canonical format to what the frontend needs.

// serveConversationList responds to GET /api/v1/chats with the conversation
// list in Open WebUI's expected format.
func (s *CoreServer) serveConversationList(w http.ResponseWriter, _ *http.Request) {
	convs, err := s.AIMemory.GetConversations(false)
	if err != nil {
		log.Printf("[display-proxy] Failed to list conversations: %v", err)
		http.Error(w, "Failed to list conversations", http.StatusInternalServerError)
		return
	}

	// Open WebUI expects an array of chat objects.
	type owuiChat struct {
		ID        string      `json:"id"`
		Title     string      `json:"title"`
		CreatedAt float64     `json:"created_at"`
		UpdatedAt float64     `json:"updated_at"`
		Chat      interface{} `json:"chat"`
	}

	result := make([]owuiChat, 0, len(convs))
	for _, c := range convs {
		result = append(result, owuiChat{
			ID:        c.ID,
			Title:     c.Title,
			CreatedAt: float64(c.CreatedAt),
			UpdatedAt: float64(c.UpdatedAt),
			Chat:      map[string]interface{}{},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// serveConversationDetail responds to GET /api/v1/chats/{id} with the full
// conversation (including messages) in Open WebUI's expected format.
func (s *CoreServer) serveConversationDetail(w http.ResponseWriter, _ *http.Request, chatID string) {
	conv, err := s.AIMemory.GetConversation(chatID)
	if err != nil || conv == nil {
		http.Error(w, "Conversation not found", http.StatusNotFound)
		return
	}

	messages, err := s.AIMemory.GetMessages(chatID)
	if err != nil {
		log.Printf("[display-proxy] Failed to get messages for %s: %v", chatID, err)
		http.Error(w, "Failed to get messages", http.StatusInternalServerError)
		return
	}

	// Open WebUI stores messages in a nested chat.messages array.
	// Each message has: id, role, content, timestamp, model, done.
	type owuiMessage struct {
		ID        string  `json:"id"`
		Role      string  `json:"role"`
		Content   string  `json:"content"`
		Timestamp float64 `json:"timestamp"`
		Model     string  `json:"model,omitempty"`
		Done      bool    `json:"done"`
	}

	owuiMessages := make([]owuiMessage, 0, len(messages))
	for _, m := range messages {
		owuiMessages = append(owuiMessages, owuiMessage{
			ID:        m.ID,
			Role:      m.Role,
			Content:   m.Content,
			Timestamp: float64(m.Timestamp),
			Model:     m.Model,
			Done:      true,
		})
	}

	// Open WebUI expects: { id, title, chat: { messages: [...] }, created_at, updated_at }
	result := map[string]interface{}{
		"id":    conv.ID,
		"title": conv.Title,
		"chat": map[string]interface{}{
			"messages": owuiMessages,
		},
		"created_at": float64(conv.CreatedAt),
		"updated_at": float64(conv.UpdatedAt),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// appDisplayProxyURL returns the Identity Agent's reverse proxy URL for a given app.
func (s *CoreServer) appDisplayProxyURL(appID string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/apps/%s/", s.Port, appID)
}
