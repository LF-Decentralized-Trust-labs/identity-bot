package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/appcall"
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
	// Cleaned once, here, so the intercepts below, the capability check and
	// the path forwarded all read the same path.
	containerPath := cleanedKeepingTheSlash(strings.TrimPrefix(r.URL.Path, prefix))

	// ── Intercept: Open WebUI chat data API ──────────────────────────────
	// These paths are normally served by Open WebUI's internal database.
	// We intercept them and serve from ai-memory.db instead.
	//
	// They are the owner's conversations, read under the same rule as
	// /api/ai/conversations: the owner, or a machine acting for them. This
	// route admits any caller holding any scope, so the rule is applied here —
	// an AI agent granted one capability must not read every conversation.
	if s.isAConversationRead(r.Method, containerPath) && !s.mayReadTheOwnersConversations(r) {
		http.Error(w, "only the owner, or a machine acting for them, reads these conversations", http.StatusForbidden)
		return
	}

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

	// ── Never a capability call ──────────────────────────────────────────
	// The display port is the same port capability calls are posted to, and
	// this route admits any caller holding any scope. Forwarded, a call here
	// would reach a capability with no scope check and no audit record — an
	// AI agent granted one capability could call every other one the app
	// provides. Capability calls go through /api/capabilities/{id}/invoke,
	// which governs them.
	if isACapabilityCall(containerPath) {
		http.Error(w, "capability calls go through /api/capabilities/{id}/invoke", http.StatusForbidden)
		return
	}
	s.stripWhatOnlyTheIdentityAgentReads(r)

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

	// Rewrite the request URL to the container's expected path — the cleaned,
	// decoded path that was checked above, re-encoded, and never the raw form,
	// so the app cannot be sent a spelling of a path that was never checked.
	r.URL.Path = containerPath
	r.URL.RawPath = ""
	r.URL.Host = target.Host
	r.Host = target.Host

	proxy.ServeHTTP(w, r)
}

// isAConversationRead reports whether method and path are one of the
// intercepted reads of ai-memory conversations.
func (s *CoreServer) isAConversationRead(method, p string) bool {
	if method != http.MethodGet {
		return false
	}
	return p == "/api/v1/chats" || p == "/api/v1/chats/" || strings.HasPrefix(p, "/api/v1/chats/")
}

// mayReadTheOwnersConversations is the conversation read rule for this route:
// the gate admitted the request as the owner's, or as a controller's acting
// for them. A caller admitted only for holding a scope is neither.
func (s *CoreServer) mayReadTheOwnersConversations(r *http.Request) bool {
	return s.isOwnerOrItsController(r)
}

// isACapabilityCall reports whether path, as an app's server would read it,
// reaches its capability API. Cleaned and compared without case, so neither
// doubled slashes, dot segments nor capitals spell a way past it.
func isACapabilityCall(p string) bool {
	c := strings.ToLower(path.Clean("/" + p))
	return c == "/v1/capability" || strings.HasPrefix(c, "/v1/capability/")
}

// cleanedKeepingTheSlash is path.Clean, keeping a trailing slash, which a web
// app may route on.
func cleanedKeepingTheSlash(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// stripWhatOnlyTheIdentityAgentReads removes from a request bound for an app
// everything that proves who the caller is to the Identity Agent, and every
// header that would tell the app who called.
//
// The first is the caller's own credential: an Identity Agent token, a browser
// session, a signature, the local owner's secret. Forwarded, the app would hold
// it and could replay it to the Identity Agent as the caller. The second is a
// forged caller: only a call the Identity Agent stamped itself may say who
// called (package appcall), and this route stamps nothing.
//
// An Authorization header that is not an Identity Agent credential is the
// app's own login and is left alone.
func (s *CoreServer) stripWhatOnlyTheIdentityAgentReads(r *http.Request) {
	// Compared with underscores read as hyphens: some servers an app runs
	// behind treat X_IA_Call_Kind and X-IA-Call-Kind as one header.
	secret := http.CanonicalHeaderKey(LocalOwnerSecretHeader)
	for name := range r.Header {
		n := http.CanonicalHeaderKey(strings.ReplaceAll(name, "_", "-"))
		if strings.HasPrefix(n, "X-Ia-") || appcall.IsCallHeader(n) || n == secret {
			delete(r.Header, name)
		}
	}
	// Both readings the Identity Agent itself uses: a token, and a browser
	// session, whose prefix is matched without case.
	for _, tok := range []string{bearerFrom(r), bearerToken(r)} {
		if tok != "" && s.isAnIdentityAgentCredential(strings.TrimSpace(tok)) {
			r.Header.Del("Authorization")
			break
		}
	}
}

// isAnIdentityAgentCredential reports whether tok is a token this Identity
// Agent issued, or a live browser session.
func (s *CoreServer) isAnIdentityAgentCredential(tok string) bool {
	if s.BrowserSessions != nil && s.BrowserSessions.valid(tok) {
		return true
	}
	presented := hashMCPToken(tok)
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
	mcpTokensMu.Unlock()
	for _, entry := range toks {
		if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(presented)) == 1 {
			return true
		}
	}
	return false
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
