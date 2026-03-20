package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// aiMemoryRoutes registers the AI Memory domain endpoints under /api/ai/.
// These routes expose the ai-memory.db domain to the Identity Agent and future Data Manager.
func (s *CoreServer) aiMemoryRoutes(r chi.Router) {
	r.Route("/ai", func(r chi.Router) {
		// Conversations
		r.Get("/conversations", s.handleListConversations)
		r.Post("/conversations", s.handleCreateConversation)
		r.Get("/conversations/{id}", s.handleGetConversation)
		r.Put("/conversations/{id}", s.handleUpdateConversation)
		r.Delete("/conversations/{id}", s.handleDeleteConversation)
		r.Post("/conversations/{id}/archive", s.handleArchiveConversation)

		// Messages within a conversation
		r.Get("/conversations/{id}/messages", s.handleGetMessages)
		r.Post("/conversations/{id}/messages", s.handleAddMessage)

		// Full-text search across all messages
		r.Get("/search", s.handleSearchMessages)

		// Per-app AI settings
		r.Get("/settings/{app_id}", s.handleGetAISettings)
		r.Put("/settings/{app_id}/{key}", s.handleSetAISetting)

	})
}

// ── Conversations ─────────────────────────────────────────────────────────────

func (s *CoreServer) handleListConversations(w http.ResponseWriter, r *http.Request) {
	includeArchived := r.URL.Query().Get("archived") == "true"
	convs, err := s.AIMemory.GetConversations(includeArchived)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list conversations", err.Error())
		return
	}
	writeJSON(w, convs)
}

func (s *CoreServer) handleCreateConversation(w http.ResponseWriter, r *http.Request) {
	var conv store.Conversation
	if err := json.NewDecoder(r.Body).Decode(&conv); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if conv.ID == "" {
		writeError(w, http.StatusBadRequest, "Conversation ID is required", "")
		return
	}
	if err := s.AIMemory.SaveConversation(conv); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save conversation", err.Error())
		return
	}

	// Return the saved record
	saved, err := s.AIMemory.GetConversation(conv.ID)
	if err != nil || saved == nil {
		writeJSON(w, conv)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, saved)
}

func (s *CoreServer) handleGetConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	conv, err := s.AIMemory.GetConversation(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get conversation", err.Error())
		return
	}
	if conv == nil {
		writeError(w, http.StatusNotFound, "Conversation not found", id)
		return
	}
	writeJSON(w, conv)
}

func (s *CoreServer) handleUpdateConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var conv store.Conversation
	if err := json.NewDecoder(r.Body).Decode(&conv); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	conv.ID = id
	if err := s.AIMemory.SaveConversation(conv); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update conversation", err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *CoreServer) handleDeleteConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.AIMemory.DeleteConversation(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete conversation", err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "deleted"})
}

func (s *CoreServer) handleArchiveConversation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Archived bool `json:"archived"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if err := s.AIMemory.ArchiveConversation(id, req.Archived); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to archive conversation", err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// ── Messages ──────────────────────────────────────────────────────────────────

func (s *CoreServer) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	convID := chi.URLParam(r, "id")
	messages, err := s.AIMemory.GetMessages(convID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get messages", err.Error())
		return
	}
	writeJSON(w, messages)
}

func (s *CoreServer) handleAddMessage(w http.ResponseWriter, r *http.Request) {
	convID := chi.URLParam(r, "id")
	var msg store.Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if msg.ID == "" {
		writeError(w, http.StatusBadRequest, "Message ID is required", "")
		return
	}
	msg.ConversationID = convID
	if err := s.AIMemory.SaveMessage(msg); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save message", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, msg)
}

// ── Search ────────────────────────────────────────────────────────────────────

func (s *CoreServer) handleSearchMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeError(w, http.StatusBadRequest, "Query parameter 'q' is required", "")
		return
	}
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	messages, err := s.AIMemory.SearchMessages(q, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Search failed", err.Error())
		return
	}
	writeJSON(w, messages)
}

// ── AI Settings ───────────────────────────────────────────────────────────────

func (s *CoreServer) handleGetAISettings(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	settings, err := s.AIMemory.GetAISettings(appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get AI settings", err.Error())
		return
	}
	writeJSON(w, settings)
}

func (s *CoreServer) handleSetAISetting(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "app_id")
	key := chi.URLParam(r, "key")
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if err := s.AIMemory.SetAISetting(appID, key, req.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to set AI setting", err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

