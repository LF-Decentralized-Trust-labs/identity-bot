package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

func (s *CoreServer) traceRoutes(r chi.Router) {
	r.Get("/dev/trace", s.handleTraceViewer)
	r.Route("/api/trace", func(r chi.Router) {
		r.Get("/", s.handleTraceList)
		r.Post("/enable", s.handleTraceEnable)
		r.Post("/disable", s.handleTraceDisable)
		r.Get("/status", s.handleTraceStatus)
		r.Post("/clear", s.handleTraceClear)
		r.Get("/entries", s.handleTraceEntries)
		r.Post("/session", s.handleTraceStartSession)
		r.Get("/session/{traceId}", s.handleTraceGetSession)
		r.Post("/session/{traceId}/end", s.handleTraceEndSession)
		r.Post("/session/{traceId}/continue", s.handleTraceStepContinue)
		r.Post("/step-mode", s.handleTraceSetStepMode)
	})
	r.Get("/ws/trace", s.handleTraceWebSocket)
}

func (s *CoreServer) getTracer() *sandbox.Tracer {
	if s.SandboxManager == nil {
		return nil
	}
	return s.SandboxManager.Tracer()
}

func (s *CoreServer) handleTraceViewer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(200)
	fmt.Fprint(w, traceViewerHTML)
}

func (s *CoreServer) handleTraceList(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries := tracer.GetRecentEntries(limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
		"enabled": tracer.IsEnabled(),
	})
}

func (s *CoreServer) handleTraceEnable(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	tracer.SetEnabled(true)
	log.Printf("[trace] Trace debugger enabled")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true})
}

func (s *CoreServer) handleTraceDisable(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	tracer.SetEnabled(false)
	log.Printf("[trace] Trace debugger disabled")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false})
}

func (s *CoreServer) handleTraceStatus(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	sessions := tracer.ListSessions()
	activeSessions := 0
	for _, s := range sessions {
		if s.Status == "active" {
			activeSessions++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":         tracer.IsEnabled(),
		"step_mode":       tracer.IsStepMode(),
		"total_sessions":  len(sessions),
		"active_sessions": activeSessions,
		"ring_buffer":     tracer.BufferLen(),
	})
}

func (s *CoreServer) handleTraceClear(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	tracer.ClearAll()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"cleared": true})
}

func (s *CoreServer) handleTraceEntries(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	appID := r.URL.Query().Get("app_id")
	var entries []sandbox.TraceEntry
	if appID != "" {
		entries = tracer.GetEntriesByApp(appID, limit)
	} else {
		entries = tracer.GetRecentEntries(limit)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func (s *CoreServer) handleTraceStartSession(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		AppID       string `json:"app_id"`
		InstanceID  string `json:"instance_id"`
		StepThrough bool   `json:"step_through"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	traceID := tracer.StartSession(req.AppID, req.InstanceID, req.StepThrough)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"trace_id":     traceID,
		"step_through": req.StepThrough,
	})
}

func (s *CoreServer) handleTraceGetSession(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	traceID := chi.URLParam(r, "traceId")
	session := tracer.GetSession(traceID)
	if session == nil {
		jsonError(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (s *CoreServer) handleTraceEndSession(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	traceID := chi.URLParam(r, "traceId")
	tracer.EndSession(traceID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ended": true, "trace_id": traceID})
}

func (s *CoreServer) handleTraceStepContinue(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	traceID := chi.URLParam(r, "traceId")
	tracer.StepContinue(traceID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"continued": true, "trace_id": traceID})
}

func (s *CoreServer) handleTraceSetStepMode(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		jsonError(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tracer.SetStepMode(req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"step_mode": req.Enabled})
}

func (s *CoreServer) handleTraceWebSocket(w http.ResponseWriter, r *http.Request) {
	tracer := s.getTracer()
	if tracer == nil {
		http.Error(w, "Tracer not available", http.StatusServiceUnavailable)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[trace-ws] Upgrade error: %v", err)
		return
	}

	subID := fmt.Sprintf("trace-ws-%d", time.Now().UnixNano())
	ch := tracer.Subscribe(subID)
	done := make(chan struct{})

	defer func() {
		tracer.Unsubscribe(subID)
		conn.Close()
	}()

	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}
