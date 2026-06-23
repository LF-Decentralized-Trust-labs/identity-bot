package server

import (
        "context"
        "encoding/json"
        "fmt"
        "log"
        "net"
        "net/http"
        "strconv"
        "time"

        "identity-agent-core/sandbox"

        "github.com/go-chi/chi/v5"
        "github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
}

func (s *CoreServer) sandboxRoutes(r chi.Router) {
        r.Get("/apps", s.handleListApps)
        r.Get("/apps/{id}", s.handleGetApp)
        r.Post("/apps/{id}/install", s.handleInstallApp)
        r.Delete("/apps/{id}", s.handleUninstallApp)
        r.Post("/apps/{id}/launch", s.handleLaunchApp)
        r.Post("/apps/{id}/stop", s.handleStopApp)
        r.Get("/apps/{id}/status", s.handleAppStatus)
        r.Get("/apps/{id}/logs", s.handleAppLogs)
        r.Get("/apps/{id}/logs/held", s.handleHeldLogs)
        r.Post("/apps/{id}/logs/{logId}/approve", s.handleApproveLog)
        r.Post("/apps/{id}/logs/{logId}/block", s.handleBlockLog)
        r.Get("/apps/{id}/resources", s.handlePendingResources)
        r.Post("/apps/{id}/resources/{reqId}/approve", s.handleApproveResource)
        r.Post("/apps/{id}/resources/{reqId}/deny", s.handleDenyResource)
        r.Post("/apps/{id}/resources/batch", s.handleBatchResources)
        r.Put("/apps/{id}/settings", s.handleUpdateAppSettings)
        r.Get("/apps/{id}/install-progress", s.handleInstallProgress)
        r.Get("/apps/{id}/display", s.handleAppDisplay)
        r.Get("/capabilities", s.handleListCapabilities)
        r.Get("/sandbox/health", s.handleSandboxHealth)
        r.Post("/sandbox/podman/setup", s.handlePodmanSetup)
        r.Get("/sandbox/podman/setup-status", s.handlePodmanSetupStatus)
        r.Get("/ws/sandbox", s.handleSandboxWebSocket)
        r.Get("/ws/terminal/{instanceId}", s.handleTerminalWebSocket)
}

// handleListCapabilities returns the functional capabilities offered by installed
// plug-ins (aggregated from manifests' provides[]). Discovery surface for the agent's
// governed capability endpoint; invoking a capability is governed separately.
func (s *CoreServer) handleListCapabilities(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }
        jsonResponse(w, s.SandboxManager.ProvidedCapabilities())
}

func (s *CoreServer) handleListApps(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        apps, err := s.SandboxManager.ListApps()
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, apps)
}

func (s *CoreServer) handleGetApp(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        app, err := s.SandboxManager.GetApp(id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }
        if app == nil {
                jsonError(w, "App not found", http.StatusNotFound)
                return
        }

        jsonResponse(w, app)
}

func (s *CoreServer) handleInstallApp(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")

        go func() {
                ctx := context.Background()
                err := s.SandboxManager.InstallApp(ctx, id, func(progress sandbox.PullProgress) {
                        log.Printf("[sandbox-api] Pull progress for %s: %s %.1f%%", id, progress.Status, progress.Progress)
                })
                if err != nil {
                        log.Printf("[sandbox-api] Install failed for %s: %v", id, err)
                }
        }()

        jsonResponse(w, map[string]string{
                "status":  "installing",
                "message": fmt.Sprintf("Installation of %s started", id),
        })
}

func (s *CoreServer) handleInstallProgress(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        info := s.SandboxManager.GetInstallProgress(id)
        if info == nil {
                app, _ := s.SandboxManager.GetApp(id)
                if app != nil && app.InstallStatus == "installed" {
                        jsonResponse(w, map[string]interface{}{
                                "app_id":   id,
                                "status":   "complete",
                                "progress": 100.0,
                                "done":     true,
                        })
                } else {
                        jsonResponse(w, map[string]interface{}{
                                "app_id":   id,
                                "status":   "idle",
                                "progress": 0.0,
                                "done":     false,
                        })
                }
                return
        }
        jsonResponse(w, info)
}

func (s *CoreServer) handleUninstallApp(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        if err := s.SandboxManager.UninstallApp(id); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "uninstalled"})
}

func (s *CoreServer) handleLaunchApp(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        instance, err := s.SandboxManager.LaunchApp(r.Context(), id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, instance)
}

func (s *CoreServer) handleStopApp(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        if err := s.SandboxManager.StopApp(r.Context(), id); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "stopped"})
}

func (s *CoreServer) handleAppStatus(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")

        status, err := s.SandboxManager.GetAppStatus(id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        stats, _ := s.SandboxManager.GetAppStats(id)

        result := map[string]interface{}{
                "status": status,
                "stats":  stats,
        }

        instance, _ := s.SandboxManager.GetRunningInstance(id)
        if instance != nil {
                result["instance"] = instance
        }

        jsonResponse(w, result)
}

func (s *CoreServer) handleAppLogs(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")

        filter := sandbox.ProxyLogFilter{}
        if d := r.URL.Query().Get("domain"); d != "" {
                filter.Domain = d
        }
        if d := r.URL.Query().Get("direction"); d != "" {
                filter.Direction = d
        }
        if a := r.URL.Query().Get("action"); a != "" {
                filter.PolicyAction = a
        }
        if l := r.URL.Query().Get("limit"); l != "" {
                if n, err := strconv.Atoi(l); err == nil {
                        filter.Limit = n
                }
        }
        if s := r.URL.Query().Get("since"); s != "" {
                if t, err := time.Parse(time.RFC3339, s); err == nil {
                        filter.Since = &t
                }
        }

        logs, err := s.SandboxManager.GetProxyLogs(id, filter)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, logs)
}

func (s *CoreServer) handleHeldLogs(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        held, err := s.SandboxManager.GetHeldRequests(id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, held)
}

func (s *CoreServer) handleApproveLog(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        logIDStr := chi.URLParam(r, "logId")
        logID, err := strconv.ParseInt(logIDStr, 10, 64)
        if err != nil {
                jsonError(w, "Invalid log ID", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.ApproveHeldRequest(logID, id); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "approved"})
}

func (s *CoreServer) handleBlockLog(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        logIDStr := chi.URLParam(r, "logId")
        logID, err := strconv.ParseInt(logIDStr, 10, 64)
        if err != nil {
                jsonError(w, "Invalid log ID", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.BlockHeldRequest(logID, id); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "blocked"})
}

func (s *CoreServer) handlePendingResources(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        reqs, err := s.SandboxManager.GetPendingResourceRequests(id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, reqs)
}

func (s *CoreServer) handleApproveResource(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        reqIDStr := chi.URLParam(r, "reqId")
        reqID, err := strconv.ParseInt(reqIDStr, 10, 64)
        if err != nil {
                jsonError(w, "Invalid request ID", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.ApproveResourceRequest(reqID); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "approved"})
}

func (s *CoreServer) handleDenyResource(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        reqIDStr := chi.URLParam(r, "reqId")
        reqID, err := strconv.ParseInt(reqIDStr, 10, 64)
        if err != nil {
                jsonError(w, "Invalid request ID", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.DenyResourceRequest(reqID); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "denied"})
}

func (s *CoreServer) handleBatchResources(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        var body struct {
                Approve []int64 `json:"approve"`
                Deny    []int64 `json:"deny"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                jsonError(w, "Invalid request body", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.BatchResolveResourceRequests(body.Approve, body.Deny); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "processed"})
}

func (s *CoreServer) handleUpdateAppSettings(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")

        var settings map[string]interface{}
        if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
                jsonError(w, "Invalid request body", http.StatusBadRequest)
                return
        }

        if err := s.SandboxManager.UpdateAppSettings(id, settings); err != nil {
                jsonError(w, err.Error(), http.StatusInternalServerError)
                return
        }

        jsonResponse(w, map[string]string{"status": "updated"})
}

func (s *CoreServer) handleAppDisplay(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        id := chi.URLParam(r, "id")
        // Verify the app is actually running before returning a proxy URL.
        _, err := s.SandboxManager.GetDisplayURL(id)
        if err != nil {
                jsonError(w, err.Error(), http.StatusNotFound)
                return
        }

        // Return the Identity Agent's reverse proxy URL instead of the container's
        // direct port. This allows the Identity Agent to intercept specific API
        // paths (e.g., chat data) and serve from its own data stores while
        // forwarding everything else to the container.
        proxyURL := s.appDisplayProxyURL(id)
        jsonResponse(w, map[string]string{"display_url": proxyURL})
}

func (s *CoreServer) handleSandboxHealth(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonResponse(w, map[string]interface{}{
                        "sandbox_initialized": false,
                        "container_engine":    sandbox.CheckContainerEngine(),
                })
                return
        }

        jsonResponse(w, s.SandboxManager.HealthCheck())
}

func (s *CoreServer) handleSandboxWebSocket(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        conn, err := wsUpgrader.Upgrade(w, r, nil)
        if err != nil {
                log.Printf("[sandbox-ws] Upgrade failed: %v", err)
                return
        }
        defer conn.Close()

        subID := fmt.Sprintf("ws-%d", time.Now().UnixNano())
        ch := s.SandboxManager.EventBus().Subscribe(subID)
        defer s.SandboxManager.EventBus().Unsubscribe(subID)

        go func() {
                for {
                        if _, _, err := conn.ReadMessage(); err != nil {
                                return
                        }
                }
        }()

        for event := range ch {
                data, err := json.Marshal(event)
                if err != nil {
                        continue
                }
                if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
                        return
                }
        }
}

func (s *CoreServer) handleTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
        if s.SandboxManager == nil {
                jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
                return
        }

        instanceID := chi.URLParam(r, "instanceId")

        brt := s.SandboxManager.GetBinaryRuntime(instanceID)
        if brt == nil {
                jsonError(w, "No binary runtime found for instance", http.StatusNotFound)
                return
        }

        conn, err := wsUpgrader.Upgrade(w, r, nil)
        if err != nil {
                log.Printf("[terminal-ws] Upgrade failed: %v", err)
                return
        }
        defer conn.Close()

        existingOutput := brt.GetOutput()
        for _, line := range existingOutput {
                conn.WriteMessage(websocket.TextMessage, []byte(line))
        }

        go func() {
                for {
                        _, msg, err := conn.ReadMessage()
                        if err != nil {
                                return
                        }
                        brt.WriteStdin(append(msg, '\n'))
                }
        }()

        ticker := time.NewTicker(100 * time.Millisecond)
        defer ticker.Stop()

        lastSent := len(existingOutput)

        for {
                select {
                case <-ticker.C:
                        output := brt.GetOutput()
                        if len(output) > lastSent {
                                for i := lastSent; i < len(output); i++ {
                                        if err := conn.WriteMessage(websocket.TextMessage, []byte(output[i])); err != nil {
                                                return
                                        }
                                }
                                lastSent = len(output)
                        }
                case <-brt.Done():
                        output := brt.GetOutput()
                        for i := lastSent; i < len(output); i++ {
                                conn.WriteMessage(websocket.TextMessage, []byte(output[i]))
                        }
                        conn.WriteMessage(websocket.TextMessage, []byte("[Process exited]"))
                        return
                }
        }
}

func isLocalRequest(r *http.Request) bool {
        host, _, _ := net.SplitHostPort(r.RemoteAddr)
        if host == "" {
                host = r.RemoteAddr
        }
        return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func (s *CoreServer) handlePodmanSetup(w http.ResponseWriter, r *http.Request) {
        if !isLocalRequest(r) {
                jsonError(w, "Podman setup is only available from the local machine", http.StatusForbidden)
                return
        }

        var body struct {
                Action string `json:"action"`
        }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                jsonError(w, "Invalid request body", http.StatusBadRequest)
                return
        }

        if body.Action != "install" && body.Action != "init-machine" && body.Action != "start-machine" {
                jsonError(w, "Invalid action. Must be one of: install, init-machine, start-machine", http.StatusBadRequest)
                return
        }

        if !sandbox.TryStartSetup() {
                jsonError(w, "A setup operation is already in progress", http.StatusConflict)
                return
        }

        go func() {
                defer sandbox.FinishSetup()
                if err := sandbox.RunPodmanSetup(body.Action); err != nil {
                        log.Printf("[podman-setup] Action %s failed: %v", body.Action, err)
                }
        }()

        jsonResponse(w, map[string]string{
                "status":  "started",
                "action":  body.Action,
                "message": fmt.Sprintf("Podman setup action '%s' started", body.Action),
        })
}

func (s *CoreServer) handlePodmanSetupStatus(w http.ResponseWriter, r *http.Request) {
        if !isLocalRequest(r) {
                jsonError(w, "Podman setup status is only available from the local machine", http.StatusForbidden)
                return
        }
        jsonResponse(w, sandbox.GetPodmanSetupStatus())
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, status int) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(map[string]string{"error": message})
}
