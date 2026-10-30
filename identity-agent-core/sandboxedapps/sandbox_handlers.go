package sandboxedapps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"identity-agent-core/sandbox"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func (s *sandboxedApps) sandboxRoutes(r chi.Router) {
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
	r.Post("/capabilities/{id}/invoke", s.handleInvokeCapability)
	r.Post("/capability-registry/packs", s.handleImportCapabilityPack)
	r.Get("/capability-registry", s.handleListCapabilityRegistry)
	r.Post("/capability-registry/{id}/enabled", s.handleSetCapabilityEnabled)
	r.Delete("/capability-registry/{id}", s.handleDeleteCapabilityRecord)
	r.Get("/sandbox/health", s.handleSandboxHealth)
	r.Post("/sandbox/podman/setup", s.handlePodmanSetup)
	r.Get("/sandbox/podman/setup-status", s.handlePodmanSetupStatus)
	r.Get("/ws/sandbox", s.handleSandboxWebSocket)
	r.Get("/ws/terminal/{instanceId}", s.handleTerminalWebSocket)
}

// handleListCapabilities returns the functional capabilities offered by installed
// plug-ins (aggregated from manifests' provides[]). Discovery surface for the agent's
// governed capability endpoint; invoking a capability is governed separately.
func (s *sandboxedApps) handleListCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	helpers.JSONResponse(w, s.SandboxManager.ProvidedCapabilities())
}

// handleInvokeCapability is the governed capability-invocation endpoint:
// ingress-authorize -> route to the providing plug-in -> egress-recheck -> return.
// A host-control capability is never invocable by a remote caller.
func (s *sandboxedApps) handleInvokeCapability(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	// Put the body back before anything resolves the caller.
	//
	// Identification digests the body, so reading it here and resolving after
	// left the resolver hashing nothing: the middleware saw a named machine and
	// this handler saw an anonymous remote, for the same request. The audit
	// record is written from the handler's context, so the caller it names was
	// the blank one.
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	caller := s.ResolveCaller(r)
	// Support the same identity-first path as /mcp: an optional signed-request
	// envelope proves the caller AID, and a proven agent picks up its lineage +
	// ceiling. Both are no-ops when no envelope is presented.
	if err := s.VerifyRequestEnvelope(r, "invoke:"+id, body, &caller); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.EnrichProvenCaller(&caller)
	helpers.ApplyCallerWhy(r, &caller)

	res, err := s.SandboxManager.InvokeCapability(r.Context(), caller, id, body)
	if err != nil {
		switch {
		case errors.Is(err, sandbox.ErrCapabilityNotFound):
			helpers.JSONError(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, sandbox.ErrDenied):
			helpers.JSONError(w, err.Error(), http.StatusForbidden)
		default:
			helpers.JSONError(w, err.Error(), http.StatusBadGateway)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.Status)
	w.Write(res.Body)
}

func (s *sandboxedApps) handleListApps(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	apps, err := s.SandboxManager.ListApps()
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, apps)
}

func (s *sandboxedApps) handleGetApp(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	app, err := s.SandboxManager.GetApp(id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if app == nil {
		helpers.JSONError(w, "App not found", http.StatusNotFound)
		return
	}

	helpers.JSONResponse(w, app)
}

func (s *sandboxedApps) handleInstallApp(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")

	s.InBackground(func(ctx context.Context) {
		err := s.SandboxManager.InstallApp(ctx, id, func(progress sandbox.PullProgress) {
			log.Printf("[sandbox-api] Pull progress for %s: %s %.1f%%", id, progress.Status, progress.Progress)
		})
		if err != nil {
			log.Printf("[sandbox-api] Install failed for %s: %v", id, err)
		}
	})

	helpers.JSONResponse(w, map[string]string{
		"status":  "installing",
		"message": fmt.Sprintf("Installation of %s started", id),
	})
}

func (s *sandboxedApps) handleInstallProgress(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	info := s.SandboxManager.GetInstallProgress(id)
	if info == nil {
		app, _ := s.SandboxManager.GetApp(id)
		if app != nil && app.InstallStatus == "installed" {
			helpers.JSONResponse(w, map[string]interface{}{
				"app_id":   id,
				"status":   "complete",
				"progress": 100.0,
				"done":     true,
			})
		} else {
			helpers.JSONResponse(w, map[string]interface{}{
				"app_id":   id,
				"status":   "idle",
				"progress": 0.0,
				"done":     false,
			})
		}
		return
	}
	helpers.JSONResponse(w, info)
}

func (s *sandboxedApps) handleUninstallApp(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if err := s.SandboxManager.UninstallApp(id); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "uninstalled"})
}

func (s *sandboxedApps) handleLaunchApp(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	instance, err := s.SandboxManager.LaunchApp(r.Context(), id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, instance)
}

func (s *sandboxedApps) handleStopApp(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	if err := s.SandboxManager.StopApp(r.Context(), id); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "stopped"})
}

func (s *sandboxedApps) handleAppStatus(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")

	status, err := s.SandboxManager.GetAppStatus(id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
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

	helpers.JSONResponse(w, result)
}

func (s *sandboxedApps) handleAppLogs(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
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
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, logs)
}

func (s *sandboxedApps) handleHeldLogs(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	held, err := s.SandboxManager.GetHeldRequests(id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, held)
}

func (s *sandboxedApps) handleApproveLog(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	logIDStr := chi.URLParam(r, "logId")
	logID, err := strconv.ParseInt(logIDStr, 10, 64)
	if err != nil {
		helpers.JSONError(w, "Invalid log ID", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.ApproveHeldRequest(logID, id); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "approved"})
}

func (s *sandboxedApps) handleBlockLog(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	logIDStr := chi.URLParam(r, "logId")
	logID, err := strconv.ParseInt(logIDStr, 10, 64)
	if err != nil {
		helpers.JSONError(w, "Invalid log ID", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.BlockHeldRequest(logID, id); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "blocked"})
}

func (s *sandboxedApps) handlePendingResources(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	reqs, err := s.SandboxManager.GetPendingResourceRequests(id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, reqs)
}

func (s *sandboxedApps) handleApproveResource(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	reqIDStr := chi.URLParam(r, "reqId")
	reqID, err := strconv.ParseInt(reqIDStr, 10, 64)
	if err != nil {
		helpers.JSONError(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.ApproveResourceRequest(reqID); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "approved"})
}

func (s *sandboxedApps) handleDenyResource(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	reqIDStr := chi.URLParam(r, "reqId")
	reqID, err := strconv.ParseInt(reqIDStr, 10, 64)
	if err != nil {
		helpers.JSONError(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.DenyResourceRequest(reqID); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "denied"})
}

func (s *sandboxedApps) handleBatchResources(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Approve []int64 `json:"approve"`
		Deny    []int64 `json:"deny"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		helpers.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.BatchResolveResourceRequests(body.Approve, body.Deny); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "processed"})
}

func (s *sandboxedApps) handleUpdateAppSettings(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")

	var settings map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		helpers.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.SandboxManager.UpdateAppSettings(id, settings); err != nil {
		helpers.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	helpers.JSONResponse(w, map[string]string{"status": "updated"})
}

func (s *sandboxedApps) handleAppDisplay(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	id := chi.URLParam(r, "id")
	// Verify the app is actually running before returning a proxy URL.
	_, err := s.SandboxManager.GetDisplayURL(id)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return the Identity Agent's reverse proxy URL instead of the container's
	// direct port. This allows the Identity Agent to intercept specific API
	// paths (e.g., chat data) and serve from its own data stores while
	// forwarding everything else to the container.
	proxyURL := s.appDisplayProxyURL(id)
	helpers.JSONResponse(w, map[string]string{"display_url": proxyURL})
}

func (s *sandboxedApps) handleSandboxHealth(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONResponse(w, map[string]interface{}{
			"sandbox_initialized": false,
			"container_engine":    sandbox.CheckContainerEngine(),
		})
		return
	}

	helpers.JSONResponse(w, s.SandboxManager.HealthCheck())
}

func (s *sandboxedApps) handleSandboxWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
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

func (s *sandboxedApps) handleTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		helpers.JSONError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}

	instanceID := chi.URLParam(r, "instanceId")

	brt := s.SandboxManager.GetBinaryRuntime(instanceID)
	if brt == nil {
		helpers.JSONError(w, "No binary runtime found for instance", http.StatusNotFound)
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

func (s *sandboxedApps) handlePodmanSetup(w http.ResponseWriter, r *http.Request) {
	if !isLocalRequest(r) {
		helpers.JSONError(w, "Podman setup is only available from the local machine", http.StatusForbidden)
		return
	}

	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		helpers.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if body.Action != "install" && body.Action != "init-machine" && body.Action != "start-machine" {
		helpers.JSONError(w, "Invalid action. Must be one of: install, init-machine, start-machine", http.StatusBadRequest)
		return
	}

	if !sandbox.TryStartSetup() {
		helpers.JSONError(w, "A setup operation is already in progress", http.StatusConflict)
		return
	}

	go func() {
		defer sandbox.FinishSetup()
		if err := sandbox.RunPodmanSetup(body.Action); err != nil {
			log.Printf("[podman-setup] Action %s failed: %v", body.Action, err)
		}
	}()

	helpers.JSONResponse(w, map[string]string{
		"status":  "started",
		"action":  body.Action,
		"message": fmt.Sprintf("Podman setup action '%s' started", body.Action),
	})
}

func (s *sandboxedApps) handlePodmanSetupStatus(w http.ResponseWriter, r *http.Request) {
	// Reading how far setup got is open to the owner's own machines; starting
	// it is not (controllerOwnerOnly).
	if !isLocalRequest(r) && !s.IsOwnerOrItsController(r) {
		helpers.JSONError(w, "Podman setup status is only available from the local machine", http.StatusForbidden)
		return
	}
	helpers.JSONResponse(w, sandbox.GetPodmanSetupStatus())
}
