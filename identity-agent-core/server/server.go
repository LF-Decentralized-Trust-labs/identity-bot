package server

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"

        "identity-agent-core/drivers"
        "identity-agent-core/endpoint"
        "identity-agent-core/sandbox"
        "identity-agent-core/store"
        "identity-agent-core/tunnel"

        "github.com/go-chi/chi/v5"
        "github.com/go-chi/chi/v5/middleware"
        "github.com/go-chi/cors"
)

type CoreServer struct {
        DataStore       store.Store
        AIMemory        *store.AIMemoryStore
        KeriDriver      *drivers.KeriDriver
        TunnelManager   *tunnel.Manager
        EndpointService *endpoint.EndpointService
        SandboxManager  *sandbox.Manager
        EventHub        *EventHub
        StartTime       time.Time
        Port            int
        DataDir         string
        AppCtx          context.Context
        cancel          context.CancelFunc
        listener        net.Listener
        router          chi.Router
        mu              sync.Mutex
        running         bool
}

type Config struct {
        DataDir        string
        Port           int
        EnableKeriDriver bool
        FlutterWebDir  string
}

func DefaultConfig() Config {
        dataDir := os.Getenv("AGENT_DATA_DIR")
        if dataDir == "" {
                dataDir = filepath.Join(".", "data")
        }

        port := 5000
        if p := os.Getenv("PORT"); p != "" {
                fmt.Sscanf(p, "%d", &port)
        }

        webDir := os.Getenv("FLUTTER_WEB_DIR")
        if webDir == "" {
                webDir = filepath.Join("..", "identity_agent_ui", "build", "web")
        }

        return Config{
                DataDir:         dataDir,
                Port:            port,
                EnableKeriDriver: true,
                FlutterWebDir:   webDir,
        }
}

func New(cfg Config) (*CoreServer, error) {
        ctx, cancel := context.WithCancel(context.Background())

        dataStore, err := store.NewSQLiteStore(cfg.DataDir)
        if err != nil {
                cancel()
                return nil, fmt.Errorf("failed to initialize store: %w", err)
        }

        aiMemory, err := store.NewAIMemoryStore(cfg.DataDir)
        if err != nil {
                cancel()
                dataStore.Close()
                return nil, fmt.Errorf("failed to initialize AI memory store: %w", err)
        }

        endpointSvc := endpoint.New(dataStore, cfg.Port)

        eventHub := NewEventHub()
        go eventHub.Run()

        s := &CoreServer{
                DataStore:       dataStore,
                AIMemory:        aiMemory,
                EndpointService: endpointSvc,
                EventHub:        eventHub,
                StartTime:       time.Now(),
                Port:            cfg.Port,
                DataDir:         cfg.DataDir,
                AppCtx:          ctx,
                cancel:          cancel,
        }

        if cfg.EnableKeriDriver {
                s.KeriDriver = drivers.NewKeriDriver()
                if err := s.KeriDriver.Start(); err != nil {
                        cancel()
                        dataStore.Close()
                        return nil, fmt.Errorf("failed to start KERI driver: %w", err)
                }
        }

        manifestsDir := filepath.Join(".", "manifests")
        sbxMgr, err := sandbox.NewManager(sandbox.ManagerConfig{
                DataDir:      cfg.DataDir,
                ManifestsDir: manifestsDir,
        })
        if err != nil {
                log.Printf("[identity-agent-core] Sandbox manager init failed (non-fatal): %v", err)
        } else {
                s.SandboxManager = sbxMgr
                if startErr := s.SandboxManager.Start(); startErr != nil {
                        log.Printf("[identity-agent-core] Sandbox manager start failed (non-fatal): %v", startErr)
                }
        }

        s.router = s.buildRouter(cfg.FlutterWebDir)

        return s, nil
}

func (s *CoreServer) Start() error {
        s.mu.Lock()
        defer s.mu.Unlock()

        if s.running {
                return fmt.Errorf("server already running")
        }

        tunnelCfg := s.loadTunnelConfig()
        s.TunnelManager = tunnel.NewManager(tunnelCfg, s.Port)
        s.EndpointService.SetTunnelManager(s.TunnelManager)
        s.EndpointService.Refresh()

        addr := fmt.Sprintf("0.0.0.0:%d", s.Port)
        var err error
        s.listener, err = net.Listen("tcp4", addr)
        if err != nil {
                return fmt.Errorf("failed to bind on %s: %w", addr, err)
        }

        s.running = true

        log.Printf("[identity-agent-core] Server listening on %s", addr)
        log.Printf("[identity-agent-core] Endpoint URL: %s (source: %s)", s.EndpointService.CurrentURL(), s.EndpointService.Source())
        if s.KeriDriver != nil {
                log.Printf("[identity-agent-core] KERI driver: %s", s.KeriDriver.BaseURL)
        } else {
                log.Printf("[identity-agent-core] KERI driver: disabled (mobile mode — use Rust bridge)")
        }

        go func() {
                if tunnelCfg.Provider == tunnel.ProviderNone {
                        log.Println("[identity-agent-core] No tunnel configured.")
                        s.EndpointService.Refresh()
                        return
                }
                if err := s.TunnelManager.Start(s.AppCtx); err != nil {
                        log.Printf("[identity-agent-core] Tunnel failed (non-fatal): %v", err)
                        s.EndpointService.Refresh()
                        return
                }
                s.EndpointService.Refresh()
                if s.TunnelManager.URL() != "" {
                        log.Printf("[identity-agent-core] OOBI public URL: %s", s.EndpointService.CurrentURL())
                        provider := s.TunnelManager.Provider()
                        if provider != nil && provider.Listener() != nil {
                                go func() {
                                        if err := http.Serve(provider.Listener(), s.router); err != nil {
                                                log.Printf("[identity-agent-core] Tunnel server stopped: %v", err)
                                        }
                                }()
                        }
                }
        }()

        go func() {
                if err := http.Serve(s.listener, s.router); err != nil {
                        log.Printf("[identity-agent-core] Server stopped: %v", err)
                }
        }()

        return nil
}

func (s *CoreServer) Stop() {
        s.mu.Lock()
        defer s.mu.Unlock()

        if !s.running {
                return
        }

        log.Println("[identity-agent-core] Shutting down...")

        if s.SandboxManager != nil {
                s.SandboxManager.Stop()
        }

        if s.TunnelManager != nil {
                s.TunnelManager.Disconnect()
        }

        if s.listener != nil {
                s.listener.Close()
        }

        if s.KeriDriver != nil {
                s.KeriDriver.Stop()
        }

        if s.DataStore != nil {
                s.DataStore.Close()
        }

        if s.cancel != nil {
                s.cancel()
        }

        s.running = false
        log.Println("[identity-agent-core] Shutdown complete")
}

func (s *CoreServer) IsRunning() bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.running
}

func (s *CoreServer) buildRouter(flutterWebDir string) chi.Router {
        r := chi.NewRouter()

        r.Use(middleware.Logger)
        r.Use(middleware.Recoverer)
        r.Use(middleware.RequestID)
        r.Use(cors.Handler(cors.Options{
                AllowedOrigins:   []string{"*"},
                AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
                AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
                ExposedHeaders:   []string{"Link"},
                AllowCredentials: true,
                MaxAge:           300,
        }))

        r.Route("/api", func(r chi.Router) {
                r.Get("/health", s.handleHealth)
                r.Get("/info", s.handleInfo)
                r.Get("/identity", s.handleIdentity)

                r.Post("/inception", s.handleInception)
                r.Post("/rotation", s.handleRotation)
                r.Post("/interact", s.handleInteract)
                r.Post("/sign", s.handleSign)
                r.Get("/kel", s.handleKel)
                r.Post("/verify", s.handleVerify)

                r.Post("/cesr/encode", s.handleCesrEncode)

                r.Post("/format-credential", s.handleFormatCredential)
                r.Post("/resolve-oobi", s.handleResolveOobi)
                r.Post("/generate-multisig-event", s.handleGenerateMultisigEvent)

                r.Post("/credential/issue", s.handleIssueCredential)
                r.Get("/credentials", s.handleGetCredentials)

                r.Get("/oobi", s.handleOobiGenerate)

                r.Get("/contacts", s.handleGetContacts)
                r.Post("/contacts/resolve", s.handleResolveOobiContact)
                r.Post("/contacts", s.handleAddContact)
                r.Get("/contacts/{aid}", s.handleGetContact)
                r.Get("/contacts/{aid}/kel", s.handleGetContactKEL)
                r.Delete("/contacts/{aid}", s.handleDeleteContact)
                r.Post("/contacts/{aid}/accept", s.handleAcceptContact)
                r.Post("/contacts/{aid}/reject", s.handleRejectContact)
                r.Get("/alerts", s.handleGetAlerts)
                r.Post("/exchange", s.handleExchange)

                r.Get("/profile", s.handleGetProfile)
                r.Put("/profile", s.handlePutProfile)

                r.Get("/settings/tunnel", s.handleGetTunnelSettings)
                r.Put("/settings/tunnel", s.handlePutTunnelSettings)
                r.Get("/settings/tunnel/check-name", s.handleCheckTunnelName)
                r.Get("/settings/tunnel/grapeid-health", s.handleGrapeIdHealth)
                r.Post("/settings/tunnel/release-name", s.handleReleaseTunnelName)
                r.Get("/tunnel/status", s.handleTunnelStatus)
                r.Post("/tunnel/restart", s.handleTunnelRestart)

                r.Get("/endpoint", s.handleGetEndpoint)

                r.Post("/store/identity", s.handleStoreIdentity)
                r.Post("/store/event", s.handleStoreEvent)

                r.Delete("/pending-requests/{aid}", s.handleDeletePendingRequest)
                r.Post("/reset", s.handleReset)

                s.sandboxRoutes(r)
                s.aiMemoryRoutes(r)
                r.Get("/ws/events", s.handleWebSocketEvents)
        })

        s.traceRoutes(r)
        s.llmRoutes(r)

        // Display reverse proxy: intercepts container API calls to serve from ai-memory.db
        r.HandleFunc("/apps/{app_id}/*", s.handleAppDisplayProxy)

        // /public/oobi/{aid} — public namespace: KERI OOBI endpoint shared with external agents.
        r.Get("/public/oobi/{aid}", s.handleOobiServe)

        absWebDir, err := filepath.Abs(flutterWebDir)
        if err != nil {
                absWebDir = flutterWebDir
        }

        if _, err := os.Stat(absWebDir); err == nil {
                log.Printf("[identity-agent-core] Serving Flutter web from: %s", absWebDir)
                fileServer := http.FileServer(http.Dir(absWebDir))
                r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
                        urlPath := r.URL.Path
                        filePath := filepath.Join(absWebDir, urlPath)
                        _, statErr := os.Stat(filePath)

                        // SPA fallback to index.html for unknown paths
                        if os.IsNotExist(statErr) {
                                w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
                                w.Header().Set("Pragma", "no-cache")
                                http.ServeFile(w, r, filepath.Join(absWebDir, "index.html"))
                                return
                        }

                        // index.html itself must never be cached — browser must always revalidate
                        if urlPath == "/" || urlPath == "/index.html" || strings.HasSuffix(urlPath, "/index.html") {
                                w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
                                w.Header().Set("Pragma", "no-cache")
                        } else {
                                // All other Flutter assets are content-hashed by the build — cache aggressively
                                w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
                        }

                        fileServer.ServeHTTP(w, r)
                })
        } else {
                r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
                        w.Header().Set("Content-Type", "text/html")
                        w.WriteHeader(200)
                        fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Identity Agent</title>
<style>body{background:#0A1628;color:#F0F4F8;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
.c{text-align:center;}.t{color:#00E5A0;font-size:14px;margin-top:12px;}</style></head>
<body><div class="c"><h1>IDENTITY AGENT CORE</h1><p style="color:#8B9DC3;">Go Core is running. Flutter web build not yet available.</p>
<p class="t">Run the Start Frontend workflow to build Flutter web.</p></div></body></html>`)
                })
        }

        return r
}

type HealthResponse struct {
        Status    string `json:"status"`
        Agent     string `json:"agent"`
        Version   string `json:"version"`
        Uptime    string `json:"uptime"`
        Timestamp string `json:"timestamp"`
        Mode      string `json:"mode"`
        TunnelURL string `json:"tunnel_url,omitempty"`
}

type CoreInfoResponse struct {
        Name         string      `json:"name"`
        Description  string      `json:"description"`
        Version      string      `json:"version"`
        Phase        string      `json:"phase"`
        Capabilities []string    `json:"capabilities"`
        Backend      BackendInfo `json:"backend"`
        Driver       DriverInfo  `json:"driver,omitempty"`
}

type BackendInfo struct {
        Mode      string `json:"mode"`
        Storage   string `json:"storage"`
        Port      int    `json:"port"`
        StartedAt string `json:"started_at"`
}

type DriverInfo struct {
        Status  string `json:"status"`
        Library string `json:"library"`
        URL     string `json:"url"`
}

type InceptionRequest struct {
        PublicKey     string `json:"public_key"`
        NextPublicKey string `json:"next_public_key"`
        // CesrSignature: optional — the controller's CESR '0B...' signature over the
        // inception event body, produced by Dart local signing + /api/cesr/encode.
        CesrSignature string `json:"cesr_signature,omitempty"`
}

type InceptionResponse struct {
        AID            string                 `json:"aid"`
        InceptionEvent map[string]interface{} `json:"inception_event"`
        // RawBytesB64: base64 of the serialized event body. Sign these bytes with
        // the Ed25519 key, then call POST /api/cesr/encode to get the CESR signature.
        RawBytesB64    string                 `json:"raw_bytes_b64"`
        PublicKey      string                 `json:"public_key"`
        Created        string                 `json:"created"`
}

type IdentityResponse struct {
        Initialized   bool   `json:"initialized"`
        AID           string `json:"aid,omitempty"`
        PublicKey     string `json:"public_key,omitempty"`
        NextKeyDigest string `json:"next_key_digest,omitempty"`
        Created       string `json:"created,omitempty"`
        EventCount    int    `json:"event_count,omitempty"`
}

type ErrorResponse struct {
        Error   string `json:"error"`
        Details string `json:"details,omitempty"`
}

func (s *CoreServer) handleHealth(w http.ResponseWriter, r *http.Request) {
        uptime := time.Since(s.StartTime).Round(time.Second)

        mode := "primary_active (driver: disabled)"
        if s.KeriDriver != nil {
                driverStatus := "unknown"
                status, err := s.KeriDriver.GetStatus()
                if err == nil {
                        driverStatus = status.Status
                }
                mode = fmt.Sprintf("primary_active (driver: %s)", driverStatus)
        }

        tunnelURL := s.EndpointService.CurrentURL()

        resp := HealthResponse{
                Status:    "active",
                Agent:     "keri-go",
                Version:   "0.1.0",
                Uptime:    uptime.String(),
                Timestamp: time.Now().UTC().Format(time.RFC3339),
                Mode:      mode,
                TunnelURL: tunnelURL,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleInfo(w http.ResponseWriter, r *http.Request) {
        identity, _ := s.DataStore.GetIdentity()
        phase := "Phase 2: Inception"
        if identity != nil {
                phase = "Phase 2: Inception (Identity Active)"
        }

        driverInfo := DriverInfo{
                Status:  "disabled",
                Library: "rust-bridge (mobile)",
                URL:     "n/a",
        }

        if s.KeriDriver != nil {
                driverInfo.URL = s.KeriDriver.BaseURL
                status, err := s.KeriDriver.GetStatus()
                if err == nil {
                        driverInfo.Status = status.Status
                        driverInfo.Library = status.KeriLibrary
                } else {
                        driverInfo.Status = "unknown"
                        driverInfo.Library = "unknown"
                }
        }

        resp := CoreInfoResponse{
                Name:        "Identity Agent Core",
                Description: "Self-sovereign identity runtime powered by KERI",
                Version:     "0.1.0",
                Phase:       phase,
                Capabilities: []string{
                        "health_check",
                        "inception",
                        "kel_storage",
                        "contacts",
                        "oobi",
                        "tunneling",
                },
                Backend: BackendInfo{
                        Mode:      "primary_active",
                        Storage:   "file-based (badgerdb pending)",
                        Port:      s.Port,
                        StartedAt: s.StartTime.UTC().Format(time.RFC3339),
                },
                Driver: driverInfo,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleIdentity(w http.ResponseWriter, r *http.Request) {
        identity, err := s.DataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }

        if identity == nil {
                resp := IdentityResponse{Initialized: false}
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(resp)
                return
        }

        resp := IdentityResponse{
                Initialized:   true,
                AID:           identity.AID,
                PublicKey:     identity.PublicKey,
                NextKeyDigest: identity.NextKeyDigest,
                Created:       identity.Created,
                EventCount:    identity.EventCount,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleInception(w http.ResponseWriter, r *http.Request) {
        existing, _ := s.DataStore.GetIdentity()
        if existing != nil {
                writeError(w, http.StatusConflict, "Identity already exists", "AID: "+existing.AID)
                return
        }

        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge for KERI inception, then call /api/store/identity and /api/store/event to persist the results")
                return
        }

        var req InceptionRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.PublicKey == "" || req.NextPublicKey == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "public_key and next_public_key are required")
                return
        }

        result, err := s.KeriDriver.CreateInception(req.PublicKey, req.NextPublicKey)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to create inception event", err.Error())
                return
        }

        now := time.Now().UTC().Format(time.RFC3339)
        eventJSON, _ := json.Marshal(result.InceptionEvent)
        eventRecord := store.EventRecord{
                AID:            result.AID,
                SequenceNumber: 0,
                EventType:      "icp",
                EventJSON:      string(eventJSON),
                PublicKey:      result.PublicKey,
                NextKeyDigest:  result.NextKeyDigest,
                Timestamp:      now,
                CesrSignature:  req.CesrSignature,
        }
        if err := s.DataStore.SaveEvent(eventRecord); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to persist inception event", err.Error())
                return
        }

        identityState := store.IdentityState{
                AID:           result.AID,
                PublicKey:     result.PublicKey,
                NextKeyDigest: result.NextKeyDigest,
                Created:       now,
                EventCount:    1,
        }
        if err := s.DataStore.SaveIdentity(identityState); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to persist identity state", err.Error())
                return
        }

        log.Printf("[identity-agent-core] INCEPTION: New identity created - AID: %s", result.AID)

        resp := InceptionResponse{
                AID:            result.AID,
                InceptionEvent: result.InceptionEvent,
                RawBytesB64:    result.RawBytesB64,
                PublicKey:      result.PublicKey,
                Created:        now,
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleStoreIdentity(w http.ResponseWriter, r *http.Request) {
        var req store.IdentityState
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.AID == "" || req.PublicKey == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "aid and public_key are required")
                return
        }

        if req.Created == "" {
                req.Created = time.Now().UTC().Format(time.RFC3339)
        }

        if err := s.DataStore.SaveIdentity(req); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to persist identity state", err.Error())
                return
        }

        log.Printf("[identity-agent-core] STORE: Identity saved - AID: %s", req.AID)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(map[string]string{"status": "saved", "aid": req.AID})
}

func (s *CoreServer) handleStoreEvent(w http.ResponseWriter, r *http.Request) {
        var req store.EventRecord
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.AID == "" || req.EventType == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "aid and event_type are required")
                return
        }

        if req.Timestamp == "" {
                req.Timestamp = time.Now().UTC().Format(time.RFC3339)
        }

        if err := s.DataStore.SaveEvent(req); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to persist event", err.Error())
                return
        }

        log.Printf("[identity-agent-core] STORE: Event saved - AID: %s type: %s sn: %d", req.AID, req.EventType, req.SequenceNumber)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(map[string]string{"status": "saved", "aid": req.AID, "event_type": req.EventType})
}

func (s *CoreServer) handleRotation(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge for key rotation, then call /api/store/event to persist the result")
                return
        }

        var req struct {
                Name             string `json:"name"`
                NewPublicKey     string `json:"new_public_key"`
                NewNextPublicKey string `json:"new_next_public_key"`
                CesrSignature    string `json:"cesr_signature,omitempty"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.Name == "" || req.NewPublicKey == "" || req.NewNextPublicKey == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "name, new_public_key, and new_next_public_key are required")
                return
        }

        result, err := s.KeriDriver.RotateAid(req.Name, req.NewPublicKey, req.NewNextPublicKey)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Rotation failed", err.Error())
                return
        }

        now := time.Now().UTC().Format(time.RFC3339)
        eventJSON, _ := json.Marshal(result.RotationEvent)
        eventRecord := store.EventRecord{
                AID:            result.AID,
                SequenceNumber: result.SequenceNumber,
                EventType:      "rot",
                EventJSON:      string(eventJSON),
                PublicKey:      result.NewPublicKey,
                NextKeyDigest:  result.NewNextKeyDigest,
                Timestamp:      now,
                CesrSignature:  req.CesrSignature,
        }
        if err := s.DataStore.SaveEvent(eventRecord); err != nil {
                log.Printf("[identity-agent-core] Warning: failed to persist rotation event: %v", err)
        }

        identity, _ := s.DataStore.GetIdentity()
        if identity != nil {
                identity.PublicKey = result.NewPublicKey
                identity.NextKeyDigest = result.NewNextKeyDigest
                identity.EventCount = result.SequenceNumber + 1
                s.DataStore.SaveIdentity(*identity)
        }

        log.Printf("[identity-agent-core] ROTATION: Key rotated for AID: %s (sn: %d)", result.AID, result.SequenceNumber)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleInteract(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge for IXN events")
                return
        }

        var req struct {
                Name          string        `json:"name"`
                Data          []interface{} `json:"data"`
                CesrSignature string        `json:"cesr_signature,omitempty"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }
        if req.Name == "" {
                writeError(w, http.StatusBadRequest, "Missing required field", "name is required")
                return
        }

        result, err := s.KeriDriver.Interact(req.Name, req.Data)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "IXN event failed", err.Error())
                return
        }

        now := time.Now().UTC().Format(time.RFC3339)
        eventJSON, _ := json.Marshal(result.IxnEvent)
        eventRecord := store.EventRecord{
                AID:            result.AID,
                SequenceNumber: result.SequenceNumber,
                EventType:      "ixn",
                EventJSON:      string(eventJSON),
                Timestamp:      now,
                CesrSignature:  req.CesrSignature,
        }
        if err := s.DataStore.SaveEvent(eventRecord); err != nil {
                log.Printf("[identity-agent-core] Warning: failed to persist IXN event: %v", err)
        }

        identity, _ := s.DataStore.GetIdentity()
        if identity != nil {
                identity.EventCount = result.SequenceNumber + 1
                s.DataStore.SaveIdentity(*identity)
        }

        log.Printf("[identity-agent-core] IXN: Interaction event for AID: %s (sn: %d, said: %s)",
                result.AID, result.SequenceNumber, result.Said)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleSign(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge for signing operations")
                return
        }

        var req struct {
                Name string `json:"name"`
                Data string `json:"data"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.Name == "" || req.Data == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "name and data (base64) are required")
                return
        }

        result, err := s.KeriDriver.SignPayload(req.Name, req.Data)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Signing failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleKel(w http.ResponseWriter, r *http.Request) {
        name := r.URL.Query().Get("name")
        if name == "" {
                writeError(w, http.StatusBadRequest, "Missing required parameter", "name query parameter is required")
                return
        }

        if s.KeriDriver == nil {
                events, err := s.DataStore.GetEvents(name)
                if err != nil {
                        writeError(w, http.StatusInternalServerError, "Failed to retrieve KEL from store", err.Error())
                        return
                }
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "aid":         name,
                        "kel":         events,
                        "event_count": len(events),
                })
                return
        }

        result, err := s.KeriDriver.GetKel(name)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to retrieve KEL", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleVerify(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge for signature verification")
                return
        }

        var req struct {
                Data      string `json:"data"`
                Signature string `json:"signature"`
                PublicKey string `json:"public_key"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.Data == "" || req.Signature == "" || req.PublicKey == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "data, signature, and public_key are required")
                return
        }

        result, err := s.KeriDriver.VerifySignature(req.Data, req.Signature, req.PublicKey)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Verification failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleCesrEncode(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, CESR encoding is handled by the Rust bridge")
                return
        }

        var req struct {
                RawSigB64 string `json:"raw_sig_b64"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }
        if req.RawSigB64 == "" {
                writeError(w, http.StatusBadRequest, "Missing required field", "raw_sig_b64 is required")
                return
        }

        result, err := s.KeriDriver.CesrEncode(req.RawSigB64)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "CESR encoding failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleFormatCredential(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge or remote KERI helper for credential formatting")
                return
        }

        var req struct {
                Claims     map[string]interface{} `json:"claims"`
                SchemaSaid string                 `json:"schema_said"`
                IssuerAid  string                 `json:"issuer_aid"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if len(req.Claims) == 0 || req.SchemaSaid == "" || req.IssuerAid == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "claims, schema_said, and issuer_aid are required")
                return
        }

        result, err := s.KeriDriver.FormatCredential(req.Claims, req.SchemaSaid, req.IssuerAid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Format credential failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "Credential issuance requires the Python KERI driver (desktop only)")
                return
        }

        var req struct {
                Claims        map[string]interface{} `json:"claims"`
                SchemaSaid    string                 `json:"schema_said"`
                HolderAid     string                 `json:"holder_aid"`
                CesrSignature string                 `json:"cesr_signature,omitempty"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }
        if len(req.Claims) == 0 || req.SchemaSaid == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "claims and schema_said are required")
                return
        }

        identity, err := s.DataStore.GetIdentity()
        if err != nil || identity == nil {
                writeError(w, http.StatusBadRequest, "No identity found", "Create an identity before issuing credentials")
                return
        }

        result, err := s.KeriDriver.IssueCredential(identity.AID, req.Claims, req.SchemaSaid, req.HolderAid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Credential issuance failed", err.Error())
                return
        }

        // Persist the credential record
        record := store.CredentialRecord{
                SAID:          result.AcdcSaid,
                IssuerAID:     identity.AID,
                HolderAID:     req.HolderAid,
                SchemaSAID:    req.SchemaSaid,
                AcdcJson:      result.AcdcJsonB64,
                IxnSAID:       result.IxnSaid,
                CesrSignature: req.CesrSignature,
                IssuedAt:      time.Now().UTC().Format(time.RFC3339),
                Status:        "issued",
        }
        if err := s.DataStore.SaveCredential(record); err != nil {
                log.Printf("[identity-agent-core] CREDENTIAL: Failed to persist credential %s: %v", result.AcdcSaid, err)
        }

        // Persist the IXN event in the KEL
        ixnEventJSON, _ := json.Marshal(result.IxnEvent)
        kelRecord := store.EventRecord{
                AID:            identity.AID,
                SequenceNumber: result.SequenceNumber,
                EventType:      "ixn",
                EventJSON:      string(ixnEventJSON),
                PublicKey:      identity.PublicKey,
                NextKeyDigest:  identity.NextKeyDigest,
                Timestamp:      time.Now().UTC().Format(time.RFC3339),
                CesrSignature:  req.CesrSignature,
        }
        if err := s.DataStore.SaveEvent(kelRecord); err != nil {
                log.Printf("[identity-agent-core] CREDENTIAL: Failed to persist IXN event for credential %s: %v", result.AcdcSaid, err)
        }

        log.Printf("[identity-agent-core] CREDENTIAL: Issued %s for holder %s (IXN sn=%d)", result.AcdcSaid, req.HolderAid, result.SequenceNumber)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(map[string]interface{}{
                "acdc_said":        result.AcdcSaid,
                "acdc_json_b64":    result.AcdcJsonB64,
                "ixn_raw_bytes_b64": result.IxnRawBytesB64,
                "ixn_said":         result.IxnSaid,
                "sequence_number":  result.SequenceNumber,
                "status":           "issued",
        })
}

func (s *CoreServer) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
        creds, err := s.DataStore.GetCredentials()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read credentials", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "credentials": creds,
                "count":       len(creds),
        })
}

func (s *CoreServer) handleResolveOobi(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge or remote KERI helper for OOBI resolution")
                return
        }

        var req struct {
                URL string `json:"url"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.URL == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "url is required")
                return
        }

        result, err := s.KeriDriver.ResolveOobi(req.URL)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "OOBI resolution failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleGenerateMultisigEvent(w http.ResponseWriter, r *http.Request) {
        if s.KeriDriver == nil {
                writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
                        "On mobile, use the Rust bridge or remote KERI helper for multisig event generation")
                return
        }

        var req struct {
                AIDs        []string `json:"aids"`
                Threshold   int      `json:"threshold"`
                CurrentKeys []string `json:"current_keys"`
                EventType   string   `json:"event_type"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if len(req.AIDs) == 0 || len(req.CurrentKeys) == 0 {
                writeError(w, http.StatusBadRequest, "Missing required fields", "aids and current_keys are required")
                return
        }

        if req.EventType == "" {
                req.EventType = "inception"
        }

        result, err := s.KeriDriver.GenerateMultisigEvent(req.AIDs, req.Threshold, req.CurrentKeys, req.EventType)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Multisig event generation failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (es *CoreServer) getPublicURL(r *http.Request) string {
        if url := es.EndpointService.CurrentURL(); url != "" {
                return url
        }

        scheme := "https"
        if r.TLS == nil {
                if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
                        scheme = fwdProto
                }
        }

        host := r.Host
        if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
                host = fwdHost
        }

        return fmt.Sprintf("%s://%s", scheme, host)
}

func (s *CoreServer) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
        state := s.EndpointService.State()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(state)
}

func (s *CoreServer) handleOobiGenerate(w http.ResponseWriter, r *http.Request) {
        identity, err := s.DataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }
        if identity == nil {
                writeError(w, http.StatusNotFound, "No identity created", "Create an identity first using /api/inception")
                return
        }

        baseURL := s.getPublicURL(r)
        oobiURL := fmt.Sprintf("%s/public/oobi/%s", baseURL, identity.AID)

        tunnelActive := false
        tunnelProvider := ""
        tunnelError := ""
        if s.TunnelManager != nil {
                status := s.TunnelManager.GetStatus()
                tunnelActive = status.Active
                tunnelProvider = string(status.Provider)
                tunnelError = status.Error
        }

        resp := map[string]interface{}{
                "oobi_url":        oobiURL,
                "aid":             identity.AID,
                "public_key":      identity.PublicKey,
                "base_url":        baseURL,
                "tunnel_active":   tunnelActive,
                "tunnel_provider": tunnelProvider,
                "tunnel_error":    tunnelError,
                "endpoint_url":    s.EndpointService.CurrentURL(),
                "endpoint_source": s.EndpointService.Source(),
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleOobiServe(w http.ResponseWriter, r *http.Request) {
        requestedAID := chi.URLParam(r, "aid")
        if requestedAID == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        identity, err := s.DataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }
        if identity == nil || identity.AID != requestedAID {
                writeError(w, http.StatusNotFound, "AID not found", fmt.Sprintf("No identity found for AID: %s", requestedAID))
                return
        }

        events, err := s.DataStore.GetEvents(requestedAID)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read KEL", err.Error())
                return
        }

        alias := identity.AID[:12] + "..."
        profile, _ := s.DataStore.GetProfile()
        var jcard *store.JCard
        if profile != nil {
                publicURL := s.getPublicURL(r)
                oobiURL := fmt.Sprintf("%s/oobi/%s", publicURL, identity.AID)
                jcard = profile.ToJCard(identity.AID, oobiURL)
                if profile.FullName != "" {
                        alias = profile.FullName
                }
        }

        resp := map[string]interface{}{
                "aid":         identity.AID,
                "public_key":  identity.PublicKey,
                "alias":       alias,
                "kel":         events,
                "event_count": identity.EventCount,
                "created":     identity.Created,
        }
        if jcard != nil {
                resp["jcard"] = jcard
        }
        if profile != nil && profile.Photo != "" {
                resp["photo"] = profile.Photo
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleGetContacts(w http.ResponseWriter, r *http.Request) {
        contacts, err := s.DataStore.GetContacts()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contacts", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "contacts": contacts,
                "count":    len(contacts),
        })
}

func (s *CoreServer) handleGetContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := s.DataStore.GetContact(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact", err.Error())
                return
        }
        if contact == nil {
                writeError(w, http.StatusNotFound, "Contact not found", fmt.Sprintf("No contact found for AID: %s", aid))
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(contact)
}

func (s *CoreServer) handleGetContactKEL(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "aid path parameter is required")
                return
        }

        kelRecord, err := s.DataStore.GetContactKEL(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact KEL", err.Error())
                return
        }
        if kelRecord == nil {
                writeError(w, http.StatusNotFound, "No KEL found", fmt.Sprintf("No validated KEL stored for AID: %s", aid))
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(kelRecord)
}

func (s *CoreServer) handleResolveOobiContact(w http.ResponseWriter, r *http.Request) {
        var req struct {
                OobiURL string `json:"oobi_url"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }
        if req.OobiURL == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "oobi_url is required")
                return
        }

        identity, _ := s.DataStore.GetIdentity()
        if identity != nil && strings.Contains(req.OobiURL, identity.AID) {
                writeError(w, http.StatusBadRequest, "Cannot add yourself", "The OOBI URL points to your own identity")
                return
        }

        log.Printf("[identity-agent-core] OOBI-RESOLVE: Resolving OOBI at %s", req.OobiURL)

        client := &http.Client{Timeout: 15 * time.Second}
        resp, err := client.Get(req.OobiURL)
        if err != nil {
                log.Printf("[identity-agent-core] OOBI-RESOLVE: Failed to reach %s: %v", req.OobiURL, err)
                writeError(w, http.StatusBadGateway, "Failed to resolve OOBI", fmt.Sprintf("Could not reach %s: %v", req.OobiURL, err))
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                body, _ := io.ReadAll(resp.Body)
                log.Printf("[identity-agent-core] OOBI-RESOLVE: Remote returned %d: %s", resp.StatusCode, string(body))
                writeError(w, http.StatusBadGateway, "OOBI resolution failed", fmt.Sprintf("Remote returned %d: %s", resp.StatusCode, string(body)))
                return
        }

        var oobiData struct {
                AID        string                   `json:"aid"`
                PublicKey  string                   `json:"public_key"`
                Alias      string                   `json:"alias"`
                KEL        []map[string]interface{} `json:"kel"`
                EventCount int                      `json:"event_count"`
                Created    string                   `json:"created"`
                JCard      *store.JCard             `json:"jcard,omitempty"`
                Photo      string                   `json:"photo,omitempty"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&oobiData); err != nil {
                writeError(w, http.StatusBadGateway, "Invalid OOBI response", fmt.Sprintf("Could not parse response: %v", err))
                return
        }

        if oobiData.AID == "" {
                writeError(w, http.StatusBadGateway, "Invalid OOBI response", "Response did not contain an AID")
                return
        }

        kelCount := len(oobiData.KEL)
        log.Printf("[identity-agent-core] OOBI-RESOLVE: Success — AID=%s, alias=%s, KEL events=%d", oobiData.AID, oobiData.Alias, kelCount)

        // Validate the KEL via the Python driver (desktop only — driver is nil on mobile).
        kelVerified := false
        currentPublicKey := oobiData.PublicKey
        var validationErrors []string
        if s.KeriDriver != nil && kelCount > 0 {
                valResult, err := s.KeriDriver.ValidateKEL(oobiData.AID, oobiData.KEL)
                if err != nil {
                        log.Printf("[identity-agent-core] OOBI-RESOLVE: KEL validation error for %s: %v", oobiData.AID, err)
                        validationErrors = []string{err.Error()}
                } else {
                        kelVerified = valResult.KelVerified
                        if valResult.CurrentPublicKey != "" {
                                currentPublicKey = valResult.CurrentPublicKey
                        }
                        validationErrors = valResult.ValidationErrors
                        log.Printf("[identity-agent-core] OOBI-RESOLVE: KEL validated=%v events=%d for %s",
                                kelVerified, valResult.EventsValidated, oobiData.AID)
                }

                kelRecord := store.ContactKELRecord{
                        AID:              oobiData.AID,
                        KEL:              oobiData.KEL,
                        KelVerified:      kelVerified,
                        CurrentPublicKey: currentPublicKey,
                        EventsValidated:  kelCount,
                        ValidationErrors: validationErrors,
                        ValidatedAt:      time.Now().UTC().Format(time.RFC3339),
                }
                if err := s.DataStore.SaveContactKEL(kelRecord); err != nil {
                        log.Printf("[identity-agent-core] OOBI-RESOLVE: Failed to store contact KEL for %s: %v", oobiData.AID, err)
                }
        }

        result := map[string]interface{}{
                "resolved":          true,
                "aid":               oobiData.AID,
                "public_key":        currentPublicKey,
                "alias":             oobiData.Alias,
                "oobi_url":          req.OobiURL,
                "kel":               oobiData.KEL,
                "event_count":       kelCount,
                "created":           oobiData.Created,
                "kel_verified":      kelVerified,
                "validation_errors": validationErrors,
        }
        if oobiData.JCard != nil {
                result["jcard"] = oobiData.JCard
        }
        if oobiData.Photo != "" {
                result["photo"] = oobiData.Photo
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleAddContact(w http.ResponseWriter, r *http.Request) {
        var req struct {
                OobiURL string `json:"oobi_url"`
                Alias   string `json:"alias"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.OobiURL == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "oobi_url is required")
                return
        }

        identity, _ := s.DataStore.GetIdentity()
        if identity != nil && strings.Contains(req.OobiURL, identity.AID) {
                writeError(w, http.StatusBadRequest, "Cannot add yourself", "The OOBI URL points to your own identity")
                return
        }

        client := &http.Client{Timeout: 15 * time.Second}
        resp, err := client.Get(req.OobiURL)
        if err != nil {
                writeError(w, http.StatusBadGateway, "Failed to resolve OOBI", fmt.Sprintf("Could not reach %s: %v", req.OobiURL, err))
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                body, _ := io.ReadAll(resp.Body)
                writeError(w, http.StatusBadGateway, "OOBI resolution failed", fmt.Sprintf("Remote returned %d: %s", resp.StatusCode, string(body)))
                return
        }

        var oobiData struct {
                AID       string                   `json:"aid"`
                PublicKey string                   `json:"public_key"`
                Alias     string                   `json:"alias"`
                KEL       []map[string]interface{} `json:"kel"`
                JCard     *store.JCard             `json:"jcard,omitempty"`
                Photo     string                   `json:"photo,omitempty"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&oobiData); err != nil {
                writeError(w, http.StatusBadGateway, "Invalid OOBI response", fmt.Sprintf("Could not parse response: %v", err))
                return
        }

        if oobiData.AID == "" {
                writeError(w, http.StatusBadGateway, "Invalid OOBI response", "Response did not contain an AID")
                return
        }

        // Validate KEL (desktop only).
        kelVerified := false
        currentPublicKey := oobiData.PublicKey
        if s.KeriDriver != nil && len(oobiData.KEL) > 0 {
                valResult, err := s.KeriDriver.ValidateKEL(oobiData.AID, oobiData.KEL)
                if err != nil {
                        log.Printf("[identity-agent-core] CONTACT: KEL validation error for %s: %v", oobiData.AID, err)
                } else {
                        kelVerified = valResult.KelVerified
                        if valResult.CurrentPublicKey != "" {
                                currentPublicKey = valResult.CurrentPublicKey
                        }
                        kelRecord := store.ContactKELRecord{
                                AID:              oobiData.AID,
                                KEL:              oobiData.KEL,
                                KelVerified:      kelVerified,
                                CurrentPublicKey: currentPublicKey,
                                EventsValidated:  len(oobiData.KEL),
                                ValidationErrors: valResult.ValidationErrors,
                                ValidatedAt:      time.Now().UTC().Format(time.RFC3339),
                        }
                        if err := s.DataStore.SaveContactKEL(kelRecord); err != nil {
                                log.Printf("[identity-agent-core] CONTACT: Failed to store KEL for %s: %v", oobiData.AID, err)
                        }
                }
        }

        alias := req.Alias
        if alias == "" && oobiData.Alias != "" {
                alias = oobiData.Alias
        }
        if alias == "" {
                if len(oobiData.AID) >= 12 {
                        alias = oobiData.AID[:12] + "..."
                } else {
                        alias = oobiData.AID
                }
        }

        contactJCard := oobiData.JCard
        if contactJCard == nil {
                contactJCard = &store.JCard{
                        FullName:  alias,
                        XKeriAID:  oobiData.AID,
                        XKeriOOBI: req.OobiURL,
                        XKeriRole: "agent",
                }
        }

        contactStatus := "verified"
        if s.KeriDriver != nil && len(oobiData.KEL) > 0 && !kelVerified {
                contactStatus = "unverified"
        }

        contact := store.ContactRecord{
                AID:          oobiData.AID,
                Alias:        alias,
                PublicKey:    currentPublicKey,
                OobiURL:      req.OobiURL,
                Verified:     kelVerified || s.KeriDriver == nil,
                DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
                Status:       contactStatus,
                Role:         "agent",
                JCard:        contactJCard,
                Photo:        oobiData.Photo,
        }

        if err := s.DataStore.SaveContact(contact); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Added %s (AID: %s) status=%s kel_verified=%v", alias, oobiData.AID, contactStatus, kelVerified)

        publicURL := s.getPublicURL(r)
        go func() {
                ourIdentity, err := s.DataStore.GetIdentity()
                if err != nil || ourIdentity == nil {
                        log.Printf("[identity-agent-core] EXCHANGE: Cannot send introduction — no identity available")
                        return
                }

                ourOOBI := fmt.Sprintf("%s/public/oobi/%s", publicURL, ourIdentity.AID)
                ourAlias := ourIdentity.AID[:12] + "..."
                ourProfile, _ := s.DataStore.GetProfile()
                if ourProfile != nil && ourProfile.FullName != "" {
                        ourAlias = ourProfile.FullName
                }

                remoteBase := oobiBase(req.OobiURL)
                exchangeURL := remoteBase + "/api/exchange"

                log.Printf("[identity-agent-core] EXCHANGE: Preparing reverse introduction to %s", exchangeURL)
                log.Printf("[identity-agent-core] EXCHANGE: Our OOBI: %s", ourOOBI)
                log.Printf("[identity-agent-core] EXCHANGE: Our AID: %s", ourIdentity.AID)

                payload := map[string]interface{}{
                        "type":              "introduction",
                        "sender_aid":        ourIdentity.AID,
                        "sender_oobi":       ourOOBI,
                        "sender_alias":      ourAlias,
                        "sender_public_key": ourIdentity.PublicKey,
                }
                if ourProfile != nil {
                        jc := ourProfile.ToJCard(ourIdentity.AID, ourOOBI)
                        payload["sender_jcard"] = jc
                        if ourProfile.Photo != "" {
                                payload["sender_photo"] = ourProfile.Photo
                        }
                }
                body, _ := json.Marshal(payload)

                exnClient := &http.Client{Timeout: 15 * time.Second}
                exnResp, err := exnClient.Post(exchangeURL, "application/json", bytes.NewReader(body))
                if err != nil {
                        log.Printf("[identity-agent-core] EXCHANGE: FAILED to send introduction to %s: %v", exchangeURL, err)
                        log.Printf("[identity-agent-core] EXCHANGE: This may mean the remote agent is not reachable. The contact was saved locally but the remote agent will not know about us.")
                        return
                }
                defer exnResp.Body.Close()
                respBody, _ := io.ReadAll(exnResp.Body)
                log.Printf("[identity-agent-core] EXCHANGE: Introduction sent to %s — response: %d %s", exchangeURL, exnResp.StatusCode, string(respBody))
        }()

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(contact)
}

func (s *CoreServer) handleDeleteContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := s.DataStore.GetContact(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact", err.Error())
                return
        }
        if contact == nil {
                writeError(w, http.StatusNotFound, "Contact not found", fmt.Sprintf("No contact found for AID: %s", aid))
                return
        }

        if err := s.DataStore.DeleteContact(aid); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to delete contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Removed %s (AID: %s)", contact.Alias, aid)

        w.WriteHeader(http.StatusNoContent)
}

func (s *CoreServer) handleExchange(w http.ResponseWriter, r *http.Request) {
        var req struct {
                Type            string       `json:"type"`
                SenderAID       string       `json:"sender_aid"`
                SenderOOBI      string       `json:"sender_oobi"`
                SenderAlias     string       `json:"sender_alias"`
                SenderPublicKey string       `json:"sender_public_key"`
                SenderJCard     *store.JCard `json:"sender_jcard,omitempty"`
                SenderPhoto     string       `json:"sender_photo,omitempty"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
                return
        }

        if req.Type == "acceptance" {
                if req.SenderAID == "" {
                        writeError(w, http.StatusBadRequest, "Missing required fields", "sender_aid is required for acceptance")
                        return
                }
                existing, _ := s.DataStore.GetContact(req.SenderAID)
                if existing != nil && (existing.Status == "pending_outbound" || existing.Status == "pending_inbound") {
                        existing.Status = "mutual"
                        s.DataStore.SaveContact(*existing)
                        log.Printf("[identity-agent-core] EXCHANGE: Acceptance received — contact %s upgraded to mutual", req.SenderAID)
                        s.EventHub.Broadcast(AgentEvent{
                                Type: "contact_accepted",
                                Payload: map[string]interface{}{
                                        "sender_aid":   req.SenderAID,
                                        "sender_alias": existing.Alias,
                                },
                        })
                }
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged", "aid": req.SenderAID})
                return
        }

        if req.Type != "introduction" {
                writeError(w, http.StatusBadRequest, "Invalid exchange type", fmt.Sprintf("Expected 'introduction' or 'acceptance', got '%s'", req.Type))
                return
        }

        if req.SenderAID == "" || req.SenderOOBI == "" {
                writeError(w, http.StatusBadRequest, "Missing required fields", "sender_aid and sender_oobi are required")
                return
        }

        existing, _ := s.DataStore.GetContact(req.SenderAID)
        if existing != nil {
                if existing.Status == "mutual" {
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(map[string]string{"status": "already_mutual", "aid": req.SenderAID})
                        return
                }
                if existing.Status == "pending_outbound" || existing.Status == "verified" {
                        existing.Status = "mutual"
                        s.DataStore.SaveContact(*existing)
                        log.Printf("[identity-agent-core] EXCHANGE: Introduction received — contact %s auto-upgraded to mutual", req.SenderAID)
                        s.EventHub.Broadcast(AgentEvent{
                                Type: "contact_accepted",
                                Payload: map[string]interface{}{
                                        "sender_aid":   req.SenderAID,
                                        "sender_alias": existing.Alias,
                                },
                        })
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(map[string]string{"status": "mutual", "aid": req.SenderAID})
                        return
                }
        }

        log.Printf("[identity-agent-core] EXCHANGE: Attempting to resolve sender OOBI: %s", req.SenderOOBI)

        client := &http.Client{Timeout: 15 * time.Second}
        oobiResp, err := client.Get(req.SenderOOBI)
        oobiReachable := false
        kelPresent := false
        var oobiErrorMsg string

        if err != nil {
                oobiErrorMsg = fmt.Sprintf("Could not reach OOBI: %v", err)
                log.Printf("[identity-agent-core] EXCHANGE: OOBI unreachable — %s", oobiErrorMsg)
        } else {
                defer oobiResp.Body.Close()
                if oobiResp.StatusCode == http.StatusOK {
                        var oobiBody struct {
                                AID string      `json:"aid"`
                                KEL interface{} `json:"kel"`
                        }
                        if err := json.NewDecoder(oobiResp.Body).Decode(&oobiBody); err == nil {
                                oobiReachable = true
                                if events, ok := oobiBody.KEL.([]interface{}); ok && len(events) > 0 {
                                        kelPresent = true
                                        log.Printf("[identity-agent-core] EXCHANGE: OOBI resolved — AID=%s, KEL events=%d", oobiBody.AID, len(events))
                                } else {
                                        log.Printf("[identity-agent-core] EXCHANGE: OOBI resolved but KEL is empty for AID=%s", oobiBody.AID)
                                }
                        }
                } else {
                        oobiErrorMsg = fmt.Sprintf("OOBI returned status %d", oobiResp.StatusCode)
                        log.Printf("[identity-agent-core] EXCHANGE: OOBI returned non-200: %d", oobiResp.StatusCode)
                }
        }

        alias := req.SenderAlias
        if alias == "" && len(req.SenderAID) >= 12 {
                alias = req.SenderAID[:12] + "..."
        } else if alias == "" {
                alias = req.SenderAID
        }

        if !oobiReachable {
                pendingJCard := req.SenderJCard
                if pendingJCard == nil {
                        pendingJCard = &store.JCard{
                                FullName:  alias,
                                XKeriAID:  req.SenderAID,
                                XKeriOOBI: req.SenderOOBI,
                                XKeriRole: "agent",
                        }
                }
                pendingReq := store.PendingRequest{
                        AID:         req.SenderAID,
                        Alias:       alias,
                        PublicKey:   req.SenderPublicKey,
                        OobiURL:     req.SenderOOBI,
                        ReceivedAt:  time.Now().UTC().Format(time.RFC3339),
                        ExpiresAt:   time.Now().AddDate(0, 0, 90).UTC().Format(time.RFC3339),
                        ErrorReason: oobiErrorMsg,
                        JCard:       pendingJCard,
                }
                if err := s.DataStore.SavePendingRequest(pendingReq); err != nil {
                        writeError(w, http.StatusInternalServerError, "Failed to save pending request", err.Error())
                        return
                }
                log.Printf("[identity-agent-core] EXCHANGE: Saved as PENDING REQUEST (OOBI unreachable) — AID=%s, error=%s", req.SenderAID, oobiErrorMsg)

                s.EventHub.Broadcast(AgentEvent{
                        Type: "pending_request_received",
                        Payload: map[string]interface{}{
                                "sender_aid":   req.SenderAID,
                                "sender_alias": alias,
                                "error":        oobiErrorMsg,
                        },
                })

                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "status":  "received_pending",
                        "aid":     req.SenderAID,
                        "error":   "sender_oobi_unreachable",
                        "message": "Contact request received but sender OOBI could not be reached. Sender needs to set up tunneling.",
                })
                return
        }

        contactJCard := req.SenderJCard
        if contactJCard == nil {
                contactJCard = &store.JCard{
                        FullName:  alias,
                        XKeriAID:  req.SenderAID,
                        XKeriOOBI: req.SenderOOBI,
                        XKeriRole: "agent",
                }
        }
        contact := store.ContactRecord{
                AID:          req.SenderAID,
                Alias:        alias,
                PublicKey:    req.SenderPublicKey,
                OobiURL:      req.SenderOOBI,
                Verified:     kelPresent,
                DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
                Status:       "pending_inbound",
                Role:         "agent",
                JCard:        contactJCard,
                Photo:        req.SenderPhoto,
        }

        if err := s.DataStore.SaveContact(contact); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] EXCHANGE: Introduction received from %s (AID: %s) — saved as pending_inbound, kel_verified=%v", alias, req.SenderAID, kelPresent)

        introPayload := map[string]interface{}{
                "sender_aid":   req.SenderAID,
                "sender_alias": alias,
                "sender_oobi":  req.SenderOOBI,
        }
        if req.SenderJCard != nil {
                introPayload["sender_jcard"] = req.SenderJCard
        }
        if req.SenderPhoto != "" {
                introPayload["sender_photo"] = req.SenderPhoto
        }
        s.EventHub.Broadcast(AgentEvent{
                Type:    "introduction_received",
                Payload: introPayload,
        })

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"status": "received", "aid": req.SenderAID})
}

func (s *CoreServer) handleAcceptContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := s.DataStore.GetContact(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact", err.Error())
                return
        }
        if contact == nil {
                writeError(w, http.StatusNotFound, "Contact not found", fmt.Sprintf("No contact found for AID: %s", aid))
                return
        }

        if contact.Status != "pending_inbound" {
                writeError(w, http.StatusBadRequest, "Invalid contact status", fmt.Sprintf("Contact status is '%s', expected 'pending_inbound'", contact.Status))
                return
        }

        log.Printf("[identity-agent-core] CONTACT-ACCEPT: Upgrading contact %s (%s) from pending_inbound to mutual", contact.Alias, aid)

        contact.Status = "mutual"
        if err := s.DataStore.SaveContact(*contact); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to update contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Accepted %s (AID: %s) — status=mutual", contact.Alias, aid)

        go func() {
                ourIdentity, err := s.DataStore.GetIdentity()
                if err != nil || ourIdentity == nil {
                        log.Printf("[identity-agent-core] EXCHANGE: Cannot send acceptance — no identity available")
                        return
                }

                remoteBase := oobiBase(contact.OobiURL)
                exchangeURL := remoteBase + "/api/exchange"

                log.Printf("[identity-agent-core] EXCHANGE: Sending acceptance confirmation to %s", exchangeURL)

                payload := map[string]string{
                        "type":       "acceptance",
                        "sender_aid": ourIdentity.AID,
                }
                body, _ := json.Marshal(payload)

                exnClient := &http.Client{Timeout: 15 * time.Second}
                exnResp, err := exnClient.Post(exchangeURL, "application/json", bytes.NewReader(body))
                if err != nil {
                        log.Printf("[identity-agent-core] EXCHANGE: Failed to send acceptance to %s: %v", exchangeURL, err)
                        return
                }
                defer exnResp.Body.Close()
                log.Printf("[identity-agent-core] EXCHANGE: Acceptance sent to %s (status: %d)", exchangeURL, exnResp.StatusCode)
        }()

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "aid": aid})
}

func (s *CoreServer) handleRejectContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := s.DataStore.GetContact(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact", err.Error())
                return
        }
        if contact == nil {
                writeError(w, http.StatusNotFound, "Contact not found", fmt.Sprintf("No contact found for AID: %s", aid))
                return
        }

        contact.Status = "rejected"
        if err := s.DataStore.SaveContact(*contact); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to update contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Rejected %s (AID: %s)", contact.Alias, aid)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"status": "rejected", "aid": aid})
}

func (s *CoreServer) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
        contacts, err := s.DataStore.GetContactsByStatus("pending_inbound")
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read alerts", err.Error())
                return
        }
        if contacts == nil {
                contacts = []store.ContactRecord{}
        }

        pendingReqs, err := s.DataStore.GetPendingRequests()
        if err != nil {
                pendingReqs = []store.PendingRequest{}
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "alerts":           contacts,
                "count":            len(contacts),
                "pending_requests": pendingReqs,
                "pending_count":    len(pendingReqs),
        })
}

func (s *CoreServer) loadTunnelConfig() tunnel.Config {
        var aid string
        if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
                aid = identity.AID
        }

        saved, err := s.DataStore.GetSettings()
        if err == nil && saved != nil && saved.TunnelProvider != "" {
                return tunnel.Config{
                        Provider:              tunnel.ProviderType(saved.TunnelProvider),
                        NgrokAuthToken:        saved.NgrokAuthToken,
                        CloudflareTunnelToken: saved.CloudflareTunnelToken,
                        TunnelDomain:          saved.TunnelDomain,
                        TunnelExtension:       saved.TunnelExtension,
                        AID:                   aid,
                }
        }
        cfg := tunnel.DefaultConfig()
        cfg.AID = aid
        return cfg
}

func (s *CoreServer) handleGetTunnelSettings(w http.ResponseWriter, r *http.Request) {
        cfg := s.TunnelManager.GetConfig()
        status := s.TunnelManager.GetStatus()

        resp := map[string]interface{}{
                "provider": cfg.Provider,
                "status":   status,
                "has_ngrok_token":      cfg.NgrokAuthToken != "",
                "has_cloudflare_token": cfg.CloudflareTunnelToken != "",
                "tunnel_domain":        cfg.TunnelDomain,
                "tunnel_extension":     cfg.TunnelExtension,
                "cloudflared_available": func() bool {
                        _, err := tunnel.LookupCloudflared()
                        return err == nil
                }(),
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handlePutTunnelSettings(w http.ResponseWriter, r *http.Request) {
        var req struct {
                Provider              string `json:"provider"`
                NgrokAuthToken        string `json:"ngrok_auth_token,omitempty"`
                CloudflareTunnelToken string `json:"cloudflare_tunnel_token,omitempty"`
                TunnelDomain          string `json:"tunnel_domain,omitempty"`
                TunnelExtension       string `json:"tunnel_extension,omitempty"`
        }

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
                return
        }

        provider := tunnel.ProviderType(req.Provider)
        switch provider {
        case tunnel.ProviderCloudflare, tunnel.ProviderNgrok, tunnel.ProviderGrapeID, tunnel.ProviderNone:
        default:
                writeError(w, http.StatusBadRequest, "Invalid provider", fmt.Sprintf("Provider must be one of: cloudflare, ngrok, grapeid, none. Got: %s", req.Provider))
                return
        }

        settings := store.SettingsData{
                TunnelProvider:        req.Provider,
                NgrokAuthToken:        req.NgrokAuthToken,
                CloudflareTunnelToken: req.CloudflareTunnelToken,
                TunnelDomain:          req.TunnelDomain,
                TunnelExtension:       req.TunnelExtension,
        }

        if err := s.DataStore.SaveSettings(settings); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save settings", err.Error())
                return
        }

        log.Printf("[identity-agent-core] Tunnel settings updated: provider=%s — restarting tunnel", req.Provider)

        if s.TunnelManager == nil {
                s.EndpointService.Refresh()
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "status":         "saved",
                        "provider":       req.Provider,
                        "tunnel":         map[string]interface{}{"active": false, "error": "tunnel manager not initialized"},
                        "endpoint_url":   s.EndpointService.CurrentURL(),
                        "endpoint_source": s.EndpointService.Source(),
                })
                return
        }

        cfg := s.loadTunnelConfig()
        if err := s.TunnelManager.Restart(s.AppCtx, cfg); err != nil {
                log.Printf("[identity-agent-core] Tunnel restart after settings change failed: %v", err)
                s.EndpointService.Refresh()
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "status":         "saved",
                        "provider":       req.Provider,
                        "tunnel":         map[string]interface{}{"active": false, "error": err.Error()},
                        "endpoint_url":   s.EndpointService.CurrentURL(),
                        "endpoint_source": s.EndpointService.Source(),
                })
                return
        }

        s.EndpointService.Refresh()
        status := s.TunnelManager.GetStatus()
        log.Printf("[identity-agent-core] Tunnel restarted after settings change: active=%v url=%s", status.Active, status.URL)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "status":       "saved",
                "provider":     req.Provider,
                "tunnel":       status,
                "endpoint_url": s.EndpointService.CurrentURL(),
                "endpoint_source": s.EndpointService.Source(),
        })
}

func (s *CoreServer) handleTunnelStatus(w http.ResponseWriter, r *http.Request) {
        status := s.TunnelManager.GetStatus()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(status)
}

func (s *CoreServer) handleCheckTunnelName(w http.ResponseWriter, r *http.Request) {
        domain := r.URL.Query().Get("domain")
        name := r.URL.Query().Get("name")

        if name == "" {
                writeError(w, http.StatusBadRequest, "Missing required parameter: name", "")
                return
        }
        if domain == "" {
                domain = "grapeid.org"
        }

        scheme := "https"
        if strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
                scheme = "http"
        }

        hubURL := fmt.Sprintf("%s://%s/check-name?name=%s", scheme, domain, name)
        client := s.newProbeHTTPClient(8 * time.Second)
        resp, err := client.Get(hubURL)
        if err != nil {
                errDetail := err.Error()
                log.Printf("[identity-agent-core] check-name proxy failed: %v", err)
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK)
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "available":  nil,
                        "hub_error":  true,
                        "message":    fmt.Sprintf("Provider not responsive: %s", errDetail),
                })
                return
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(resp.Body)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read hub response", err.Error())
                return
        }

        // Normalize provider-side server errors — do not let 5xx bubble up as
        // "name taken". Return 200 with hub_error so the client can show the
        // correct message ("provider not responsive") instead of a false negative.
        if resp.StatusCode >= 500 {
                log.Printf("[identity-agent-core] check-name: provider returned HTTP %d", resp.StatusCode)
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK)
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "available": nil,
                        "hub_error": true,
                        "message":   fmt.Sprintf("Provider server returned HTTP %d", resp.StatusCode),
                })
                return
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(resp.StatusCode)
        w.Write(body)
}

func (s *CoreServer) handleGrapeIdHealth(w http.ResponseWriter, r *http.Request) {
        domain := r.URL.Query().Get("domain")
        if domain == "" {
                domain = "grapeid.org"
        }

        scheme := "https"
        if strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
                scheme = "http"
        }

        probeURL := fmt.Sprintf("%s://%s/health", scheme, domain)
        client := s.newProbeHTTPClient(3 * time.Second)
        resp, err := client.Get(probeURL)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)

        if err != nil {
                errDetail := err.Error()
                log.Printf("[identity-agent-core] grapeid health probe failed: %v", err)
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "reachable": false,
                        "reason":    fmt.Sprintf("Provider not responsive: %s", errDetail),
                })
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode >= 500 {
                json.NewEncoder(w).Encode(map[string]interface{}{
                        "reachable": false,
                        "reason":    fmt.Sprintf("Provider server returned HTTP %d", resp.StatusCode),
                })
                return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
                "reachable": true,
        })
}

func (s *CoreServer) handleTunnelRestart(w http.ResponseWriter, r *http.Request) {
        cfg := s.loadTunnelConfig()
        log.Printf("[identity-agent-core] Restarting tunnel with provider: %s", cfg.Provider)

        if err := s.TunnelManager.Restart(s.AppCtx, cfg); err != nil {
                log.Printf("[identity-agent-core] Tunnel restart failed: %v", err)
                s.EndpointService.Refresh()
                writeError(w, http.StatusInternalServerError, "Tunnel restart failed", err.Error())
                return
        }

        s.EndpointService.Refresh()
        status := s.TunnelManager.GetStatus()
        log.Printf("[identity-agent-core] Tunnel restarted: active=%v url=%s endpoint=%s", status.Active, status.URL, s.EndpointService.CurrentURL())

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "provider":        status.Provider,
                "active":          status.Active,
                "url":             status.URL,
                "error":           status.Error,
                "endpoint_url":    s.EndpointService.CurrentURL(),
                "endpoint_source": s.EndpointService.Source(),
        })
}

func (s *CoreServer) handleGetProfile(w http.ResponseWriter, r *http.Request) {
        profile, err := s.DataStore.GetProfile()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read profile", err.Error())
                return
        }
        if profile == nil {
                profile = &store.ProfileData{}
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(profile)
}

func (s *CoreServer) handlePutProfile(w http.ResponseWriter, r *http.Request) {
        var profile store.ProfileData
        if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
                writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
                return
        }

        if err := s.DataStore.SaveProfile(profile); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save profile", err.Error())
                return
        }

        log.Printf("[identity-agent-core] Profile updated: fn=%q", profile.FullName)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{"status": "saved", "profile": profile})
}

func (s *CoreServer) handleDeletePendingRequest(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "")
                return
        }

        if err := s.DataStore.DeletePendingRequest(aid); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to delete pending request", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{"deleted": true, "aid": aid})
}

func (s *CoreServer) handleReset(w http.ResponseWriter, r *http.Request) {
        if err := s.DataStore.ResetAll(); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to reset", err.Error())
                return
        }

        log.Println("[identity-agent-core] All data reset — identity, contacts, settings, KEL cleared")

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{"reset": true})
}

func (s *CoreServer) newProbeHTTPClient(timeout time.Duration) *http.Client {
        return &http.Client{
                Timeout: timeout,
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                },
        }
}

func (s *CoreServer) handleReleaseTunnelName(w http.ResponseWriter, r *http.Request) {
        if s.TunnelManager == nil {
                writeError(w, http.StatusInternalServerError, "Tunnel manager not initialized", "")
                return
        }

        cfg := s.TunnelManager.GetConfig()
        if cfg.Provider != tunnel.ProviderGrapeID {
                writeError(w, http.StatusBadRequest, "Release is only supported for Grape ID provider", "")
                return
        }
        if cfg.TunnelExtension == "" {
                writeError(w, http.StatusBadRequest, "No name is currently claimed", "")
                return
        }

        releasedName := cfg.TunnelExtension
        log.Printf("[identity-agent-core] Releasing tunnel name '%s' on hub", releasedName)

        s.TunnelManager.Stop()

        settings, err := s.DataStore.GetSettings()
        if err == nil && settings != nil {
                settings.TunnelExtension = ""
                s.DataStore.SaveSettings(*settings)
        }

        s.EndpointService.Refresh()
        log.Printf("[identity-agent-core] Tunnel name '%s' released and cleared from settings", releasedName)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "released":       true,
                "name":           releasedName,
                "endpoint_url":   s.EndpointService.CurrentURL(),
                "endpoint_source": s.EndpointService.Source(),
        })
}

// oobiBase extracts the scheme+host+port base URL from an OOBI URL so the
// caller can append /api/exchange. OOBI URLs follow the /public/oobi/{aid} pattern.
func oobiBase(oobiURL string) string {
        if idx := strings.Index(oobiURL, "/public/oobi/"); idx != -1 {
                return oobiURL[:idx]
        }
        return oobiURL
}

func writeError(w http.ResponseWriter, status int, errMsg string, details string) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Details: details})
}
