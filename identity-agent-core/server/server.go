package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
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

	"identity-agent-core/asset"
	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/endpoint"
	"identity-agent-core/iacrypto"
	"identity-agent-core/linkverifier"
	"identity-agent-core/login"
	"identity-agent-core/oidc"
	"identity-agent-core/recovery"
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
	"identity-agent-core/tunnel"
	"identity-agent-core/update"
	"identity-agent-core/watcher"
	"identity-agent-core/witness"

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
	loginHandler    *login.Handler
	assetHandler    *asset.Handler

	// Overlay-registered extra routes, mounted under /api by buildRouter. See
	// MountExtraRoutes / extension.go — inert unless an overlay registers.
	extraRoutes []func(chi.Router)

	// G-052: asset login challenge store (per-session bundles for /i/{token})
	challengeMu     sync.Mutex
	challenges      map[string]login.ChallengeBundle  // keyed by session_token
	challengeStatus map[string]map[string]interface{} // keyed by session_token; tracks pending/complete

	oidcAdapter       *oidc.Adapter
	WatcherService    *watcher.Service
	WitnessService    *witness.Service
	LinkVerifier      *linkverifier.SDK
	BackupService     *backup.Service
	RecoveryService   *recovery.Service
	UpdateService     *update.Service
	AttestationRunner *secureenclave.Runner
	TrustGate         *secureenclave.TrustGate
	CallerResolver    CallerResolver // resolves endpoint caller identity/scopes; nil = loopback default (delegated-identity injects the real one)
	mu                sync.Mutex
	running           bool
}

type Config struct {
	DataDir          string
	Port             int
	EnableKeriDriver bool
	FlutterWebDir    string
}

func DefaultConfig() Config {
	dataDir := os.Getenv("AGENT_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(".", "data")
	}

	port := 5050
	if p := os.Getenv("PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	webDir := os.Getenv("FLUTTER_WEB_DIR")
	if webDir == "" {
		webDir = filepath.Join("..", "identity_agent_ui", "build", "web")
	}

	enableKeri := true
	if v := os.Getenv("ENABLE_KERI_DRIVER"); v == "false" || v == "0" {
		enableKeri = false
	}

	return Config{
		DataDir:          dataDir,
		Port:             port,
		EnableKeriDriver: enableKeri,
		FlutterWebDir:    webDir,
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

	ws := watcher.NewService(watcher.NewSQLiteStore(dataStore.DB()))
	ws.OnEvent = func(eventType string, payload map[string]interface{}) {
		s.EventHub.Broadcast(AgentEvent{Type: eventType, Payload: payload})
	}
	s.WatcherService = ws
	watcher.StartPruneLoop(ws, 24*time.Hour)

	backendType := witness.BackendDesktop
	if os.Getenv("IA_BACKEND_TYPE") != "" {
		backendType = os.Getenv("IA_BACKEND_TYPE")
	}
	wsvc := witness.NewService(witness.NewSQLiteStore(dataStore.DB()), dataStore, nil, backendType)
	wsvc.OurAID = func() string {
		id, _ := dataStore.GetIdentity()
		if id != nil {
			return id.AID
		}
		return ""
	}
	wsvc.OurOOBI = func() string {
		id, _ := dataStore.GetIdentity()
		if id == nil {
			return ""
		}
		return fmt.Sprintf("http://127.0.0.1:%d/public/oobi/%s", cfg.Port, id.AID)
	}
	wsvc.OnEvent = func(eventType string, payload map[string]interface{}) {
		s.EventHub.Broadcast(AgentEvent{Type: eventType, Payload: payload})
	}
	s.WitnessService = wsvc
	go witness.StartHeartbeatLoop(wsvc, ctx.Done())

	if cfg.EnableKeriDriver {
		s.KeriDriver = drivers.NewKeriDriver()
		if err := s.KeriDriver.Start(); err != nil {
			cancel()
			dataStore.Close()
			return nil, fmt.Errorf("failed to start KERI driver: %w", err)
		}
		// If an identity already exists in the DB, seed the driver's in-memory
		// state so IssueCredential and Interact work without a fresh inception.
		s.reloadIdentityIntoDriver()
	}

	if s.WitnessService != nil {
		s.WitnessService.Driver = s.KeriDriver
	}

	s.LinkVerifier = linkverifier.New(s.KeriDriver, linkverifier.Config{
		ContactLookup: func(aid string) (bool, string) {
			c, err := dataStore.GetContact(aid)
			if err != nil || c == nil {
				return false, ""
			}
			return c.Status == "accepted", c.Alias
		},
	})

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

	if err := s.initLoginHandler(); err != nil {
		log.Printf("[identity-agent-core] login handler init failed (non-fatal): %v", err)
	}
	if err := s.initAssetHandler(); err != nil {
		log.Printf("[identity-agent-core] asset handler init failed (non-fatal): %v", err)
	}
	if err := s.initOIDCHandler(); err != nil {
		log.Printf("[identity-agent-core] OIDC adapter init failed (non-fatal): %v", err)
	}

	updCfg := update.DefaultConfig(cfg.DataDir)
	updCfg.HealthCheckURL = fmt.Sprintf("http://127.0.0.1:%d/api/health", cfg.Port)
	if updSvc, err := update.NewService(updCfg); err != nil {
		log.Printf("[identity-agent-core] update service init failed (non-fatal): %v", err)
	} else {
		s.UpdateService = updSvc
	}

	s.AttestationRunner = secureenclave.NewRunner(secureenclave.RunnerConfig{
		DataDir:          cfg.DataDir,
		EnableKeriDriver: cfg.EnableKeriDriver,
	})
	if s.UpdateService != nil {
		s.TrustGate = secureenclave.NewTrustGate(s.AttestationRunner, s.UpdateService.Attestation())
	} else {
		s.TrustGate = secureenclave.NewTrustGate(s.AttestationRunner, nil)
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

	// Try the configured port first, then fallback to 5051–5059
	requestedPort := s.Port
	var bindErr error
	for attempt := 0; attempt < 10; attempt++ {
		tryPort := requestedPort + attempt
		addr := fmt.Sprintf("0.0.0.0:%d", tryPort)
		s.listener, bindErr = net.Listen("tcp4", addr)
		if bindErr == nil {
			if tryPort != requestedPort {
				log.Printf("[identity-agent-core] Port %d in use — using fallback port %d", requestedPort, tryPort)
			}
			s.Port = tryPort
			break
		}
		log.Printf("[identity-agent-core] Port %d unavailable: %v", tryPort, bindErr)
	}
	if s.listener == nil {
		return fmt.Errorf("failed to bind on ports %d–%d: %w", requestedPort, requestedPort+9, bindErr)
	}

	// Update endpoint service with actual port (may differ from configured)
	s.EndpointService.SetPort(s.Port)

	// Write actual port to .port file so Flutter UI can discover it
	portFilePath := filepath.Join(s.DataDir, ".port")
	if err := os.MkdirAll(s.DataDir, 0755); err != nil {
		log.Printf("[identity-agent-core] Warning: could not create data dir for .port file: %v", err)
	} else if err := os.WriteFile(portFilePath, []byte(fmt.Sprintf("%d", s.Port)), 0644); err != nil {
		log.Printf("[identity-agent-core] Warning: could not write .port file: %v", err)
	}

	tunnelCfg := s.loadTunnelConfig()
	s.TunnelManager = tunnel.NewManager(tunnelCfg, s.Port)
	s.EndpointService.SetTunnelManager(s.TunnelManager)
	s.EndpointService.Refresh()

	if s.UpdateService != nil {
		healthURL := fmt.Sprintf("http://127.0.0.1:%d/api/health", s.Port)
		s.UpdateService.SetHealthCheck(func() error {
			resp, err := http.Get(healthURL)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("health status %d", resp.StatusCode)
			}
			return nil
		})
		s.UpdateService.Start(s.AppCtx)
	}
	if s.AttestationRunner != nil {
		s.AttestationRunner.Start(s.AppCtx)
	}
	if s.loginHandler != nil && s.TrustGate != nil {
		s.loginHandler.TrustGate = s.TrustGate
	}

	s.running = true

	if cfg, err := s.backupService().LoadConfig(); err == nil && cfg.Enabled && cfg.ScheduleDaily {
		s.backupService().Scheduler.StartDaily()
	}

	addr := fmt.Sprintf("0.0.0.0:%d", s.Port)
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

	// Clean up .port file
	portFilePath := filepath.Join(s.DataDir, ".port")
	os.Remove(portFilePath)

	if s.UpdateService != nil {
		s.UpdateService.Stop()
	}

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

	// G-052: public endpoint for IA to fetch signed login challenge bundle (QR pointer)
	r.Get("/i/{token}", s.handleChallengeBundleServe)

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/info", s.handleInfo)
		r.Get("/identity", s.handleIdentity)
		r.Get("/security/enclave", s.handleSecurityEnclave)

		r.Post("/inception", s.handleInception)
		r.Post("/hybrid-inception", s.handleHybridInception)
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
		r.Get("/credentials/{said}", s.handleGetCredential)
		r.Post("/credentials/receive", s.handleReceiveCredential)
		r.Post("/credentials/deliver", s.handleDeliverCredential)
		r.Post("/credentials/{said}/accept", s.handleAcceptCredential)
		r.Post("/credentials/{said}/reject", s.handleRejectCredential)
		r.Delete("/credentials/{said}", s.handleDeleteCredential)
		r.Post("/credential/present", s.handlePresentCredential)
		r.Get("/presentations", s.handleGetPresentations)
		r.Post("/credential/verify", s.handleVerifyCredential)
		r.Post("/credentials/verify", s.handleVerifyCredentialChain)
		r.Get("/credential-schemas", s.handleGetCredentialSchemas)
		r.Post("/credential-schemas/fetch", s.handleFetchCredentialSchema)
		r.Get("/schemas", s.handleListBuiltinSchemas)
		r.Get("/schemas/{said}", s.handleGetBuiltinSchema)

		r.Post("/receipt/submit", s.handleSubmitReceipt)
		r.Get("/kerl", s.handleGetKERL)

		r.Get("/oobi", s.handleOobiGenerate)

		r.Get("/contacts", s.handleGetContacts)
		r.Post("/contacts/resolve", s.handleResolveOobiContact)
		r.Post("/contacts", s.handleAddContact)
		r.Get("/contacts/{aid}", s.handleGetContact)
		r.Get("/contacts/{aid}/kel", s.handleGetContactKEL)
		r.Delete("/contacts/{aid}", s.handleDeleteContact)
		r.Put("/contacts/{aid}", s.handleUpdateContact)
		r.Post("/contacts/{aid}/accept", s.handleAcceptContact)
		r.Post("/contacts/{aid}/reject", s.handleRejectContact)
		r.Get("/alerts", s.handleGetAlerts)
		r.Post("/exchange", s.handleExchange)

		r.Get("/tasks", s.handleGetTasks)

		// Inter-agent witness protocol (server-to-server, fully automated)
		r.Post("/witness/request", s.handleWitnessRequest)
		r.Post("/witness/accept", s.handleWitnessAccept)

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
		r.Get("/actions", s.handleGetActions)
		r.Get("/share-actions", s.handleGetShareActions)
		r.Post("/share-actions", s.handleCreateShareAction)
		r.Put("/share-actions/{id}", s.handleUpdateShareAction)
		r.Delete("/share-actions/{id}", s.handleDeleteShareAction)

		r.Post("/store/identity", s.handleStoreIdentity)
		r.Post("/store/event", s.handleStoreEvent)
		r.Post("/store/receipt", s.handleStoreReceipt)
		r.Get("/store/receipts", s.handleGetStoreReceipts)
		r.Post("/store/credential", s.handleStoreCredential)

		r.Delete("/pending-requests/{aid}", s.handleDeletePendingRequest)
		r.Post("/reset", s.handleReset)

		s.sandboxRoutes(r)
		s.guardianshipRoutes(r)
		s.serviceProviderRoutes(r)
		s.aiMemoryRoutes(r)
		s.mountBackupRoutes(r)
		s.mountRecoveryRoutes(r)
		r.Get("/ws/events", s.handleWebSocketEvents)

		s.mountLoginRoutes(r)
		s.mountAssetRoutes(r)
		s.mountVerificationRoutes(r)
		s.mountWitnessRoutes(r)
		s.mountUpdateRoutes(r)

		// Overlay-registered routes (MountExtraRoutes) mount last, under /api.
		for _, fn := range s.extraRoutes {
			fn(r)
		}
	})

	s.traceRoutes(r)
	s.llmRoutes(r)

	// Display reverse proxy: intercepts container API calls to serve from ai-memory.db
	r.HandleFunc("/apps/{app_id}/*", s.handleAppDisplayProxy)

	// /public/oobi/{aid} — public namespace: KERI OOBI endpoint shared with external agents.
	r.Get("/public/oobi/{aid}", s.handleOobiServe)
	s.mountDidWebsPublicRoutes(r)
	s.mountOIDCRoutes(r)
	s.mountWatcherPublicRoutes(r)

	// /public/credential/{said} — public credential delivery endpoint for sharing issued credentials.
	r.Get("/public/credential/{said}", s.handlePublicCredentialServe)

	// Serve did.json for owned/registered AIDs at /public/{aid}/did.json (before the SPA), so
	// login site keys and minted pairwise signer keys resolve.
	s.mountPublicDidWebsRoutes(r)
	// Dumb-router scan gate: forward a scanned Ask pointer here; Go decodes + dispatches by t.
	s.mountScanRoutes(r)
	// Mint IA-originated Asks (e.g. an add-contact "add me" QR) hosted at /i/{token}.
	s.mountAskCreateRoute(r)
	// login-web SignInButton-compatible endpoints (drop-in widget → an Identity Agent, no per-site backend).
	s.mountLoginWidgetRoutes(r)

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
	RawBytesB64 string `json:"raw_bytes_b64"`
	PublicKey   string `json:"public_key"`
	Created     string `json:"created"`
}

type HybridInceptionRequest struct {
	// Synthetic: use fixed seed=0 harness material (C3 golden-vector prep).
	Synthetic bool   `json:"synthetic"`
	Name      string `json:"name,omitempty"`
}

type HybridInceptionResponse struct {
	AID            string                 `json:"aid"`
	SAID           string                 `json:"said"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	RawBytesB64    string                 `json:"raw_bytes_b64"`
	CipherSuite    string                 `json:"cipher_suite"`
	PublicKey      string                 `json:"public_key"`
	NextKeyDigest  string                 `json:"next_key_digest"`
	Created        string                 `json:"created,omitempty"`
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
		Description: "User-controlled identity runtime powered by KERI",
		Version:     "0.1.0",
		Phase:       phase,
		Capabilities: []string{
			"health_check",
			"inception",
			"kel_storage",
			"contacts",
			"oobi",
			"tunneling",
			"sandbox_plugins",
			"pairwise_aids",
			// Transaction hash receipts (pointer/stub) — primitives (secureenclave + blake3) reused when built
			// Governance policy config (pointer/stub) — LLM egress structurally denied until the governance gateway strip-gate
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

func (s *CoreServer) handleHybridInception(w http.ResponseWriter, r *http.Request) {
	var req HybridInceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if !req.Synthetic {
		writeError(w, http.StatusNotImplemented,
			"Non-synthetic hybrid inception not yet wired",
			"Use synthetic=true for C1 harness vectors; production keygen routes through keripy driver or Rust bridge")
		return
	}

	result, err := iacrypto.BuildHybridInception(iacrypto.SyntheticHybridKeyMaterial(0))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create hybrid inception event", err.Error())
		return
	}

	resp := HybridInceptionResponse{
		AID:            result.AID,
		SAID:           result.SAID,
		InceptionEvent: result.InceptionEvent,
		RawBytesB64:    result.RawBytesB64,
		CipherSuite:    result.CipherSuite,
		PublicKey:      result.PublicKey,
		NextKeyDigest:  result.NextKeyDigest,
		Created:        time.Now().UTC().Format(time.RFC3339),
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
	s.broadcastWitnessEvent(req.AID, req.EventJSON)

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
	s.broadcastWitnessEvent(result.AID, string(eventJSON))
	s.notifyBackupEvent(backup.EventKeyRotation)

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
		// Edges: optional ACDC edge block for credential chaining.
		// Structure: {"<label>": {"n": "<parent-SAID>", "s": "<schema-SAID>"}}
		Edges map[string]interface{} `json:"edges,omitempty"`
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

	// Use our per-contact relationship (pairwise) AID as the issuer for this issuance, not root.
	// Lookup contact by the presented holder AID (their side of the relationship).
	issuerAID := identity.AID
	if req.HolderAid != "" {
		if c, cerr := s.DataStore.GetContact(req.HolderAid); cerr == nil && c != nil && c.RelationshipAID != "" {
			issuerAID = c.RelationshipAID
		}
	}

	// Chain-of-trust: if the holder is a known dependent with an active guardianship
	// credential, auto-build a proper ACDC edges block referencing that credential.
	// The caller may also supply edges explicitly; explicit edges take precedence.
	if req.Edges == nil && req.HolderAid != "" {
		if gr, err2 := s.DataStore.GetGuardianshipByDependentAID(req.HolderAid); err2 == nil && gr != nil && gr.CredentialSAID != "" {
			req.Edges = map[string]interface{}{
				"guardianship": map[string]interface{}{
					"n": gr.CredentialSAID,
					"s": "EGuardianship__placeholder__v1",
				},
			}
			log.Printf("[identity-agent-core] CREDENTIAL: Auto-built guardianship edges block (SAID %s) for dependent %s", gr.CredentialSAID, req.HolderAid)
		}
	}

	result, err := s.KeriDriver.IssueCredential(issuerAID, req.Claims, req.SchemaSaid, req.HolderAid, req.Edges)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Credential issuance failed", err.Error())
		return
	}

	// Populate credential type from builtin schema catalog
	credType := ""
	if schema := schemas.Get(req.SchemaSaid); schema != nil {
		credType = schema.Name
	}

	// Populate issuer name from profile
	issuerName := ""
	if profile, _ := s.DataStore.GetProfile(); profile != nil {
		issuerName = profile.FullName
	}

	// Persist the credential record
	record := store.CredentialRecord{
		SAID:           result.AcdcSaid,
		IssuerAID:      issuerAID,
		HolderAID:      req.HolderAid,
		SchemaSAID:     req.SchemaSaid,
		AcdcJson:       result.AcdcJsonB64,
		IxnSAID:        result.IxnSaid,
		CesrSignature:  req.CesrSignature,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
		Status:         "issued",
		Format:         "acdc",
		CredentialType: credType,
		IssuerName:     issuerName,
	}
	if err := s.DataStore.SaveCredential(record); err != nil {
		log.Printf("[identity-agent-core] CREDENTIAL: Failed to persist credential %s: %v", result.AcdcSaid, err)
	} else {
		s.notifyBackupEvent(backup.EventCredential)
	}

	// Attempt automatic push delivery to the holder if they are a known contact
	if contact, err := s.DataStore.GetContact(req.HolderAid); err == nil && contact != nil && contact.OobiURL != "" {
		go s.deliverCredentialToContact(contact, record)
	}

	// Persist the IXN event in the KEL (use the relationship AID when issuing via pairwise context)
	ixnEventJSON, _ := json.Marshal(result.IxnEvent)
	kelRecord := store.EventRecord{
		AID:            issuerAID,
		SequenceNumber: result.SequenceNumber,
		EventType:      "ixn",
		EventJSON:      string(ixnEventJSON),
		PublicKey:      identity.PublicKey, // may need rel pub if separate, but reuse root pub state for now
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
		"acdc_said":         result.AcdcSaid,
		"acdc_json_b64":     result.AcdcJsonB64,
		"ixn_raw_bytes_b64": result.IxnRawBytesB64,
		"ixn_said":          result.IxnSaid,
		"sequence_number":   result.SequenceNumber,
		"status":            "issued",
	})
}

func (s *CoreServer) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")     // "holder" | "issuer" | ""
	status := r.URL.Query().Get("status") // "valid" | "expired" | ""

	creds, err := s.DataStore.GetCredentialsFiltered(role, status)
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

func (s *CoreServer) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	cred, err := s.DataStore.GetCredential(said)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read credential", err.Error())
		return
	}
	if cred == nil {
		writeError(w, http.StatusNotFound, "Credential not found", said)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cred)
}

// detectCredentialFormat implements server-side format auto-detection so the
// caller cannot lie about "format". Mirrors the client heuristic but is authoritative here.
func detectCredentialFormat(acdcJSON, rawJSON string) string {
	for _, j := range []string{acdcJSON, rawJSON} {
		if j == "" {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal([]byte(j), &m) == nil {
			if v, ok := m["v"].(string); ok && strings.HasPrefix(v, "ACDC") {
				return "acdc"
			}
			if _, ok := m["@context"]; ok {
				return "w3c_vc"
			}
		}
	}
	return "acdc"
}

func (s *CoreServer) handleReceiveCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AcdcJson string `json:"acdc_json"`
		RawJson  string `json:"raw_json"`
		Format   string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	// Server-side format detection (do not trust caller-supplied format).
	req.Format = detectCredentialFormat(req.AcdcJson, req.RawJson)

	// Determine SAID: for ACDC parse from JSON, for others use raw_json hash placeholder
	said := ""
	sourceJson := req.AcdcJson
	if req.Format != "acdc" && req.RawJson != "" {
		sourceJson = req.AcdcJson // ACDC wrapper (caller must provide)
	}

	// Extract SAID from ACDC JSON "d" field
	var acdcMap map[string]interface{}
	if err := json.Unmarshal([]byte(sourceJson), &acdcMap); err == nil {
		if d, ok := acdcMap["d"].(string); ok && d != "" {
			said = d
		}
	}
	if said == "" {
		writeError(w, http.StatusBadRequest, "Cannot extract SAID from credential", "Ensure the ACDC JSON contains a 'd' field")
		return
	}

	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusBadRequest, "No identity found", "Create an identity before receiving credentials")
		return
	}

	issuerAID := ""
	if v, ok := acdcMap["i"].(string); ok {
		issuerAID = v
	}
	// Use pairwise subject if present in the ACDC (A1: credentials issued to P-AID not Root)
	holderAID := identity.AID
	if subj, ok := acdcMap["a"].(string); ok && subj != "" {
		holderAID = subj
	} else if h, ok := acdcMap["holder"].(string); ok && h != "" {
		holderAID = h
	}

	record := store.CredentialRecord{
		SAID:      said,
		HolderAID: holderAID,
		IssuerAID: issuerAID,
		AcdcJson:  req.AcdcJson,
		RawJson:   req.RawJson,
		Format:    req.Format,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		Status:    "received",
	}
	if err := s.DataStore.SaveCredential(record); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save credential", err.Error())
		return
	}
	s.notifyBackupEvent(backup.EventCredential)

	log.Printf("[identity-agent-core] CREDENTIAL: Received %s (format=%s) for holder %s", said, req.Format, identity.AID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"said": said, "status": "received"})
}

func (s *CoreServer) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	cred, err := s.DataStore.GetCredential(said)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read credential", err.Error())
		return
	}
	if cred == nil {
		writeError(w, http.StatusNotFound, "Credential not found", said)
		return
	}
	if err := s.DataStore.DeleteCredential(said); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete credential", err.Error())
		return
	}
	log.Printf("[identity-agent-core] CREDENTIAL: Deleted %s", said)
	w.WriteHeader(http.StatusNoContent)
}

// handleDeliverCredential receives a credential pushed by another Identity Agent.
// The credential is saved with status "pending_inbound" and a WebSocket event is broadcast.
func (s *CoreServer) handleDeliverCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Said           string `json:"said"`
		AcdcJson       string `json:"acdc_json"`
		Format         string `json:"format"`
		CredentialType string `json:"credential_type"`
		IssuerAID      string `json:"issuer_aid"`
		IssuerName     string `json:"issuer_name"`
		SchemaSAID     string `json:"schema_said"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.Said == "" || req.AcdcJson == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "said and acdc_json are required")
		return
	}

	holderAID := ""
	if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
		holderAID = identity.AID
	}
	// Server-side format detection (do not trust caller-supplied format).
	req.Format = detectCredentialFormat(req.AcdcJson, "")

	record := store.CredentialRecord{
		SAID:           req.Said,
		IssuerAID:      req.IssuerAID,
		HolderAID:      holderAID,
		SchemaSAID:     req.SchemaSAID,
		AcdcJson:       req.AcdcJson,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
		Status:         "pending_inbound",
		Format:         req.Format,
		CredentialType: req.CredentialType,
		IssuerName:     req.IssuerName,
	}
	if err := s.DataStore.SaveCredential(record); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save credential", err.Error())
		return
	}
	s.notifyBackupEvent(backup.EventCredential)

	s.EventHub.Broadcast(AgentEvent{
		Type: "credential_received",
		Payload: map[string]interface{}{
			"said":            req.Said,
			"credential_type": req.CredentialType,
			"issuer_aid":      req.IssuerAID,
			"issuer_name":     req.IssuerName,
		},
	})

	log.Printf("[identity-agent-core] CREDENTIAL: Received pending credential %s from %s", req.Said, req.IssuerAID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"said":   req.Said,
		"status": "pending_inbound",
	})
}

// handleAcceptCredential moves a pending_inbound credential to accepted (status=received).
func (s *CoreServer) handleAcceptCredential(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	if err := s.DataStore.UpdateCredentialStatus(said, "received"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to accept credential", err.Error())
		return
	}
	s.EventHub.Broadcast(AgentEvent{
		Type:    "credential_accepted",
		Payload: map[string]interface{}{"said": said},
	})
	log.Printf("[identity-agent-core] CREDENTIAL: Accepted %s", said)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"said": said, "status": "received"})
}

// handleRejectCredential deletes a pending_inbound credential.
func (s *CoreServer) handleRejectCredential(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	if err := s.DataStore.DeleteCredential(said); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to reject credential", err.Error())
		return
	}
	log.Printf("[identity-agent-core] CREDENTIAL: Rejected and deleted %s", said)
	w.WriteHeader(http.StatusNoContent)
}

// deliverCredentialToContact pushes an issued credential directly to a known contact's agent.
// Called as a goroutine — failures are logged but do not affect the issue response.
func (s *CoreServer) deliverCredentialToContact(contact *store.ContactRecord, cred store.CredentialRecord) {
	baseURL := oobiBase(contact.OobiURL)
	if baseURL == "" {
		return
	}
	deliverURL := fmt.Sprintf("%s/api/credentials/deliver", baseURL)
	payload := map[string]interface{}{
		"said":            cred.SAID,
		"acdc_json":       cred.AcdcJson,
		"format":          cred.Format,
		"credential_type": cred.CredentialType,
		"issuer_aid":      cred.IssuerAID,
		"issuer_name":     cred.IssuerName,
		"schema_said":     cred.SchemaSAID,
	}
	body, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", deliverURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("[identity-agent-core] CREDENTIAL DELIVER: build request failed for %s: %v", deliverURL, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[identity-agent-core] CREDENTIAL DELIVER: push failed to %s: %v", deliverURL, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[identity-agent-core] CREDENTIAL DELIVER: pushed %s to %s (HTTP %d)", cred.SAID, deliverURL, resp.StatusCode)
}

// handleListBuiltinSchemas returns all schemas bundled into the Identity Agent binary.
// These are served to any KERI verifier that needs to resolve a schema SAID.
func (s *CoreServer) handleListBuiltinSchemas(w http.ResponseWriter, r *http.Request) {
	list := schemas.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": list,
		"count":   len(list),
	})
}

func (s *CoreServer) handleGetBuiltinSchema(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	schema := schemas.Get(said)
	if schema == nil {
		writeError(w, http.StatusNotFound, "Schema not found", said)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schema)
}

func (s *CoreServer) handleGetCredentialSchemas(w http.ResponseWriter, r *http.Request) {
	schemas, err := s.DataStore.GetCredentialSchemas()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read credential schemas", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": schemas,
		"count":   len(schemas),
	})
}

func (s *CoreServer) handleFetchCredentialSchema(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SAID string `json:"said"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.SAID == "" && req.URL == "" {
		writeError(w, http.StatusBadRequest, "Either said or url is required", "")
		return
	}

	// Check cache first
	if req.SAID != "" {
		if cached, _ := s.DataStore.GetCredentialSchema(req.SAID); cached != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cached)
			return
		}
	}

	// Fetch from URL or GLEIF ACDC schema registry
	fetchURL := req.URL
	if fetchURL == "" {
		fetchURL = "https://schema.gleif.org/acdc/" + req.SAID
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fetchURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to fetch schema", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "Schema fetch returned non-200", fmt.Sprintf("status %d from %s", resp.StatusCode, fetchURL))
		return
	}

	schemaBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read schema response", err.Error())
		return
	}

	// Extract SAID from response if not provided
	said := req.SAID
	if said == "" {
		var schemaMap map[string]interface{}
		if json.Unmarshal(schemaBytes, &schemaMap) == nil {
			if d, ok := schemaMap["$id"].(string); ok {
				said = d
			}
		}
	}
	if said == "" {
		said = req.URL
	}

	record := store.CredentialSchemaRecord{
		SAID:       said,
		SchemaJson: string(schemaBytes),
		FetchedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.DataStore.SaveCredentialSchema(record); err != nil {
		log.Printf("[identity-agent-core] SCHEMA: Failed to cache schema %s: %v", said, err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(record)
}

func (s *CoreServer) handlePresentCredential(w http.ResponseWriter, r *http.Request) {
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Credential presentation requires the Python KERI driver (desktop only)")
		return
	}

	var req struct {
		AcdcSaid      string `json:"acdc_said"`
		HolderAid     string `json:"holder_aid"`
		IssuerAid     string `json:"issuer_aid,omitempty"`
		SchemaSaid    string `json:"schema_said,omitempty"`
		CesrSignature string `json:"cesr_signature,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.AcdcSaid == "" || req.HolderAid == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "acdc_said and holder_aid are required")
		return
	}

	// Use our relationship (pairwise) AID for this presentation context, not root or arbitrary caller value.
	holderToUse := req.HolderAid
	if req.HolderAid != "" {
		if c, cerr := s.DataStore.GetContact(req.HolderAid); cerr == nil && c != nil && c.RelationshipAID != "" {
			holderToUse = c.RelationshipAID
		}
	}

	result, err := s.KeriDriver.PresentCredential(req.AcdcSaid, holderToUse, req.IssuerAid, req.SchemaSaid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Credential presentation failed", err.Error())
		return
	}

	record := store.PresentationRecord{
		SAID:                result.PresentationSaid,
		CredentialSAID:      req.AcdcSaid,
		HolderAID:           holderToUse,
		IssuerAID:           req.IssuerAid,
		PresentationJsonB64: result.PresentationJsonB64,
		CesrSignature:       req.CesrSignature,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		Status:              "created",
	}
	if err := s.DataStore.SavePresentation(record); err != nil {
		log.Printf("[identity-agent-core] PRESENTATION: Failed to persist %s: %v", result.PresentationSaid, err)
	}

	log.Printf("[identity-agent-core] PRESENTATION: Created %s for credential %s", result.PresentationSaid, req.AcdcSaid)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presentation_said":     result.PresentationSaid,
		"presentation_json_b64": result.PresentationJsonB64,
		// pres_said_b64: base64 of pres_said.encode(); Dart signs these bytes with holder key
		"pres_said_b64": result.PresSaidB64,
		"status":        "created",
	})
}

func (s *CoreServer) handleGetPresentations(w http.ResponseWriter, r *http.Request) {
	pres, err := s.DataStore.GetPresentations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read presentations", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presentations": pres,
		"count":         len(pres),
	})
}

func (s *CoreServer) handleVerifyCredential(w http.ResponseWriter, r *http.Request) {
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Credential verification requires the Python KERI driver (desktop only)")
		return
	}

	var req struct {
		AcdcJson           string   `json:"acdc_json"`
		HolderAid          string   `json:"holder_aid"`
		PresentationSaid   string   `json:"presentation_said"`
		CesrSignature      string   `json:"cesr_signature"`
		HolderPublicKey    string   `json:"holder_public_key"`
		TrustedSchemaSaids []string `json:"trusted_schema_saids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.AcdcJson == "" {
		writeError(w, http.StatusBadRequest, "Missing acdc_json", "")
		return
	}

	// Extract issuer AID from the ACDC JSON (which is base64-encoded) to look up its stored KEL.
	var acdcBody map[string]interface{}
	var issuerKelEvents []map[string]interface{}
	if acdcBytes, err := base64.StdEncoding.DecodeString(req.AcdcJson); err == nil {
		if err2 := json.Unmarshal(acdcBytes, &acdcBody); err2 == nil {
			if issuerAid, ok := acdcBody["i"].(string); ok && issuerAid != "" {
				// Try contact KEL first (cross-instance: issuer is a remote contact).
				if kelRecord, err3 := s.DataStore.GetContactKEL(issuerAid); err3 == nil && kelRecord != nil {
					issuerKelEvents = unwrapEventJSON(kelRecord.KEL)
				}
				// Fall back to own KEL (self-issued: issuer is this instance).
				if issuerKelEvents == nil {
					if ownEvents, err3 := s.DataStore.GetEvents(issuerAid); err3 == nil && len(ownEvents) > 0 {
						issuerKelEvents = eventRecordsToKEDs(ownEvents)
					}
				}
			}
		}
	}

	driverReq := &drivers.DriverVerifyCredentialRequest{
		AcdcJson:           req.AcdcJson,
		IssuerKelEvents:    issuerKelEvents,
		HolderAid:          req.HolderAid,
		PresentationSaid:   req.PresentationSaid,
		CesrSignature:      req.CesrSignature,
		HolderPublicKey:    req.HolderPublicKey,
		TrustedSchemaSaids: req.TrustedSchemaSaids,
	}

	result, err := s.KeriDriver.VerifyCredential(driverReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Credential verification failed", err.Error())
		return
	}

	if result != nil && issuerKelEvents != nil {
		issuerAid := ""
		if acdcBody != nil {
			if ia, ok := acdcBody["i"].(string); ok {
				issuerAid = ia
			}
		}
		if issuerAid != "" {
			if wRes := s.runWatcherOnKel(r.Context(), issuerAid, issuerKelEvents, watcher.SourceCredential, "", nil); wRes != nil && wRes.Blocked {
				writeError(w, http.StatusConflict, "Issuer KEL duplicity detected", wRes.Reason)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleVerifyCredentialChain accepts a SAID or ACDC JSON, verifies the credential,
// then walks the 'e' (edges) block to recursively verify each parent credential in the chain.
// Returns {valid, chain: [{...}], warnings, errors} where each chain step includes
// the credential SAID, schema, checks map, and overall step validity.
func (s *CoreServer) handleVerifyCredentialChain(w http.ResponseWriter, r *http.Request) {
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Credential verification requires the Python KERI driver (desktop only)")
		return
	}

	var req struct {
		// AcdcSaid: look up a credential by SAID from the local store.
		AcdcSaid string `json:"acdc_said"`
		// AcdcJsonB64: raw base64-encoded ACDC JSON for external credentials not in local store.
		AcdcJsonB64 string `json:"acdc_json_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.AcdcSaid == "" && req.AcdcJsonB64 == "" {
		writeError(w, http.StatusBadRequest, "acdc_said or acdc_json_b64 required", "")
		return
	}

	// Resolve ACDC JSON: from local store (by SAID) or from request body directly.
	acdcJsonB64 := req.AcdcJsonB64
	if acdcJsonB64 == "" {
		cred, err := s.DataStore.GetCredential(req.AcdcSaid)
		if err != nil || cred == nil {
			writeError(w, http.StatusNotFound, "Credential not found", req.AcdcSaid)
			return
		}
		acdcJsonB64 = cred.AcdcJson
	}

	type ChainStep struct {
		Said       string                 `json:"said"`
		SchemaSaid string                 `json:"schema_said"`
		IssuerAid  string                 `json:"issuer_aid"`
		Checks     map[string]interface{} `json:"checks"`
		Errors     []string               `json:"errors"`
		Valid      bool                   `json:"valid"`
		EdgeLabel  string                 `json:"edge_label,omitempty"` // label used in parent's edges block
	}

	var chain []ChainStep
	var allErrors []string
	warnings := []string{}

	// verifyOne: call the driver to verify a single ACDC, add a ChainStep, return the parsed ACDC body.
	verifyOne := func(jsonB64, edgeLabel string) (map[string]interface{}, bool) {
		// Decode to extract issuer AID for KEL lookup.
		var acdcBody map[string]interface{}
		if decoded, err := base64.StdEncoding.DecodeString(jsonB64); err == nil {
			_ = json.Unmarshal(decoded, &acdcBody)
		}

		var issuerKelEvents []map[string]interface{}
		issuerAid := ""
		if acdcBody != nil {
			if aid, ok := acdcBody["i"].(string); ok {
				issuerAid = aid
				if kelRecord, err := s.DataStore.GetContactKEL(aid); err == nil && kelRecord != nil {
					issuerKelEvents = unwrapEventJSON(kelRecord.KEL)
				}
				if issuerKelEvents == nil {
					if ownEvents, err := s.DataStore.GetEvents(aid); err == nil && len(ownEvents) > 0 {
						issuerKelEvents = eventRecordsToKEDs(ownEvents)
					}
				}
				if issuerKelEvents == nil {
					warnings = append(warnings, "No KEL found for issuer "+aid+"; issuer checks skipped")
				}
			}
		}

		driverReq := &drivers.DriverVerifyCredentialRequest{
			AcdcJson:        jsonB64,
			IssuerKelEvents: issuerKelEvents,
		}
		result, err := s.KeriDriver.VerifyCredential(driverReq)

		step := ChainStep{
			EdgeLabel: edgeLabel,
			IssuerAid: issuerAid,
			Errors:    []string{},
		}
		if acdcBody != nil {
			step.Said, _ = acdcBody["d"].(string)
			step.SchemaSaid, _ = acdcBody["s"].(string)
		}
		if err != nil {
			step.Valid = false
			step.Errors = append(step.Errors, err.Error())
			allErrors = append(allErrors, err.Error())
		} else {
			step.Valid = result.Verified
			step.Checks = result.Checks
			step.Errors = result.Errors
			if !result.Verified {
				allErrors = append(allErrors, result.Errors...)
			}
		}
		chain = append(chain, step)
		return acdcBody, step.Valid
	}

	// Verify the top-level credential.
	topBody, _ := verifyOne(acdcJsonB64, "")

	// Walk the 'e' edges block to verify parent credentials.
	if topBody != nil {
		if edgesRaw, ok := topBody["e"]; ok {
			if edgesMap, ok := edgesRaw.(map[string]interface{}); ok {
				for label, edgeRaw := range edgesMap {
					if label == "d" {
						continue // skip the edges block SAID itself
					}
					edgeEntry, ok := edgeRaw.(map[string]interface{})
					if !ok {
						continue
					}
					parentSAID, _ := edgeEntry["n"].(string)
					if parentSAID == "" {
						continue
					}
					// Look up parent credential from local store.
					parentCred, err := s.DataStore.GetCredential(parentSAID)
					if err != nil || parentCred == nil || parentCred.AcdcJson == "" {
						warnings = append(warnings, "Parent credential "+parentSAID+" (edge '"+label+"') not found in local store; cannot verify chain")
						// Add a placeholder step.
						chain = append(chain, ChainStep{
							Said:      parentSAID,
							EdgeLabel: label,
							Valid:     false,
							Errors:    []string{"Parent credential not in local store"},
						})
						allErrors = append(allErrors, "Chain broken: parent credential "+parentSAID+" not found")
						continue
					}
					verifyOne(parentCred.AcdcJson, label)
				}
			}
		}
	}

	// Overall validity: all steps must be valid.
	valid := len(allErrors) == 0
	for _, step := range chain {
		if !step.Valid {
			valid = false
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    valid,
		"chain":    chain,
		"warnings": warnings,
		"errors":   allErrors,
	})
}

func (s *CoreServer) handleSubmitReceipt(w http.ResponseWriter, r *http.Request) {
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Witness receipt submission requires the Python KERI driver (desktop only)")
		return
	}

	var req struct {
		EventSAID        string   `json:"event_said"`
		WitnessAID       string   `json:"witness_aid"`
		WitnessPublicKey string   `json:"witness_public_key"`
		CesrSignature    string   `json:"cesr_signature"`
		TrustedWitnesses []string `json:"trusted_witnesses"`
		Threshold        int      `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.EventSAID == "" || req.WitnessAID == "" || req.CesrSignature == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "event_said, witness_aid, cesr_signature are required")
		return
	}

	driverReq := &drivers.DriverSubmitReceiptRequest{
		EventSAID:        req.EventSAID,
		WitnessAID:       req.WitnessAID,
		WitnessPublicKey: req.WitnessPublicKey,
		CesrSignature:    req.CesrSignature,
		TrustedWitnesses: req.TrustedWitnesses,
		Threshold:        req.Threshold,
	}

	result, err := s.KeriDriver.SubmitReceipt(driverReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Receipt submission failed", err.Error())
		return
	}

	// Persist accepted receipts to durable store.
	if result.Accepted {
		_ = s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{
			EventSAID:     req.EventSAID,
			WitnessAID:    req.WitnessAID,
			CesrSignature: req.CesrSignature,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleGetKERL(w http.ResponseWriter, r *http.Request) {
	eventSAID := r.URL.Query().Get("event_said")
	if eventSAID == "" {
		writeError(w, http.StatusBadRequest, "Missing event_said query parameter", "")
		return
	}
	threshold := 0
	if t := r.URL.Query().Get("threshold"); t != "" {
		fmt.Sscanf(t, "%d", &threshold)
	}

	// Load receipts from durable store (always available, even without the Python driver).
	receipts, err := s.DataStore.GetWitnessReceipts(eventSAID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read witness receipts", err.Error())
		return
	}

	thresholdMet := threshold == 0 || len(receipts) >= threshold

	type receiptEntry struct {
		WitnessAID    string `json:"witness_aid"`
		CesrSignature string `json:"cesr_signature"`
		ReceivedAt    string `json:"received_at"`
	}
	entries := make([]receiptEntry, 0, len(receipts))
	for _, r := range receipts {
		entries = append(entries, receiptEntry{
			WitnessAID:    r.WitnessAID,
			CesrSignature: r.CesrSignature,
			ReceivedAt:    r.ReceivedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"event_said":    eventSAID,
		"receipts":      entries,
		"receipt_count": len(receipts),
		"threshold_met": thresholdMet,
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

// handleGetActions returns the list of available agent actions/endpoints.
// The Flutter Endpoints screen fetches this to display a live, searchable list.
func (s *CoreServer) handleGetActions(w http.ResponseWriter, r *http.Request) {
	type ActionEndpoint struct {
		Name        string   `json:"name"`
		Endpoint    string   `json:"endpoint"`
		Method      string   `json:"method"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}
	actions := []ActionEndpoint{
		{Name: "Add Contact", Endpoint: "/api/contacts/resolve", Method: "POST",
			Description: "Resolve an OOBI URL and add the identity as a trusted contact.",
			Tags:        []string{"contacts", "identity"}},
		{Name: "Get Contacts", Endpoint: "/api/contacts", Method: "GET",
			Description: "List all verified contacts in your network.",
			Tags:        []string{"contacts"}},
		{Name: "Accept Contact", Endpoint: "/api/contacts/{aid}/accept", Method: "POST",
			Description: "Accept an incoming contact request.",
			Tags:        []string{"contacts"}},
		{Name: "Get OOBI", Endpoint: "/api/oobi", Method: "GET",
			Description: "Generate your OOBI URL for sharing with contacts.",
			Tags:        []string{"identity", "sharing"}},
		{Name: "Get Identity", Endpoint: "/api/identity", Method: "GET",
			Description: "Get the current identity AID and status.",
			Tags:        []string{"identity"}},
		{Name: "Key Rotation", Endpoint: "/api/rotation", Method: "POST",
			Description: "Rotate signing keys. Your AID remains unchanged.",
			Tags:        []string{"identity", "security"}},
		{Name: "Get Key Event Log", Endpoint: "/api/kel", Method: "GET",
			Description: "Retrieve the Key Event Log for an AID.",
			Tags:        []string{"identity", "keri"}},
		{Name: "Sign Data", Endpoint: "/api/sign", Method: "POST",
			Description: "Cryptographically sign arbitrary data with your current keys.",
			Tags:        []string{"crypto", "signing"}},
		{Name: "Verify Signature", Endpoint: "/api/verify", Method: "POST",
			Description: "Verify a signature against a known AID.",
			Tags:        []string{"crypto", "verification"}},
		{Name: "Send Exchange", Endpoint: "/api/exchange", Method: "POST",
			Description: "Send an exchange message (payment request, credential offer, etc.) to a contact.",
			Tags:        []string{"exchange", "payments"}},
		{Name: "Issue Credential", Endpoint: "/api/credential/issue", Method: "POST",
			Description: "Issue a verifiable credential (ACDC) to a contact.",
			Tags:        []string{"credentials"}},
		{Name: "Get Credentials", Endpoint: "/api/credentials", Method: "GET",
			Description: "List all credentials held by this agent.",
			Tags:        []string{"credentials"}},
		{Name: "Get Health", Endpoint: "/api/health", Method: "GET",
			Description: "Check agent health and status.",
			Tags:        []string{"system"}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"actions": actions})
}

// ── Share Actions ─────────────────────────────────────────────────────────────

func (s *CoreServer) handleGetShareActions(w http.ResponseWriter, r *http.Request) {
	actions, err := s.DataStore.GetShareActions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read share actions", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"actions": actions, "count": len(actions)})
}

func (s *CoreServer) handleCreateShareAction(w http.ResponseWriter, r *http.Request) {
	var action store.ShareAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if action.ID == "" {
		action.ID = fmt.Sprintf("sa-%s", strings.ReplaceAll(action.ActionKey, "_", "-"))
	}
	if err := s.DataStore.UpsertShareAction(action); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save share action", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(action)
}

func (s *CoreServer) handleUpdateShareAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var action store.ShareAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	action.ID = id
	if err := s.DataStore.UpsertShareAction(action); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update share action", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(action)
}

func (s *CoreServer) handleDeleteShareAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.DataStore.DeleteShareAction(id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete share action", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	// Embed action type in OOBI URL if requested (e.g. ?action=add_contact)
	if action := r.URL.Query().Get("action"); action != "" {
		oobiURL = fmt.Sprintf("%s?action=%s", oobiURL, action)
	}

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
		// check asset store for a matching pairwise AID (G-049: serve asset AIDs for login verify)
		if s.assetHandler != nil {
			for _, a := range s.assetHandler.Store.ListAssets() {
				if a.PairwiseAID == requestedAID {
					// serve a minimal OOBI response for the asset AID
					kelResp, err := s.KeriDriver.GetKel(a.DisplayName)
					if err != nil {
						writeError(w, http.StatusInternalServerError, "KEL unavailable", err.Error())
						return
					}
					publicURL := s.getPublicURL(r)
					oobiURL := fmt.Sprintf("%s/public/oobi/%s", publicURL, a.PairwiseAID)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"aid":           a.PairwiseAID,
						"oobi":          oobiURL,
						"kel":           kelResp.KEL,
						"type":          "asset",
						"asset_id":      a.ID,
						"display_name":  a.DisplayName,
						"delegator_aid": a.DelegatorAID,
					})
					return
				}
			}
		}
		// Minted pairwise AID (e.g. an add-contact Ask signer): serve its OOBI from the
		// registered KEL so a peer can resolve + add it.
		if kel, ok := getPairwiseKEL(requestedAID); ok {
			publicURL := s.getPublicURL(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"aid":  requestedAID,
				"oobi": fmt.Sprintf("%s/public/oobi/%s", publicURL, requestedAID),
				"kel":  kel,
				"type": "pairwise",
			})
			return
		}
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

	// Browser landing page: when a browser (not the Identity Agent app) opens an OOBI link,
	// return a human-readable HTML page with download instructions and the OOBI URL.
	acceptHeader := r.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/html") {
		action := r.URL.Query().Get("action")
		actionLabel := "connect with you on Identity Agent"
		if action == "add_contact" {
			actionLabel = "add you as a contact on Identity Agent"
		}
		publicURL := s.getPublicURL(r)
		rawOobiURL := fmt.Sprintf("%s/public/oobi/%s", publicURL, identity.AID)
		if action != "" {
			rawOobiURL = fmt.Sprintf("%s?action=%s", rawOobiURL, action)
		}
		htmlPage := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect with %s — Identity Agent</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0e1a;color:#e2e8f0;max-width:480px;margin:60px auto;padding:24px}
    h1{font-size:22px;font-weight:700;margin-bottom:8px}
    p{color:#94a3b8;line-height:1.6}
    .card{background:#1e2433;border:1px solid #2d3748;border-radius:12px;padding:20px;margin:24px 0}
    .oobi{font-family:monospace;font-size:11px;color:#67e8f9;word-break:break-all}
    .step{display:flex;gap:12px;margin:12px 0}
    .num{background:#3b82f6;color:white;border-radius:50%%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
  </style>
</head>
<body>
  <h1>%s wants to %s</h1>
  <p>You need the Identity Agent app to accept this request.</p>
  <div class="card">
    <div class="step"><div class="num">1</div><div>Download and install Identity Agent</div></div>
    <div class="step"><div class="num">2</div><div>Open the app and create or import your identity</div></div>
    <div class="step"><div class="num">3</div><div>Scan or paste the link below to complete the request</div></div>
  </div>
  <p style="font-size:13px;margin-bottom:4px;">Your connection link (save this):</p>
  <div class="card"><span class="oobi">%s</span></div>
  <p style="font-size:12px;color:#64748b;">This link only works while the sender's Identity Agent is running.</p>
</body>
</html>`, alias, alias, actionLabel, rawOobiURL)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlPage)
		return
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
	if s.WatcherService != nil {
		resp["watchers"] = s.WatcherService.WatcherHints()
	} else {
		resp["watchers"] = []string{}
	}
	if s.WitnessService != nil {
		for k, v := range s.WitnessService.OOBIExtensions() {
			resp[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) broadcastWitnessEvent(aid string, eventJSON string) {
	if s.WitnessService == nil || eventJSON == "" {
		return
	}
	var ked map[string]interface{}
	if err := json.Unmarshal([]byte(eventJSON), &ked); err != nil {
		return
	}
	s.triggerWitnessBroadcast(aid, ked)
}

func (s *CoreServer) handlePublicCredentialServe(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	if said == "" {
		writeError(w, http.StatusBadRequest, "Missing SAID", "SAID parameter is required")
		return
	}

	cred, err := s.DataStore.GetCredential(said)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read credential", err.Error())
		return
	}
	if cred == nil {
		writeError(w, http.StatusNotFound, "Credential not found", fmt.Sprintf("No credential found for SAID: %s", said))
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if strings.Contains(acceptHeader, "text/html") {
		typeName := cred.CredentialType
		if typeName == "" {
			typeName = "Credential"
		}
		issuerDisplay := cred.IssuerName
		if issuerDisplay == "" {
			issuerDisplay = cred.IssuerAID
			if len(issuerDisplay) > 20 {
				issuerDisplay = issuerDisplay[:12] + "..."
			}
		}
		publicURL := s.getPublicURL(r)
		credURL := fmt.Sprintf("%s/public/credential/%s", publicURL, said)
		htmlPage := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s — Identity Agent</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0e1a;color:#e2e8f0;max-width:480px;margin:60px auto;padding:24px}
    h1{font-size:22px;font-weight:700;margin-bottom:8px}
    p{color:#94a3b8;line-height:1.6}
    .card{background:#1e2433;border:1px solid #2d3748;border-radius:12px;padding:20px;margin:24px 0}
    .url{font-family:monospace;font-size:11px;color:#67e8f9;word-break:break-all}
    .step{display:flex;gap:12px;margin:12px 0}
    .num{background:#3b82f6;color:white;border-radius:50%%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
  </style>
</head>
<body>
  <h1>%s has sent you a credential</h1>
  <p>You've been issued a <strong>%s</strong> credential. Open Identity Agent to accept it.</p>
  <div class="card">
    <div class="step"><div class="num">1</div><div>Download and install Identity Agent</div></div>
    <div class="step"><div class="num">2</div><div>Open the app and create or import your identity</div></div>
    <div class="step"><div class="num">3</div><div>Go to Credentials → Receive, then paste this link:</div></div>
    <div style="margin-top:12px"><div class="url">%s</div></div>
  </div>
  <p style="font-size:12px;color:#64748b;">This link only works while the issuer's Identity Agent is running.</p>
</body>
</html>`, typeName, issuerDisplay, typeName, credURL)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlPage)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"said":            cred.SAID,
		"acdc_json":       cred.AcdcJson,
		"format":          cred.Format,
		"credential_type": cred.CredentialType,
		"issuer_name":     cred.IssuerName,
		"issuer_aid":      cred.IssuerAID,
		"schema_said":     cred.SchemaSAID,
		"issued_at":       cred.IssuedAt,
	})
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
		Watchers   []string                 `json:"watchers"`
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

	if kelCount > 0 {
		if wRes := s.runWatcherOnKel(r.Context(), oobiData.AID, oobiData.KEL, watcher.SourceOOBI, req.OobiURL, oobiData.Watchers); wRes != nil && wRes.Blocked {
			writeError(w, http.StatusConflict, "KEL duplicity detected", wRes.Reason)
			return
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
		Trusted bool   `json:"trusted"`
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
			XKeriRole: "general",
		}
	}

	contactStatus := "verified"
	if s.KeriDriver != nil && len(oobiData.KEL) > 0 && !kelVerified {
		contactStatus = "unverified"
	}

	contactCategory := "general"
	if req.Trusted {
		contactCategory = "trusted"
	}

	contact := store.ContactRecord{
		AID:             oobiData.AID,
		Alias:           alias,
		PublicKey:       currentPublicKey,
		OobiURL:         req.OobiURL,
		Verified:        kelVerified || s.KeriDriver == nil,
		DiscoveredAt:    time.Now().UTC().Format(time.RFC3339),
		Status:          contactStatus,
		ContactSource:   "keri",
		ContactCategory: contactCategory,
		IsWitness:       false, // set via witness protocol (ADR-016)
		JCard:           contactJCard,
		Photo:           oobiData.Photo,
	}

	// Mint using architected HD derivation (BIP32/SLIP-0010 from root keystore seed) + real driver icp.
	// Assign stable monotonic RelationshipIndex at creation (persisted in record + used for derive).
	// Never derive index from len() or hash. Re-derive seed on demand from root + index (no per-rel seed files).
	// Hard error if root seed unavailable for derivation.
	if contact.RelationshipAID == "" && s.KeriDriver != nil {
		rootSeed, rerr := secureenclave.LoadRootSeed(s.DataDir)
		if rerr != nil {
			writeError(w, http.StatusInternalServerError, "Root keystore seed required for HD pairwise derivation (not found in secure storage)", rerr.Error())
			return
		}
		contactIdx, err := s.DataStore.AllocateNextRelationshipIndex("contacts")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to allocate relationship index", err.Error())
			return
		}
		contact.RelationshipIndex = contactIdx

		pairwiseSeed, derr := backup.DerivePairwiseSeed(rootSeed, contactIdx, 0)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, "Failed to HD-derive pairwise seed", derr.Error())
			return
		}
		// for pre-rot next key, derive keyIndex=1 under same relationship slot
		nextPairwiseSeed, _ := backup.DerivePairwiseSeed(rootSeed, contactIdx, 1)
		pub := ed25519.NewKeyFromSeed(pairwiseSeed).Public().(ed25519.PublicKey)
		nextPub := ed25519.NewKeyFromSeed(nextPairwiseSeed).Public().(ed25519.PublicKey)
		pubB64 := iacrypto.VerkeyQB64(pub)
		nextB64 := iacrypto.VerkeyQB64(nextPub)
		if resp, err := s.KeriDriver.CreateInceptionNamed(pubB64, nextB64, "rel-"+oobiData.AID); err == nil && resp.AID != "" {
			contact.RelationshipAID = resp.AID
			contact.RelationshipSeedB64 = "" // no per-contact secret; re-derive from root+index
			log.Printf("[identity-agent-core] CONTACT: HD-derived (index %d) + minted real relationship P-AID %s via local KERI driver for %s", contactIdx, resp.AID, oobiData.AID)
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to mint relationship icp via driver", err.Error())
			return
		}
	}

	if err := s.DataStore.SaveContact(contact); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
		return
	}
	if contact.Verified {
		s.notifyBackupEvent(backup.EventContactVerified)
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
			existing.Status = "accepted"
			s.DataStore.SaveContact(*existing)
			log.Printf("[identity-agent-core] EXCHANGE: Acceptance received — contact %s upgraded to accepted", req.SenderAID)
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
		if existing.Status == "accepted" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "already_accepted", "aid": req.SenderAID})
			return
		}
		if existing.Status == "pending_outbound" || existing.Status == "verified" {
			existing.Status = "accepted"
			s.DataStore.SaveContact(*existing)
			log.Printf("[identity-agent-core] EXCHANGE: Introduction received — contact %s auto-upgraded to accepted", req.SenderAID)
			s.EventHub.Broadcast(AgentEvent{
				Type: "contact_accepted",
				Payload: map[string]interface{}{
					"sender_aid":   req.SenderAID,
					"sender_alias": existing.Alias,
				},
			})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "aid": req.SenderAID})
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
				XKeriRole: "general",
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
			XKeriRole: "general",
		}
	}
	contact := store.ContactRecord{
		AID:             req.SenderAID,
		Alias:           alias,
		PublicKey:       req.SenderPublicKey,
		OobiURL:         req.SenderOOBI,
		Verified:        kelPresent,
		DiscoveredAt:    time.Now().UTC().Format(time.RFC3339),
		Status:          "pending_inbound",
		ContactSource:   "keri",
		ContactCategory: "general",
		JCard:           contactJCard,
		Photo:           req.SenderPhoto,
	}

	// HD-derive (BIP32/SLIP-0010) + real driver icp for inbound exchange (consistent with add).
	// Assign and persist stable RelationshipIndex; no per-rel seed persist, re-derive later.
	if contact.RelationshipAID == "" && s.KeriDriver != nil {
		rootSeed, rerr := secureenclave.LoadRootSeed(s.DataDir)
		if rerr != nil {
			writeError(w, http.StatusInternalServerError, "Root keystore seed required for HD pairwise derivation", rerr.Error())
			return
		}
		cidx, err := s.DataStore.AllocateNextRelationshipIndex("contacts")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to allocate relationship index", err.Error())
			return
		}
		contact.RelationshipIndex = cidx

		pwiseSeed, derr := backup.DerivePairwiseSeed(rootSeed, cidx, 0)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, "HD derive failed", derr.Error())
			return
		}
		nextPwise, _ := backup.DerivePairwiseSeed(rootSeed, cidx, 1)
		pub := ed25519.NewKeyFromSeed(pwiseSeed).Public().(ed25519.PublicKey)
		npub := ed25519.NewKeyFromSeed(nextPwise).Public().(ed25519.PublicKey)
		if resp, err := s.KeriDriver.CreateInceptionNamed(iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(npub), "rel-"+req.SenderAID); err == nil && resp.AID != "" {
			contact.RelationshipAID = resp.AID
			contact.RelationshipSeedB64 = ""
			log.Printf("[identity-agent-core] EXCHANGE: HD-derived (index %d) + minted rel P-AID %s", cidx, resp.AID)
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "driver mint failed for exchange rel", err.Error())
			return
		}
	}

	if err := s.DataStore.SaveContact(contact); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
		return
	}
	if contact.Verified {
		s.notifyBackupEvent(backup.EventContactVerified)
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

	var acceptReq struct {
		ContactCategory string `json:"contact_category"` // transactional | general | trusted | professional
	}
	json.NewDecoder(r.Body).Decode(&acceptReq) // body is optional

	if acceptReq.ContactCategory == "" {
		acceptReq.ContactCategory = "general"
	}

	log.Printf("[identity-agent-core] CONTACT-ACCEPT: Upgrading contact %s (%s) to accepted, category=%s", contact.Alias, aid, acceptReq.ContactCategory)

	contact.Status = "accepted"
	contact.ContactCategory = acceptReq.ContactCategory
	if err := s.DataStore.SaveContact(*contact); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update contact", err.Error())
		return
	}

	log.Printf("[identity-agent-core] CONTACT: Accepted %s (AID: %s) — status=accepted, category=%s", contact.Alias, aid, contact.ContactCategory)

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

	if s.WitnessService != nil && contact.ContactCategory == "trusted" {
		go func(contactAID string) {
			_ = s.WitnessService.SendWitnessRequest(context.Background(), contactAID)
		}(aid)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "aid": aid})
}

func (s *CoreServer) handleUpdateContact(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	if aid == "" {
		writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
		return
	}

	var req struct {
		ContactCategory string `json:"contact_category"` // transactional | general | trusted | professional
		Alias           string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
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

	if req.ContactCategory != "" {
		validCategories := map[string]bool{
			"transactional": true, "general": true, "trusted": true, "professional": true,
		}
		if !validCategories[req.ContactCategory] {
			writeError(w, http.StatusBadRequest, "Invalid contact_category", "contact_category must be one of: transactional, general, trusted, professional")
			return
		}
		contact.ContactCategory = req.ContactCategory
	}
	if req.Alias != "" {
		contact.Alias = req.Alias
	}

	if err := s.DataStore.SaveContact(*contact); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update contact", err.Error())
		return
	}

	log.Printf("[identity-agent-core] CONTACT: Updated %s (AID: %s) contact_category=%s", contact.Alias, aid, contact.ContactCategory)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contact)
}

func (s *CoreServer) countWitnesses() int {
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range contacts {
		if c.IsWitness {
			n++
		}
	}
	return n
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

	pendingCreds, err := s.DataStore.GetCredentialsFiltered("", "pending_inbound")
	if err != nil {
		pendingCreds = []store.CredentialRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts":              contacts,
		"count":               len(contacts),
		"pending_requests":    pendingReqs,
		"pending_count":       len(pendingReqs),
		"pending_credentials": pendingCreds,
		"pending_cred_count":  len(pendingCreds),
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

	// Auto-generate a Grape ID tunnel name if defaulting to GrapeID with no extension.
	if cfg.Provider == tunnel.ProviderGrapeID && cfg.TunnelExtension == "" {
		domain := cfg.TunnelDomain
		if domain == "" {
			domain = "grapeid.org"
		}
		name, err := tunnel.FindAvailableName(domain, 10)
		if err != nil {
			log.Printf("[identity-agent-core] Auto-tunnel: could not find available name: %v — falling back to no tunnel", err)
			cfg.Provider = tunnel.ProviderNone
			return cfg
		}
		cfg.TunnelExtension = name

		// Persist so the same name is used on restart.
		s.DataStore.SaveSettings(store.SettingsData{
			TunnelProvider:  string(tunnel.ProviderGrapeID),
			TunnelDomain:    domain,
			TunnelExtension: name,
		})
		log.Printf("[identity-agent-core] Auto-tunnel: assigned Grape ID name '%s'", name)
	}

	return cfg
}

func (s *CoreServer) handleGetTunnelSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.TunnelManager.GetConfig()
	status := s.TunnelManager.GetStatus()

	resp := map[string]interface{}{
		"provider":             cfg.Provider,
		"status":               status,
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
			"status":          "saved",
			"provider":        req.Provider,
			"tunnel":          map[string]interface{}{"active": false, "error": "tunnel manager not initialized"},
			"endpoint_url":    s.EndpointService.CurrentURL(),
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
			"status":          "saved",
			"provider":        req.Provider,
			"tunnel":          map[string]interface{}{"active": false, "error": err.Error()},
			"endpoint_url":    s.EndpointService.CurrentURL(),
			"endpoint_source": s.EndpointService.Source(),
		})
		return
	}

	s.EndpointService.Refresh()
	status := s.TunnelManager.GetStatus()
	log.Printf("[identity-agent-core] Tunnel restarted after settings change: active=%v url=%s", status.Active, status.URL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "saved",
		"provider":        req.Provider,
		"tunnel":          status,
		"endpoint_url":    s.EndpointService.CurrentURL(),
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
			"available": nil,
			"hub_error": true,
			"message":   fmt.Sprintf("Provider not responsive: %s", errDetail),
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
	s.notifyBackupEvent(backup.EventProfileChange)

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

// reloadIdentityIntoDriver seeds the Python KERI driver's in-memory _identities dict
// from the persisted DB state. Called once on startup after the driver is ready.
// This makes IssueCredential and Interact work across server restarts without
// requiring a fresh inception event each session.
func (s *CoreServer) reloadIdentityIntoDriver() {
	if s.KeriDriver == nil {
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		log.Printf("[identity-agent-core] KERI driver reload: no existing identity in DB")
		return
	}

	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		log.Printf("[identity-agent-core] KERI driver reload: failed to load KEL events: %v", err)
		return
	}

	// Parse each stored event_json into a KED dict and track the last SAID
	kel := make([]map[string]interface{}, 0, len(events))
	lastSAID := ""
	lastSN := 0
	for _, ev := range events {
		var ked map[string]interface{}
		if err := json.Unmarshal([]byte(ev.EventJSON), &ked); err != nil {
			log.Printf("[identity-agent-core] KERI driver reload: failed to parse event sn=%d: %v", ev.SequenceNumber, err)
			continue
		}
		kel = append(kel, ked)
		if d, ok := ked["d"].(string); ok && d != "" {
			lastSAID = d
		}
		if ev.SequenceNumber > lastSN {
			lastSN = ev.SequenceNumber
		}
	}

	req := &drivers.DriverReloadIdentityRequest{
		AID:            identity.AID,
		PublicKey:      identity.PublicKey,
		NextKeyDigest:  identity.NextKeyDigest,
		SequenceNumber: lastSN,
		LastSAID:       lastSAID,
		KEL:            kel,
	}

	result, err := s.KeriDriver.ReloadIdentity(req)
	if err != nil {
		log.Printf("[identity-agent-core] KERI driver reload failed (non-fatal — issuing will require fresh inception): %v", err)
		return
	}
	log.Printf("[identity-agent-core] KERI driver: reloaded identity %s (sn=%d, %d KEL events)",
		result.AID, result.SequenceNumber, result.KelEvents)
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
		"released":        true,
		"name":            releasedName,
		"endpoint_url":    s.EndpointService.CurrentURL(),
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

// unwrapEventJSON converts EventRecord-style dicts (with an "event_json" field containing a
// JSON-encoded KED) to raw KED dicts. Events that are already raw KEDs are passed through unchanged.
// This is needed because the OOBI endpoint serves EventRecord structs, so contact_kels stores
// event_json-wrapped records, while the Python credential_verify driver expects raw KED dicts.
func unwrapEventJSON(events []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if ejson, ok := ev["event_json"].(string); ok {
			var ked map[string]interface{}
			if err := json.Unmarshal([]byte(ejson), &ked); err == nil {
				out = append(out, ked)
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

// eventRecordsToKEDs converts store.EventRecord structs to raw KED dicts by parsing EventJSON.
func eventRecordsToKEDs(records []store.EventRecord) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
		var ked map[string]interface{}
		if err := json.Unmarshal([]byte(rec.EventJSON), &ked); err == nil {
			out = append(out, ked)
		}
	}
	return out
}

func writeError(w http.ResponseWriter, status int, errMsg string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Details: details})
}

// handleGetTasks returns all background tasks tracked in the database.
// Tasks are always automated — created and resolved by the identity agent,
// never manually initiated by the user. They provide a status window into
// ongoing operations (witness requests, KEL sync, credential verification, etc.).
func (s *CoreServer) handleGetTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.DataStore.GetTasks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read tasks", err.Error())
		return
	}
	if tasks == nil {
		tasks = []store.TaskRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
	})
}
