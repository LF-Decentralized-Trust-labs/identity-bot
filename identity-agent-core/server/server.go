package server

import (
	"context"
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
	"identity-agent-core/store"
	"identity-agent-core/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type CoreServer struct {
	DataStore     store.Store
	KeriDriver    *drivers.KeriDriver
	TunnelManager *tunnel.Manager
	StartTime     time.Time
	Port          int
	DataDir       string
	AppCtx        context.Context
	cancel        context.CancelFunc
	listener      net.Listener
	router        chi.Router
	mu            sync.Mutex
	running       bool
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

	dataStore, err := store.NewFileStore(cfg.DataDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	s := &CoreServer{
		DataStore:  dataStore,
		StartTime:  time.Now(),
		Port:       cfg.Port,
		DataDir:    cfg.DataDir,
		AppCtx:     ctx,
		cancel:     cancel,
	}

	if cfg.EnableKeriDriver {
		s.KeriDriver = drivers.NewKeriDriver()
		if err := s.KeriDriver.Start(); err != nil {
			cancel()
			dataStore.Close()
			return nil, fmt.Errorf("failed to start KERI driver: %w", err)
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

	addr := fmt.Sprintf("0.0.0.0:%d", s.Port)
	var err error
	s.listener, err = net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to bind on %s: %w", addr, err)
	}

	s.running = true

	log.Printf("[identity-agent-core] Server listening on %s", addr)
	if s.KeriDriver != nil {
		log.Printf("[identity-agent-core] KERI driver: %s", s.KeriDriver.BaseURL)
	} else {
		log.Printf("[identity-agent-core] KERI driver: disabled (mobile mode — use Rust bridge)")
	}

	go func() {
		if tunnelCfg.Provider == tunnel.ProviderNone {
			log.Println("[identity-agent-core] No tunnel configured.")
			return
		}
		if err := s.TunnelManager.Start(s.AppCtx); err != nil {
			log.Printf("[identity-agent-core] Tunnel failed (non-fatal): %v", err)
			return
		}
		if s.TunnelManager.URL() != "" {
			log.Printf("[identity-agent-core] OOBI public URL: %s", s.TunnelManager.URL())
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

	if s.TunnelManager != nil {
		s.TunnelManager.Stop()
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
		r.Post("/sign", s.handleSign)
		r.Get("/kel", s.handleKel)
		r.Post("/verify", s.handleVerify)

		r.Post("/format-credential", s.handleFormatCredential)
		r.Post("/resolve-oobi", s.handleResolveOobi)
		r.Post("/generate-multisig-event", s.handleGenerateMultisigEvent)

		r.Get("/oobi", s.handleOobiGenerate)

		r.Get("/contacts", s.handleGetContacts)
		r.Post("/contacts", s.handleAddContact)
		r.Get("/contacts/{aid}", s.handleGetContact)
		r.Delete("/contacts/{aid}", s.handleDeleteContact)

		r.Get("/settings/tunnel", s.handleGetTunnelSettings)
		r.Put("/settings/tunnel", s.handlePutTunnelSettings)
		r.Get("/tunnel/status", s.handleTunnelStatus)
		r.Post("/tunnel/restart", s.handleTunnelRestart)

		r.Post("/store/identity", s.handleStoreIdentity)
		r.Post("/store/event", s.handleStoreEvent)
	})

	r.Get("/oobi/{aid}", s.handleOobiServe)

	absWebDir, err := filepath.Abs(flutterWebDir)
	if err != nil {
		absWebDir = flutterWebDir
	}

	if _, err := os.Stat(absWebDir); err == nil {
		log.Printf("[identity-agent-core] Serving Flutter web from: %s", absWebDir)
		fileServer := http.FileServer(http.Dir(absWebDir))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Join(absWebDir, r.URL.Path)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				http.ServeFile(w, r, filepath.Join(absWebDir, "index.html"))
				return
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
}

type InceptionResponse struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
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

	tunnelURL := ""
	if s.TunnelManager != nil {
		tunnelURL = s.TunnelManager.URL()
	}

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

func (s *CoreServer) getPublicURL(r *http.Request) string {
	if envURL := os.Getenv("PUBLIC_URL"); envURL != "" {
		return strings.TrimRight(envURL, "/")
	}

	if s.TunnelManager != nil && s.TunnelManager.URL() != "" {
		return s.TunnelManager.URL()
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
	oobiURL := fmt.Sprintf("%s/oobi/%s", baseURL, identity.AID)

	resp := map[string]interface{}{
		"oobi_url":   oobiURL,
		"aid":        identity.AID,
		"public_key": identity.PublicKey,
		"base_url":   baseURL,
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

	resp := map[string]interface{}{
		"aid":         identity.AID,
		"public_key":  identity.PublicKey,
		"kel":         events,
		"event_count": identity.EventCount,
		"created":     identity.Created,
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
		AID       string `json:"aid"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oobiData); err != nil {
		writeError(w, http.StatusBadGateway, "Invalid OOBI response", fmt.Sprintf("Could not parse response: %v", err))
		return
	}

	if oobiData.AID == "" {
		writeError(w, http.StatusBadGateway, "Invalid OOBI response", "Response did not contain an AID")
		return
	}

	alias := req.Alias
	if alias == "" {
		alias = oobiData.AID[:12] + "..."
	}

	contact := store.ContactRecord{
		AID:          oobiData.AID,
		Alias:        alias,
		PublicKey:    oobiData.PublicKey,
		OobiURL:      req.OobiURL,
		Verified:     true,
		DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := s.DataStore.SaveContact(contact); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
		return
	}

	log.Printf("[identity-agent-core] CONTACT: Added %s (AID: %s)", alias, oobiData.AID)

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

func (s *CoreServer) loadTunnelConfig() tunnel.Config {
	saved, err := s.DataStore.GetSettings()
	if err == nil && saved != nil && saved.TunnelProvider != "" {
		return tunnel.Config{
			Provider:              tunnel.ProviderType(saved.TunnelProvider),
			NgrokAuthToken:        saved.NgrokAuthToken,
			CloudflareTunnelToken: saved.CloudflareTunnelToken,
		}
	}
	return tunnel.DefaultConfig()
}

func (s *CoreServer) handleGetTunnelSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.TunnelManager.GetConfig()
	status := s.TunnelManager.GetStatus()

	resp := map[string]interface{}{
		"provider": cfg.Provider,
		"status":   status,
		"has_ngrok_token":      cfg.NgrokAuthToken != "",
		"has_cloudflare_token": cfg.CloudflareTunnelToken != "",
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
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	provider := tunnel.ProviderType(req.Provider)
	switch provider {
	case tunnel.ProviderCloudflare, tunnel.ProviderNgrok, tunnel.ProviderNone:
	default:
		writeError(w, http.StatusBadRequest, "Invalid provider", fmt.Sprintf("Provider must be one of: cloudflare, ngrok, none. Got: %s", req.Provider))
		return
	}

	settings := store.SettingsData{
		TunnelProvider:        req.Provider,
		NgrokAuthToken:        req.NgrokAuthToken,
		CloudflareTunnelToken: req.CloudflareTunnelToken,
	}

	if err := s.DataStore.SaveSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save settings", err.Error())
		return
	}

	log.Printf("[identity-agent-core] Tunnel settings updated: provider=%s", req.Provider)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "saved", "provider": req.Provider})
}

func (s *CoreServer) handleTunnelStatus(w http.ResponseWriter, r *http.Request) {
	status := s.TunnelManager.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *CoreServer) handleTunnelRestart(w http.ResponseWriter, r *http.Request) {
	cfg := s.loadTunnelConfig()
	log.Printf("[identity-agent-core] Restarting tunnel with provider: %s", cfg.Provider)

	if err := s.TunnelManager.Restart(s.AppCtx, cfg); err != nil {
		log.Printf("[identity-agent-core] Tunnel restart failed: %v", err)
		writeError(w, http.StatusInternalServerError, "Tunnel restart failed", err.Error())
		return
	}

	status := s.TunnelManager.GetStatus()
	log.Printf("[identity-agent-core] Tunnel restarted: active=%v url=%s", status.Active, status.URL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func writeError(w http.ResponseWriter, status int, errMsg string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Details: details})
}
