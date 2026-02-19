package main

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net"
        "net/http"
        "os"
        "os/signal"
        "path/filepath"
        "strings"
        "syscall"
        "time"

        "identity-agent-core/drivers"
        "identity-agent-core/store"
        "identity-agent-core/tunnel"

        "github.com/go-chi/chi/v5"
        "github.com/go-chi/chi/v5/middleware"
        "github.com/go-chi/cors"
)

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
        Status      string `json:"status"`
        Library     string `json:"library"`
        URL         string `json:"url"`
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

var (
        startTime  time.Time
        dataStore  store.Store
        keriDriver *drivers.KeriDriver
        tunnelURL  string
)

func main() {
        startTime = time.Now()

        storeDir := os.Getenv("AGENT_DATA_DIR")
        if storeDir == "" {
                storeDir = filepath.Join(".", "data")
        }

        var err error
        dataStore, err = store.NewFileStore(storeDir)
        if err != nil {
                log.Fatalf("[identity-agent-core] Failed to initialize store: %v", err)
        }
        defer dataStore.Close()

        keriDriver = drivers.NewKeriDriver()
        if err := keriDriver.Start(); err != nil {
                log.Fatalf("[identity-agent-core] Failed to start KERI driver: %v", err)
        }

        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigChan
                log.Println("[identity-agent-core] Shutting down...")
                keriDriver.Stop()
                dataStore.Close()
                os.Exit(0)
        }()

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
                r.Get("/health", handleHealth)
                r.Get("/info", handleInfo)
                r.Get("/identity", handleIdentity)

                r.Post("/inception", handleInception)
                r.Post("/rotation", handleRotation)
                r.Post("/sign", handleSign)
                r.Get("/kel", handleKel)
                r.Post("/verify", handleVerify)

                r.Post("/format-credential", handleFormatCredential)
                r.Post("/resolve-oobi", handleResolveOobi)
                r.Post("/generate-multisig-event", handleGenerateMultisigEvent)

                r.Get("/oobi", handleOobiGenerate)

                r.Get("/contacts", handleGetContacts)
                r.Post("/contacts", handleAddContact)
                r.Get("/contacts/{aid}", handleGetContact)
                r.Delete("/contacts/{aid}", handleDeleteContact)
        })

        r.Get("/oobi/{aid}", handleOobiServe)

        webDir := os.Getenv("FLUTTER_WEB_DIR")
        if webDir == "" {
                webDir = filepath.Join("..", "identity_agent_ui", "build", "web")
        }

        absWebDir, err := filepath.Abs(webDir)
        if err != nil {
                log.Printf("[identity-agent-core] Warning: could not resolve web dir: %v", err)
                absWebDir = webDir
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
                log.Printf("[identity-agent-core] Flutter web build not found at: %s", absWebDir)
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

        port := os.Getenv("PORT")
        if port == "" {
                port = "5000"
        }

        portInt := 5000
        fmt.Sscanf(port, "%d", &portInt)

        addr := fmt.Sprintf("0.0.0.0:%s", port)
        log.Printf("[identity-agent-core] Starting Go Core on %s", addr)
        log.Printf("[identity-agent-core] KERI endpoints: /api/inception, /api/rotation, /api/sign, /api/kel, /api/verify, /api/format-credential, /api/resolve-oobi, /api/generate-multisig-event")
        log.Printf("[identity-agent-core] Connectivity endpoints: /api/oobi, /api/contacts, /oobi/{aid}")
        log.Printf("[identity-agent-core] KERI driver: %s", keriDriver.BaseURL)
        log.Printf("[identity-agent-core] Phase 3: Connectivity - OOBI & Contacts Ready")

        ctx := context.Background()
        tun, tunErr := tunnel.Start(ctx)
        if tunErr != nil {
                log.Printf("[identity-agent-core] Tunnel failed (non-fatal): %v", tunErr)
        }
        if tun != nil {
                tunnelURL = tun.URL()
                log.Printf("[identity-agent-core] OOBI public URL: %s", tunnelURL)
                defer tun.Close()

                go func() {
                        if err := http.Serve(tun.Listener(), r); err != nil {
                                log.Printf("[identity-agent-core] Tunnel server stopped: %v", err)
                        }
                }()
        } else {
                log.Println("[identity-agent-core] No tunnel configured. OOBI URLs use request-derived host or PUBLIC_URL env var.")
        }

        listener, err := net.Listen("tcp4", addr)
        if err != nil {
                log.Fatalf("[identity-agent-core] Failed to bind on %s: %v", addr, err)
        }
        if err := http.Serve(listener, r); err != nil {
                log.Fatalf("[identity-agent-core] Failed to start server: %v", err)
        }
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
        uptime := time.Since(startTime).Round(time.Second)

        driverStatus := "unknown"
        status, err := keriDriver.GetStatus()
        if err == nil {
                driverStatus = status.Status
        }

        resp := HealthResponse{
                Status:    "active",
                Agent:     "keri-go",
                Version:   "0.1.0",
                Uptime:    uptime.String(),
                Timestamp: time.Now().UTC().Format(time.RFC3339),
                Mode:      fmt.Sprintf("primary_active (driver: %s)", driverStatus),
                TunnelURL: tunnelURL,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
        identity, _ := dataStore.GetIdentity()
        phase := "Phase 2: Inception"
        if identity != nil {
                phase = "Phase 2: Inception (Identity Active)"
        }

        driverInfo := DriverInfo{
                Status:  "unknown",
                Library: "unknown",
                URL:     keriDriver.BaseURL,
        }

        status, err := keriDriver.GetStatus()
        if err == nil {
                driverInfo.Status = status.Status
                driverInfo.Library = status.KeriLibrary
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
                        "keri_driver",
                },
                Backend: BackendInfo{
                        Mode:      "primary_active",
                        Storage:   "file-based (badgerdb pending)",
                        Port:      5000,
                        StartedAt: startTime.UTC().Format(time.RFC3339),
                },
                Driver: driverInfo,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func handleInception(w http.ResponseWriter, r *http.Request) {
        existing, _ := dataStore.GetIdentity()
        if existing != nil {
                writeError(w, http.StatusConflict, "Identity already exists", "AID: "+existing.AID)
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

        result, err := keriDriver.CreateInception(req.PublicKey, req.NextPublicKey)
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
                PublicKey:       result.PublicKey,
                NextKeyDigest:  result.NextKeyDigest,
                Timestamp:      now,
        }
        if err := dataStore.SaveEvent(eventRecord); err != nil {
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
        if err := dataStore.SaveIdentity(identityState); err != nil {
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

func handleIdentity(w http.ResponseWriter, r *http.Request) {
        identity, err := dataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }

        if identity == nil {
                resp := IdentityResponse{
                        Initialized: false,
                }
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

func handleRotation(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.RotateAid(req.Name, req.NewPublicKey, req.NewNextPublicKey)
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
                PublicKey:       result.NewPublicKey,
                NextKeyDigest:  result.NewNextKeyDigest,
                Timestamp:      now,
        }
        if err := dataStore.SaveEvent(eventRecord); err != nil {
                log.Printf("[identity-agent-core] Warning: failed to persist rotation event: %v", err)
        }

        identity, _ := dataStore.GetIdentity()
        if identity != nil {
                identity.PublicKey = result.NewPublicKey
                identity.NextKeyDigest = result.NewNextKeyDigest
                identity.EventCount = result.SequenceNumber + 1
                dataStore.SaveIdentity(*identity)
        }

        log.Printf("[identity-agent-core] ROTATION: Key rotated for AID: %s (sn: %d)", result.AID, result.SequenceNumber)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleSign(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.SignPayload(req.Name, req.Data)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Signing failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleKel(w http.ResponseWriter, r *http.Request) {
        name := r.URL.Query().Get("name")
        if name == "" {
                writeError(w, http.StatusBadRequest, "Missing required parameter", "name query parameter is required")
                return
        }

        result, err := keriDriver.GetKel(name)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to retrieve KEL", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.VerifySignature(req.Data, req.Signature, req.PublicKey)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Verification failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleFormatCredential(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.FormatCredential(req.Claims, req.SchemaSaid, req.IssuerAid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Format credential failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleResolveOobi(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.ResolveOobi(req.URL)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "OOBI resolution failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func handleGenerateMultisigEvent(w http.ResponseWriter, r *http.Request) {
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

        result, err := keriDriver.GenerateMultisigEvent(req.AIDs, req.Threshold, req.CurrentKeys, req.EventType)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Multisig event generation failed", err.Error())
                return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(result)
}

func getPublicURL(r *http.Request) string {
        if envURL := os.Getenv("PUBLIC_URL"); envURL != "" {
                return strings.TrimRight(envURL, "/")
        }

        if tunnelURL != "" {
                return tunnelURL
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

func handleOobiGenerate(w http.ResponseWriter, r *http.Request) {
        identity, err := dataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }
        if identity == nil {
                writeError(w, http.StatusNotFound, "No identity created", "Create an identity first using /api/inception")
                return
        }

        baseURL := getPublicURL(r)
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

func handleOobiServe(w http.ResponseWriter, r *http.Request) {
        requestedAID := chi.URLParam(r, "aid")
        if requestedAID == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        identity, err := dataStore.GetIdentity()
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read identity", err.Error())
                return
        }
        if identity == nil || identity.AID != requestedAID {
                writeError(w, http.StatusNotFound, "AID not found", fmt.Sprintf("No identity found for AID: %s", requestedAID))
                return
        }

        events, err := dataStore.GetEvents(requestedAID)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read KEL", err.Error())
                return
        }

        resp := map[string]interface{}{
                "aid":        identity.AID,
                "public_key": identity.PublicKey,
                "kel":        events,
                "event_count": identity.EventCount,
                "created":    identity.Created,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
}

func handleGetContacts(w http.ResponseWriter, r *http.Request) {
        contacts, err := dataStore.GetContacts()
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

func handleGetContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := dataStore.GetContact(aid)
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

func handleAddContact(w http.ResponseWriter, r *http.Request) {
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

        identity, _ := dataStore.GetIdentity()
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

        if err := dataStore.SaveContact(contact); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to save contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Added %s (AID: %s)", alias, oobiData.AID)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(contact)
}

func handleDeleteContact(w http.ResponseWriter, r *http.Request) {
        aid := chi.URLParam(r, "aid")
        if aid == "" {
                writeError(w, http.StatusBadRequest, "Missing AID", "AID parameter is required")
                return
        }

        contact, err := dataStore.GetContact(aid)
        if err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to read contact", err.Error())
                return
        }
        if contact == nil {
                writeError(w, http.StatusNotFound, "Contact not found", fmt.Sprintf("No contact found for AID: %s", aid))
                return
        }

        if err := dataStore.DeleteContact(aid); err != nil {
                writeError(w, http.StatusInternalServerError, "Failed to delete contact", err.Error())
                return
        }

        log.Printf("[identity-agent-core] CONTACT: Removed %s (AID: %s)", contact.Alias, aid)

        w.WriteHeader(http.StatusNoContent)
}

func writeError(w http.ResponseWriter, status int, errMsg string, details string) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Details: details})
}
