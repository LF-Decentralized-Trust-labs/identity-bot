package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/keri"
	"identity-agent-core/store"

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
}

type CoreInfoResponse struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	Version      string      `json:"version"`
	Phase        string      `json:"phase"`
	Capabilities []string    `json:"capabilities"`
	Backend      BackendInfo `json:"backend"`
}

type BackendInfo struct {
	Mode      string `json:"mode"`
	Storage   string `json:"storage"`
	Port      int    `json:"port"`
	StartedAt string `json:"started_at"`
}

type InceptionRequest struct {
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
}

type InceptionResponse struct {
	AID       string              `json:"aid"`
	Event     keri.InceptionEvent `json:"inception_event"`
	PublicKey string              `json:"public_key"`
	Created   string              `json:"created"`
}

type IdentityResponse struct {
	Initialized   bool                `json:"initialized"`
	AID           string              `json:"aid,omitempty"`
	PublicKey     string              `json:"public_key,omitempty"`
	NextKeyDigest string             `json:"next_key_digest,omitempty"`
	Created       string              `json:"created,omitempty"`
	EventCount    int                 `json:"event_count,omitempty"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

var (
	startTime  time.Time
	dataStore  store.Store
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
		r.Post("/inception", handleInception)
		r.Get("/identity", handleIdentity)
	})

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
	log.Printf("[identity-agent-core] API endpoints: /api/health, /api/info, /api/inception, /api/identity")
	log.Printf("[identity-agent-core] Phase 2: Inception - Identity Creation Ready")

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("[identity-agent-core] Failed to start server: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime).Round(time.Second)

	resp := HealthResponse{
		Status:    "active",
		Agent:     "keri-go",
		Version:   "0.1.0",
		Uptime:    uptime.String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Mode:      "primary_active",
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

	resp := CoreInfoResponse{
		Name:        "Identity Agent Core",
		Description: "Self-sovereign identity runtime powered by KERI",
		Version:     "0.1.0",
		Phase:       phase,
		Capabilities: []string{
			"health_check",
			"inception",
			"kel_storage",
		},
		Backend: BackendInfo{
			Mode:      "primary_active",
			Storage:   "file-based (badgerdb pending)",
			Port:      5000,
			StartedAt: startTime.UTC().Format(time.RFC3339),
		},
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

	signingPub, err := decodePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid public_key", err.Error())
		return
	}

	nextPub, err := decodePublicKey(req.NextPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid next_public_key", err.Error())
		return
	}

	result, err := keri.CreateInceptionEvent(signingPub, nextPub)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create inception event", err.Error())
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	eventRecord := store.EventRecord{
		AID:            result.AID,
		SequenceNumber: 0,
		EventType:      "icp",
		EventJSON:      result.EventJSON,
		PublicKey:       result.PublicKey,
		NextKeyDigest:  result.NextPublicKey,
		Timestamp:      now,
	}
	if err := dataStore.SaveEvent(eventRecord); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist inception event", err.Error())
		return
	}

	identityState := store.IdentityState{
		AID:           result.AID,
		PublicKey:     result.PublicKey,
		NextKeyDigest: result.NextPublicKey,
		Created:       now,
		EventCount:    1,
	}
	if err := dataStore.SaveIdentity(identityState); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist identity state", err.Error())
		return
	}

	log.Printf("[identity-agent-core] INCEPTION: New identity created - AID: %s", result.AID)

	resp := InceptionResponse{
		AID:       result.AID,
		Event:     result.Event,
		PublicKey: result.PublicKey,
		Created:   now,
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

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	var keyBytes []byte
	var err error

	if strings.HasPrefix(encoded, "B") {
		keyBytes, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded[1:])
	} else {
		keyBytes, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)
		if err != nil {
			keyBytes, err = base64.StdEncoding.DecodeString(encoded)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d bytes, expected %d", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}

func writeError(w http.ResponseWriter, status int, errMsg string, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Details: details})
}
