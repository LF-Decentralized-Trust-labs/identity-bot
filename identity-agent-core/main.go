package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

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

var startTime time.Time

func main() {
	startTime = time.Now()

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
<p class="t">Run: cd identity_agent_ui && flutter build web</p></div></body></html>`)
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
	log.Printf("[identity-agent-core] API endpoints: /api/health, /api/info")
	log.Printf("[identity-agent-core] Phase 1: Skeleton - Health Check Ready")

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
	resp := CoreInfoResponse{
		Name:        "Identity Agent Core",
		Description: "Self-sovereign identity runtime powered by KERI",
		Version:     "0.1.0",
		Phase:       "Phase 1: Skeleton",
		Capabilities: []string{
			"health_check",
		},
		Backend: BackendInfo{
			Mode:      "primary_active",
			Storage:   "in-memory (badgerdb pending)",
			Port:      5000,
			StartedAt: startTime.UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
