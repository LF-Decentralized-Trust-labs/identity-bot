package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Phase       string   `json:"phase"`
	Capabilities []string `json:"capabilities"`
	Backend     BackendInfo `json:"backend"`
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

	r.Get("/health", handleHealth)
	r.Get("/info", handleInfo)

	port := os.Getenv("GO_CORE_PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("[identity-agent-core] Starting Go Core on %s", addr)
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
			Port:      8080,
			StartedAt: startTime.UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
