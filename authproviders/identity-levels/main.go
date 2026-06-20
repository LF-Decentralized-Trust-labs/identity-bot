// Identity Levels AuthProvider stub (the contract) — band-only score for the login steel thread.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

const contractVersion = "ap-1"

func main() {
	port := os.Getenv("AUTH_PROVIDER_PORT")
	if port == "" {
		port = "9998"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/score", handleScore)
	mux.HandleFunc("/check", handleCheck)
	addr := "127.0.0.1:" + port
	log.Printf("[identity-levels] listening on %s (contract stub)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":         "active",
		"provider":       "identity_levels",
		"version":        "1.0.0",
		"contract":       contractVersion,
		"secure_enclave": false,
	})
}

func handleScore(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{
		"score":       75,
		"band":        "green",
		"provider":    "identity_levels",
		"score_as_of": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Operation  string `json:"operation"`
		Required   int    `json:"required"`
		MaxAgeSec  int    `json:"max_age_sec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	current := 75
	writeJSON(w, map[string]interface{}{
		"operation":   req.Operation,
		"required":    req.Required,
		"current":     current,
		"sufficient":  current >= req.Required,
		"score_as_of": time.Now().UTC().Format(time.RFC3339),
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}