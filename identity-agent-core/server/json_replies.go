package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/internal/jsonreply"
)

// How a handler answers in JSON. Every route uses these, whichever part of the
// Identity Agent it belongs to.

func writeJSON(w http.ResponseWriter, v interface{}) {
	writeJSONStatus(w, http.StatusOK, v)
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	writeJSONStatus(w, http.StatusOK, data)
}

// writeJSONStatus writes v as JSON with a status. jsonResponse is it at 200.
func writeJSONStatus(w http.ResponseWriter, status int, v interface{}) {
	jsonreply.Write(w, status, v)
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
