package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/authorisation"

	"identity-agent-core/internal/jsonreply"
)

// A machine key's short code, from the one function that computes it.
//
// The screen that adds a machine and the screen that confirms it must show the
// same code, and the confirming screen gets its code from the core
// (authorisation.KeyFingerprint, ADR-045 Amendment 2). An app that computed it
// itself would be a second copy of that function, so it asks here instead.

type aKeysShortCodeRequest struct {
	PublicKey string `json:"public_key"`
}

type aKeysShortCodeResponse struct {
	ShortCode string `json:"short_code"`
}

func (s *CoreServer) handleAKeysShortCode(w http.ResponseWriter, r *http.Request) {
	var req aKeysShortCodeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Could not read the request", err.Error())
		return
	}
	code := authorisation.KeyFingerprint(req.PublicKey)
	if code == "" {
		writeError(w, http.StatusBadRequest, "No key to give a short code for", "public_key is empty")
		return
	}
	jsonreply.Write(w, http.StatusOK, aKeysShortCodeResponse{ShortCode: code})
}
