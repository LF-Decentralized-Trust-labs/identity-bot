package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Capability-registry management: capabilities are data, imported as packs and
// managed over this local API — never compiled in. All management is local-owner
// only; remote callers only ever see the registry through the governed
// search/describe/execute surface.

// handleImportCapabilityPack imports (or rolls forward) one capability pack.
func (s *CoreServer) handleImportCapabilityPack(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		jsonError(w, "failed to read pack", http.StatusBadRequest)
		return
	}
	pack, n, err := s.SandboxManager.ImportCapabilityPackJSON(body)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]any{"pack": pack.Pack, "version": pack.Version, "imported": n})
}

// handleListCapabilityRegistry is the management view: every record, disabled ones
// included.
func (s *CoreServer) handleListCapabilityRegistry(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	recs, err := s.SandboxManager.Store().ListAllCapabilityRecords()
	if err != nil {
		jsonError(w, "failed to list capabilities", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"capabilities": recs, "count": len(recs)})
}

// handleSetCapabilityEnabled toggles one record.
func (s *CoreServer) handleSetCapabilityEnabled(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "body must be {\"enabled\": true|false}", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	ok, err := s.SandboxManager.Store().SetCapabilityEnabled(id, req.Enabled)
	if err != nil {
		jsonError(w, "failed to update capability", http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonError(w, "no such capability", http.StatusNotFound)
		return
	}
	jsonResponse(w, map[string]any{"id": id, "enabled": req.Enabled})
}

// handleDeleteCapabilityRecord removes one record (its invocation-log history remains).
func (s *CoreServer) handleDeleteCapabilityRecord(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		jsonError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ok, err := s.SandboxManager.Store().DeleteCapabilityRecord(id)
	if err != nil {
		jsonError(w, "failed to delete capability", http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonError(w, "no such capability", http.StatusNotFound)
		return
	}
	jsonResponse(w, map[string]any{"deleted": id})
}
