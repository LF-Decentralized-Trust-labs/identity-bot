package sandboxedapps

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Capability-registry management: capabilities are data, imported as packs and
// managed over this local API — never compiled in. Importing, enabling, disabling
// and deleting a capability stay owner-only, because they define or arm the
// capabilities the gateway trusts at invoke time; reading the registry is reachable
// by the owner's authorized controller. Remote callers (agents) only ever see the
// registry through the governed search/describe/execute surface.

// handleImportCapabilityPack imports (or rolls forward) one capability pack.
func (s *sandboxedApps) handleImportCapabilityPack(w http.ResponseWriter, r *http.Request) {
	if !s.IsOwner(r) {
		helpers.JSONError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		helpers.JSONError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		helpers.JSONError(w, "failed to read pack", http.StatusBadRequest)
		return
	}
	pack, n, err := s.SandboxManager.ImportCapabilityPackJSON(body)
	if err != nil {
		helpers.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	helpers.JSONResponse(w, map[string]any{"pack": pack.Pack, "version": pack.Version, "imported": n})
}

// handleListCapabilityRegistry is the management view: every record, disabled ones
// included.
func (s *sandboxedApps) handleListCapabilityRegistry(w http.ResponseWriter, r *http.Request) {
	// App operation (read) — authorized by the router-wide authorize gate (the owner
	// or the owner's authorized controller). Reading the registry is not owner-only;
	// importing a pack — which defines the capabilities the gateway trusts — stays
	// owner-only below, because that writes state the authorization decision reads.
	if s.SandboxManager == nil {
		helpers.JSONError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	recs, err := s.SandboxManager.Store().ListAllCapabilityRecords()
	if err != nil {
		helpers.JSONError(w, "failed to list capabilities", http.StatusInternalServerError)
		return
	}
	helpers.JSONResponse(w, map[string]any{"capabilities": recs, "count": len(recs)})
}

// handleSetCapabilityEnabled toggles one record.
func (s *sandboxedApps) handleSetCapabilityEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.IsOwner(r) {
		helpers.JSONError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		helpers.JSONError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.JSONError(w, "body must be {\"enabled\": true|false}", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	ok, err := s.SandboxManager.Store().SetCapabilityEnabled(id, req.Enabled)
	if err != nil {
		helpers.JSONError(w, "failed to update capability", http.StatusInternalServerError)
		return
	}
	if !ok {
		helpers.JSONError(w, "no such capability", http.StatusNotFound)
		return
	}
	helpers.JSONResponse(w, map[string]any{"id": id, "enabled": req.Enabled})
}

// handleDeleteCapabilityRecord removes one record (its invocation-log history remains).
func (s *sandboxedApps) handleDeleteCapabilityRecord(w http.ResponseWriter, r *http.Request) {
	if !s.IsOwner(r) {
		helpers.JSONError(w, "capability management is local-owner only", http.StatusForbidden)
		return
	}
	if s.SandboxManager == nil {
		helpers.JSONError(w, "sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ok, err := s.SandboxManager.Store().DeleteCapabilityRecord(id)
	if err != nil {
		helpers.JSONError(w, "failed to delete capability", http.StatusInternalServerError)
		return
	}
	if !ok {
		helpers.JSONError(w, "no such capability", http.StatusNotFound)
		return
	}
	helpers.JSONResponse(w, map[string]any{"deleted": id})
}
