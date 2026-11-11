package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/watcher"
)

// The contacts this agent's watcher cross-checks with are the owner's to choose.
// Asking a contact tells it whom this agent is checking on, and until the owner
// has chosen one none is asked, so after an upgrade the cross-check does nothing
// until these routes are used. Setting is owner-only (controllerOwnerOnly); reading is open to a
// controller, as the opt-out read is.

// handleWatcherPeersGet lists the chosen contacts, whether peer cross-checks are
// on, and the most that can be chosen.
func (s *CoreServer) handleWatcherPeersGet(w http.ResponseWriter, r *http.Request) {
	if s.WatcherService == nil {
		writeError(w, http.StatusNotFound, "watcher not running", "")
		return
	}
	aids := s.WatcherService.ChosenPeers()
	if aids == nil {
		aids = []string{}
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"aids":    aids,
		"enabled": s.WatcherService.PeerWatchEnabled(),
		"max":     watcher.MaxChosenPeers,
	})
}

// handleWatcherPeersSet replaces the chosen contacts. Every one must be an
// accepted contact, and more than watcher.MaxChosenPeers is refused rather than
// trimmed, so the owner is never told a contact is chosen when it is not.
func (s *CoreServer) handleWatcherPeersSet(w http.ResponseWriter, r *http.Request) {
	if s.WatcherService == nil || s.DataStore == nil {
		writeError(w, http.StatusNotFound, "watcher not running", "")
		return
	}
	var req struct {
		AIDs *[]string `json:"aids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AIDs == nil {
		writeError(w, http.StatusBadRequest, "aids required", "")
		return
	}
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read contacts", err.Error())
		return
	}
	accepted := map[string]bool{}
	for _, c := range contacts {
		if c.Status == "accepted" {
			accepted[c.AID] = true
		}
	}
	chosen := []string{}
	seen := map[string]bool{}
	for _, aid := range *req.AIDs {
		if !accepted[aid] {
			writeError(w, http.StatusBadRequest, "not an accepted contact", aid)
			return
		}
		if !seen[aid] {
			seen[aid] = true
			chosen = append(chosen, aid)
		}
	}
	if len(chosen) > watcher.MaxChosenPeers {
		writeError(w, http.StatusBadRequest, "too many contacts chosen", "")
		return
	}
	if err := s.WatcherService.SetChosenPeers(chosen); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"aids": chosen, "enabled": s.WatcherService.PeerWatchEnabled(), "max": watcher.MaxChosenPeers})
}
