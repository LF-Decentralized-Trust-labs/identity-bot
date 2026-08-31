package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// The owner's side of authorising a controller.
//
// These are owner-only by being unlisted: this router denies by default, and a
// route reaches anybody else only by being named in publicRoutes or
// scopedRoutes. That default is what makes these safe, so DO NOT add them to
// either list — a controller that could grant itself is not an authorisation.

// handleGrantController records that a machine may act for this identity.
//
// Called by the device holding the key, after it has authenticated the person
// and derived a pairwise owner identity for this machine — steps 7 to 9 of O6.
// The agent is the register here, never the decider.
func (s *CoreServer) handleGrantController(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ControllerAID string `json:"controller_aid"`
		PublicKey     string `json:"public_key"`
		Label         string `json:"label"`
		Grade         string `json:"grade"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}

	g := ControllerGrant{
		ControllerAID: req.ControllerAID,
		PublicKey:     req.PublicKey,
		Label:         req.Label,
		Grade:         ControllerGrade(strings.TrimSpace(req.Grade)),
	}
	if t := strings.TrimSpace(req.ExpiresAt); t != "" {
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				"expires_at must be an RFC3339 time", err.Error())
			return
		}
		g.ExpiresAt = parsed
	}

	granted, err := s.controllers().Grant(g, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "grant": granted})
}

// handleListControllers answers what this identity has authorised.
//
// Expired grants are included and marked rather than hidden, because this is
// what the owner is shown and "a machine I lent this to on Tuesday, which
// stopped" is something they may want to see. Newest first: the one somebody
// just granted is the one they are looking for.
func (s *CoreServer) handleListControllers(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	all := s.controllers().All()
	sort.Slice(all, func(i, j int) bool { return all[i].GrantedAt.After(all[j].GrantedAt) })

	out := make([]map[string]any, 0, len(all))
	for _, g := range all {
		live, why := g.Live(now)
		e := map[string]any{
			"controller_aid": g.ControllerAID,
			"public_key":     g.PublicKey,
			"label":          g.Label,
			"grade":          g.Grade,
			"granted_at":     g.GrantedAt,
			"live":           live,
		}
		if !g.ExpiresAt.IsZero() {
			e["expires_at"] = g.ExpiresAt
		}
		if !live {
			e["why_not"] = why
		}
		out = append(out, e)
	}
	writeJSON(w, map[string]any{"controllers": out})
}

// handleRevokeController takes a machine's authorisation away.
//
// The controller's key never left that machine and this agent could not have
// signed as it anyway; what it had was this record, so removing it is the whole
// revocation. Nothing needs to be reached, which is why this works for a laptop
// somebody no longer has.
func (s *CoreServer) handleRevokeController(w http.ResponseWriter, r *http.Request) {
	aid := strings.TrimSpace(chi.URLParam(r, "aid"))
	if aid == "" {
		writeError(w, http.StatusBadRequest, "which controller", "")
		return
	}
	if err := s.controllers().Revoke(aid); err != nil {
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("could not revoke %s", aid), err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "revoked": aid})
}
