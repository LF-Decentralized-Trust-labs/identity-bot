package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// The owner's side of authorising a controller.
//
// These are unlisted, so the router's default-deny keeps them from the public
// and from capability holders: a route reaches either only by being named in
// publicRoutes or scopedRoutes, and these must never be added to those.
//
// UNLISTED IS NOT THE WHOLE STORY, and saying only that used to make this
// comment wrong. An authorised controller also reaches unlisted routes, because
// a controller acts for the owner — so what actually governs these three is
// controllerOwnerOnly and the one check (what_a_controller_may_reach.go):
//
//   - Granting is owner-only. A controller that could enrol another one could
//     make its own access outlive the revocation of the grant the owner knows
//     about.
//   - Revoking is owner-only too, done from the device holding the key.
//   - Listing is open to a controller, subject to the one check.

// handleGrantController records that a machine may act for this identity.
//
// Called by the device holding the key, after it has authenticated the person
// and derived a pairwise owner identity for this machine. The agent is the
// register here, never the decider.
func (s *CoreServer) handleGrantController(w http.ResponseWriter, r *http.Request) {
	// Who asked, read before the body is: the owner's signed request, kept as
	// it was signed, is the authority the grant names.
	by, release, err := s.authorityOf(r)
	if err != nil {
		writeError(w, http.StatusForbidden, "who asked for this grant: "+err.Error(), "")
		return
	}
	defer release()
	var req struct {
		ControllerAID string `json:"controller_aid"`
		PublicKey     string `json:"public_key"`
		Label         string `json:"label"`
		Grade         string `json:"grade"`
		ExpiresAt     string `json:"expires_at"`
		Signer        string `json:"signer"`
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
		Signer:        strings.TrimSpace(req.Signer),
	}
	// A machine granted while the organisation has one signer belongs to
	// that signer from the start, so who it speaks for is settled when it is
	// paired rather than at its first message.
	if g.Signer == "" {
		g.Signer = s.onlyActiveSigner()
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

	now := time.Now().UTC()
	granted, err := s.grantController(g, now, by)
	if errors.Is(err, errKeyUnavailable) {
		writeError(w, http.StatusServiceUnavailable, err.Error(), "")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "grant": onTheWire(granted, now)})
}

// onTheWire is how a grant is described to a caller, and there is exactly one
// of these so that every route describes it the same way.
//
// The struct cannot be marshalled directly. `omitempty` does not omit a
// non-pointer struct, so a time.Time that is not set marshals as
// "0001-01-01T00:00:00Z" rather than disappearing — and a machine the owner
// KEEPS would come back carrying an expiry in year one. Any client comparing
// that against now reads it as long dead. Before this, the grant route
// marshalled the struct and the list route built its own map, so the two
// disagreed about whether the field existed at all — on the very response the
// granting device acts on.
func onTheWire(g ControllerGrant, now time.Time) map[string]any {
	live, why := g.Live(now)
	out := map[string]any{
		"controller_aid": g.ControllerAID,
		"public_key":     g.PublicKey,
		"label":          g.Label,
		"grade":          g.Grade,
		"granted_at":     g.GrantedAt,
		"live":           live,
	}
	// Present only when there is one, which is what distinguishes a machine
	// somebody keeps from one they borrowed.
	if !g.ExpiresAt.IsZero() {
		out["expires_at"] = g.ExpiresAt
	}
	if g.Signer != "" {
		out["signer"] = g.Signer
	}
	if g.CredentialSAID != "" {
		out["credential"] = g.CredentialSAID
	}
	if g.CredentialPending {
		out["credential"] = "pending on the device that holds the identity's key"
	}
	if !live {
		out["why_not"] = why
	}
	return out
}

// handleListControllers answers what this identity has authorised.
//
// Expired grants are included and marked rather than hidden, because this is
// what the owner is shown and "a machine I lent this to on Tuesday, which
// stopped" is something they may want to see. Newest first: the one somebody
// just granted is the one they are looking for.
func (s *CoreServer) handleListControllers(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	all, err := s.controllers().All()
	if err != nil {
		// Never an empty list. "No machines are authorised" and "what was
		// authorised could not be read" are opposite answers, and showing the
		// owner the first when the second is true invites them to grant again.
		writeError(w, http.StatusInternalServerError,
			"could not read which machines may act for this identity", err.Error())
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GrantedAt.After(all[j].GrantedAt) })

	out := make([]map[string]any, 0, len(all))
	for _, g := range all {
		out = append(out, onTheWire(g, now))
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
	if err := s.revokeController(aid); err != nil {
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("could not revoke %s", aid), err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "revoked": aid})
}
