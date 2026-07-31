package asset

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// HandleCreateEnrolment issues a token for one machine. Owner only.
func (h *Handler) HandleCreateEnrolment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName string `json:"display_name"`
		AssetType   string `json:"asset_type"`
		Origin      string `json:"origin"`
		ExpiresInS  int    `json:"expires_in_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}

	e := Enrolment{
		DisplayName: strings.TrimSpace(body.DisplayName),
		AssetType:   strings.TrimSpace(body.AssetType),
		Origin:      strings.TrimSpace(body.Origin),
	}
	if body.ExpiresInS > 0 {
		e.ExpiresAt = time.Now().UTC().Add(time.Duration(body.ExpiresInS) * time.Second)
	}

	created, err := h.Store.CreateEnrolment(e)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusBadRequest)
		return
	}
	h.writeJSON(w, created, http.StatusCreated)
}

func (h *Handler) HandleListEnrolments(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, h.Store.ListEnrolments(), http.StatusOK)
}

func (h *Handler) HandleRevokeEnrolment(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.RevokeEnrolment(chi.URLParam(r, "token")); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusNotFound)
		return
	}
	h.writeJSON(w, map[string]string{"status": "revoked"}, http.StatusOK)
}

// HandleEnrol is the machine's side: it presents the key it generated and the
// token it was given, and receives a delegated identity over that key.
//
// Reachable without being the owner, because the machine enrolling is not the
// owner and never will be. The token is what authorises it, and it is
// single-use, time-bounded, and describes in advance what it may enrol.
func (h *Handler) HandleEnrol(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token         string `json:"token"`
		PublicKey     string `json:"public_key"`
		NextPublicKey string `json:"next_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeJSON(w, map[string]string{"error": "bad request"}, http.StatusBadRequest)
		return
	}
	if body.Token == "" || body.PublicKey == "" || body.NextPublicKey == "" {
		h.writeJSON(w, map[string]string{
			"error": "token, public_key and next_public_key are all required",
		}, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	enrolment, ok := h.Store.GetEnrolment(body.Token)
	if !ok {
		// Same answer as a spent token, and deliberately vague. Distinguishing
		// "no such token" from "already used" tells somebody guessing which
		// guesses were close.
		h.writeJSON(w, map[string]string{"error": "this enrolment token cannot be used"}, http.StatusForbidden)
		return
	}
	if spent, why := enrolment.Spent(now); spent {
		h.writeJSON(w, map[string]string{"error": why}, http.StatusForbidden)
		return
	}

	// A delegated identity or nothing. The whole point of enrolling a machine
	// this way is that its authority comes from, and ends with, its owner.
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	if rootAID == "" {
		h.writeJSON(w, map[string]string{
			"error": "this agent has no identity yet, so it has nothing to delegate from",
		}, http.StatusConflict)
		return
	}
	if h.KeriDriver == nil {
		h.writeJSON(w, map[string]string{"error": "no KERI engine"}, http.StatusServiceUnavailable)
		return
	}

	// Delegate over the key the MACHINE generated. Nothing here derives a key,
	// which is the difference between this and every other asset: the private
	// half stays where it was made and never reaches this agent.
	resp, err := h.KeriDriver.CreateDelegatedInception(
		body.PublicKey, body.NextPublicKey, enrolment.DisplayName, rootAID)
	if err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	// The delegation is only real once our own KEL records it. Persisting the
	// anchor first means a failure here leaves no asset claiming an identity
	// nobody can verify.
	if err := h.persistDelegationAnchor(rootAID, resp.DelegatorIxn); err != nil {
		h.writeJSON(w, map[string]string{
			"error": "the delegation could not be anchored, so it was not issued: " + err.Error(),
		}, http.StatusInternalServerError)
		return
	}

	a := Asset{
		ID:          genID(),
		DisplayName: enrolment.DisplayName,
		AssetType:   enrolment.AssetType,
		// Taken from the token, not from the request. A machine does not get to
		// tell the owner where it lives.
		Origin:          enrolment.Origin,
		PairwiseAID:     resp.AID,
		DelegationModel: "delegated",
		DelegatorAID:    resp.DelegatorAID,
		// No SigningIndex. That field records where an asset's key sits in the
		// owner's derivation tree, and this asset's key is not in it at all.
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.Store.UpsertAsset(a); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	// Spent last. A token burned before the asset was stored would leave the
	// machine unable to retry something that never completed.
	if err := h.Store.SpendEnrolment(body.Token, a.ID, now); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusForbidden)
		return
	}

	h.writeJSON(w, map[string]interface{}{
		"asset":         a,
		"aid":           resp.AID,
		"delegator_aid": resp.DelegatorAID,
		// The machine needs its own inception event to serve its KEL and be
		// verifiable by anyone else.
		"dip_event": resp.DipEvent,
	}, http.StatusCreated)
}
