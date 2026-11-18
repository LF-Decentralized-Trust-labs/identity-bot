package asset

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Whether an installed front end of a utility app must sign in with a key its
// device's secure hardware proves (ADR-072 Amendment 17). The owner decides, per
// utility app; it is off unless they turn it on. Off, an installed front end may
// sign in with a key held in software, and the sign-in is kept, and told to the
// app's back end, at the lower grade. On, the Identity Agent refuses every
// installed-front-end sign-in without the hardware's proof, and ends every grant a
// key in software already holds. The utility app never chooses: nothing its back
// end or front end sends is read for this.

// SetRequireHardwareKey records whether the utility app assetID requires a
// hardware key. Turning it on tells OnHardwareKeyRequired, after the record is
// saved, so what was granted to a key in software ends at once. The owner's route
// and an add-on acting for the owner (the one that makes a utility app) both come
// here; a utility app's back end has no way to.
func (h *Handler) SetRequireHardwareKey(assetID string, require bool) (*Asset, error) {
	frontEndsMu.Lock()
	a, found, err := h.Store.GetAsset(assetID)
	switch {
	case err != nil:
		frontEndsMu.Unlock()
		return nil, err
	case !found:
		frontEndsMu.Unlock()
		return nil, ErrNotFound
	case a.AssetType != "app":
		frontEndsMu.Unlock()
		return nil, ErrNotAnApp
	}
	turnedOn := require && !a.RequireHardwareKey
	a.RequireHardwareKey = require
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		frontEndsMu.Unlock()
		return nil, err
	}
	frontEndsMu.Unlock()
	if turnedOn && h.OnHardwareKeyRequired != nil {
		h.OnHardwareKeyRequired(a.ID)
	}
	return &a, nil
}

// HandleSetRequireHardwareKey: PUT /api/assets/{id}/require-hardware-key
// {"require_hardware_key": true}. Owner only, both ways: turning it off lowers
// what the owner required, and turning it on ends sign-ins people hold.
func (h *Handler) HandleSetRequireHardwareKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Require *bool `json:"require_hardware_key"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || body.Require == nil {
		h.writeJSON(w, map[string]string{"error": "bad request: the body is {\"require_hardware_key\": true} or false"}, http.StatusBadRequest)
		return
	}
	a, err := h.SetRequireHardwareKey(chi.URLParam(r, "id"), *body.Require)
	switch {
	case errors.Is(err, ErrNotFound):
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
	case errors.Is(err, ErrNotAnApp):
		h.writeJSON(w, map[string]string{"error": "only a utility app's sign-in can require a hardware key"}, http.StatusBadRequest)
	case err != nil:
		h.writeJSON(w, map[string]string{"error": "the setting could not be saved"}, http.StatusInternalServerError)
	default:
		h.writeJSON(w, map[string]bool{"require_hardware_key": a.RequireHardwareKey}, http.StatusOK)
	}
}
