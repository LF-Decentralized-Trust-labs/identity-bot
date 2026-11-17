package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// How long a person's sign-in to a utility app lets their browser's key speak
// for them (ADR-066, "How long a key speaks"). The owner of the utility app sets
// it, when the app is made or later; nothing the utility app sends can. An
// asset that has not said, and every asset that is not a utility app, gets the
// default. The core never records a longer one than the ceiling, whatever the
// asset's record says.

const (
	// DefaultSignInLifetime is how long a sign-in lasts at an asset whose owner
	// has not said: a working day.
	DefaultSignInLifetime = 12 * time.Hour
	// MaxSignInLifetime is the longest any owner may set, and the longest the
	// core records whatever is stored: thirty days. Past it a person who has
	// left or lost their computer is still signed in for longer than an owner
	// would notice.
	MaxSignInLifetime = 30 * 24 * time.Hour
)

// ErrSignInLifetime is a lifetime the core will not keep.
var ErrSignInLifetime = fmt.Errorf("sign_in_lifetime_hours is a whole number of hours from 1 to %d, or 0 for the default of %d",
	int(MaxSignInLifetime/time.Hour), int(DefaultSignInLifetime/time.Hour))

// CheckSignInLifetimeHours says whether an owner may set this many hours: 0
// (the default) or from one hour to the ceiling.
func CheckSignInLifetimeHours(hours int) error {
	// Compared in hours, so a huge number cannot wrap round to a short one.
	if hours < 0 || hours > int(MaxSignInLifetime/time.Hour) {
		return ErrSignInLifetime
	}
	return nil
}

// SignInLifetime is how long a sign-in at this asset lets its key speak: the
// owner's setting for a utility app, within the ceiling, and the default
// otherwise. A record made before the setting existed has none and gets the
// default; one that holds more than the ceiling (written by hand, or by an older
// build with another ceiling) gets the ceiling.
func (a Asset) SignInLifetime() time.Duration {
	if a.AssetType != "app" || a.SignInLifetimeHours <= 0 {
		return DefaultSignInLifetime
	}
	if a.SignInLifetimeHours > int(MaxSignInLifetime/time.Hour) {
		return MaxSignInLifetime
	}
	return time.Duration(a.SignInLifetimeHours) * time.Hour
}

// SetSignInLifetime records how long a sign-in at the utility app assetID
// lasts, in hours; 0 returns it to the default. Sign-ins already made keep the
// time they were given. The owner's route and an add-on acting for the owner
// (the one that makes a utility app) both come here; a utility app's back end
// has no way to.
func (h *Handler) SetSignInLifetime(assetID string, hours int) (*Asset, error) {
	if err := CheckSignInLifetimeHours(hours); err != nil {
		return nil, err
	}
	frontEndsMu.Lock()
	defer frontEndsMu.Unlock()
	a, found, err := h.Store.GetAsset(assetID)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, ErrNotFound
	case a.AssetType != "app":
		return nil, ErrNotAnApp
	}
	a.SignInLifetimeHours = hours
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		return nil, err
	}
	return &a, nil
}

// HandleSetSignInLifetime sets how long a sign-in at a utility app lasts.
// PUT /api/assets/{id}/sign-in-lifetime {"sign_in_lifetime_hours": 720}. Owner
// only: a longer sign-in widens what the owner allowed.
func (h *Handler) HandleSetSignInLifetime(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hours *int `json:"sign_in_lifetime_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hours == nil {
		h.writeJSON(w, map[string]string{"error": "bad request: " + ErrSignInLifetime.Error()}, http.StatusBadRequest)
		return
	}
	a, err := h.SetSignInLifetime(chi.URLParam(r, "id"), *body.Hours)
	switch {
	case errors.Is(err, ErrSignInLifetime):
		h.writeJSON(w, map[string]string{"error": "bad request: " + err.Error()}, http.StatusBadRequest)
	case errors.Is(err, ErrNotFound):
		h.writeJSON(w, map[string]string{"error": "not found"}, http.StatusNotFound)
	case errors.Is(err, ErrNotAnApp):
		h.writeJSON(w, map[string]string{"error": "only a utility app's sign-in lifetime is set; every other asset's is the default"}, http.StatusBadRequest)
	case err != nil:
		h.writeJSON(w, map[string]string{"error": "the sign-in lifetime could not be saved"}, http.StatusInternalServerError)
	default:
		h.writeJSON(w, map[string]interface{}{
			"sign_in_lifetime_hours": a.SignInLifetimeHours,
			"effective_hours":        int(a.SignInLifetime() / time.Hour),
		}, http.StatusOK)
	}
}
