package asset

import (
	"fmt"
	"time"
)

// AppAsChanged is an app as it would be if its grant gave capabilities, within
// constraints (nil keeps the limits it has), checked as a grant is when the app
// is made: one that gives nothing, is past its end, or records a limit the
// gateway would not enforce is refused. Nothing is stored: the grant is issued
// first, and the record follows it (SetAppGrant).
func (h *Handler) AppAsChanged(assetID string, capabilities []string, constraints *map[string]interface{}) (Asset, error) {
	a, ok, err := h.Store.GetAsset(assetID)
	if err != nil {
		return Asset{}, err
	}
	if !ok {
		return Asset{}, fmt.Errorf("app not found")
	}
	if a.AssetType != "app" {
		return Asset{}, ErrNotAnApp
	}
	a.Capabilities = NormaliseCapabilities(capabilities)
	if constraints != nil {
		a.GrantConstraints = *constraints
	}
	if err := checkGrantAsked("app", a.Capabilities, a.GrantValidUntil, a.GrantConstraints); err != nil {
		return Asset{}, err
	}
	return a, nil
}

// SetAppGrant records what an app's grant gives, once the grant that says so
// stands.
func (h *Handler) SetAppGrant(assetID string, capabilities []string, constraints map[string]interface{}) (*Asset, error) {
	a, err := h.AppAsChanged(assetID, capabilities, &constraints)
	if err != nil {
		return nil, err
	}
	a.UpdatedAt = time.Now().UTC()
	if err := h.Store.UpsertAsset(a); err != nil {
		return nil, fmt.Errorf("persisting the app's grant: %w", err)
	}
	return &a, nil
}
