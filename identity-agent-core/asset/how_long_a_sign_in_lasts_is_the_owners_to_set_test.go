package asset

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func aLifetimeHandler(t *testing.T, a ...Asset) (*Handler, http.Handler) {
	t.Helper()
	h, err := NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range a {
		if err := h.Store.UpsertAsset(x); err != nil {
			t.Fatal(err)
		}
	}
	r := chi.NewRouter()
	r.Put("/assets/{id}/sign-in-lifetime", h.HandleSetSignInLifetime)
	return h, r
}

// Fails without the setting: the owner sets a utility app's sign-in lifetime,
// it is kept, and it is what a sign-in at the app is then given.
func TestTheOwnerSetsHowLongASignInToAUtilityAppLasts(t *testing.T) {
	h, r := aLifetimeHandler(t, Asset{ID: "chat", AssetType: "app"})
	if got := mustGet(t, h, "chat").SignInLifetime(); got != DefaultSignInLifetime {
		t.Fatalf("an app that has not said lasts %v, not the default %v", got, DefaultSignInLifetime)
	}
	if rec := do(r, "PUT", "/assets/chat/sign-in-lifetime", `{"sign_in_lifetime_hours":720}`); rec.Code != http.StatusOK {
		t.Fatalf("thirty days answered %d: %s", rec.Code, rec.Body)
	}
	if got := mustGet(t, h, "chat").SignInLifetime(); got != 30*24*time.Hour {
		t.Fatalf("the app's sign-in lasts %v after the owner set thirty days", got)
	}
	// Zero returns it to the default.
	if rec := do(r, "PUT", "/assets/chat/sign-in-lifetime", `{"sign_in_lifetime_hours":0}`); rec.Code != http.StatusOK {
		t.Fatalf("the default answered %d: %s", rec.Code, rec.Body)
	}
	if got := mustGet(t, h, "chat").SignInLifetime(); got != DefaultSignInLifetime {
		t.Fatalf("set back to the default, it lasts %v", got)
	}
}

// Fails without the ceiling: no owner can set a sign-in longer than thirty
// days, nor a negative or absent one, nor one for an asset that is not a
// utility app, and a refusal leaves what was set alone.
func TestASignInLifetimeOutsideTheCeilingIsRefused(t *testing.T) {
	h, r := aLifetimeHandler(t, Asset{ID: "chat", AssetType: "app", SignInLifetimeHours: 24}, Asset{ID: "site", AssetType: "website"})
	for _, body := range []string{
		`{"sign_in_lifetime_hours":721}`,
		`{"sign_in_lifetime_hours":-1}`,
		`{"sign_in_lifetime_hours":9223372036854775807}`,
		`{"sign_in_lifetime_hours":"720h"}`,
		`{}`,
		`not json`,
	} {
		if rec := do(r, "PUT", "/assets/chat/sign-in-lifetime", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d: %s", body, rec.Code, rec.Body)
		}
	}
	if got := mustGet(t, h, "chat").SignInLifetimeHours; got != 24 {
		t.Fatalf("a refused setting changed the app's to %d hours", got)
	}
	if rec := do(r, "PUT", "/assets/site/sign-in-lifetime", `{"sign_in_lifetime_hours":24}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a website's lifetime was set: %d", rec.Code)
	}
	if rec := do(r, "PUT", "/assets/nobody/sign-in-lifetime", `{"sign_in_lifetime_hours":24}`); rec.Code != http.StatusNotFound {
		t.Fatalf("a missing asset answered %d", rec.Code)
	}
	if _, err := h.SetSignInLifetime("chat", int(MaxSignInLifetime/time.Hour)+1); err != ErrSignInLifetime {
		t.Fatalf("the add-on's way in took more than the ceiling: %v", err)
	}
}

// Fails without the ceiling being applied on reading: a record that holds more
// than thirty days (written by hand, or by a build with another ceiling) still
// gives a sign-in thirty days, and a record from before the setting, which has
// no such field, reads as the default. Every asset that is not a utility app has
// the default whatever its record says.
func TestTheCoreGivesNoSignInMoreThanTheCeilingWhateverIsStored(t *testing.T) {
	var old Asset
	if err := json.Unmarshal([]byte(`{"id":"old","asset_type":"app","display_name":"old"}`), &old); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		a    Asset
		want time.Duration
	}{
		"an older record":         {old, DefaultSignInLifetime},
		"past the ceiling":        {Asset{AssetType: "app", SignInLifetimeHours: 100000}, MaxSignInLifetime},
		"negative":                {Asset{AssetType: "app", SignInLifetimeHours: -5}, DefaultSignInLifetime},
		"a website that says one": {Asset{AssetType: "website", SignInLifetimeHours: 720}, DefaultSignInLifetime},
		"one hour":                {Asset{AssetType: "app", SignInLifetimeHours: 1}, time.Hour},
	} {
		if got := c.a.SignInLifetime(); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func mustGet(t *testing.T, h *Handler, id string) Asset {
	t.Helper()
	a, ok, err := h.Store.GetAsset(id)
	if err != nil || !ok {
		t.Fatalf("asset %s: %v %v", id, ok, err)
	}
	return a
}
