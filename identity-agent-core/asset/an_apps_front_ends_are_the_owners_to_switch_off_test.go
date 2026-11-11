package asset

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func anAppHandler(t *testing.T, a Asset) (*Handler, http.Handler) {
	t.Helper()
	h, err := NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Get("/assets/{id}/front-ends", h.HandleGetFrontEnds)
	r.Put("/assets/{id}/front-ends", h.HandlePutFrontEnds)
	return h, r
}

func do(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

// Fails without the "only what is offered" rule: switching off is not a way to
// invent a front end.
func TestAnOwnerCannotSwitchOffAFrontEndTheAppDoesNotOffer(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", DeviceFrontEnds: []string{"browser"}})
	if rec := do(r, "PUT", "/assets/a/front-ends", `{"switched_off":["installed_app"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	if rec := do(r, "PUT", "/assets/a/front-ends", `{"switched_off":["tablet"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown kind answered %d", rec.Code)
	}
	if rec := do(r, "PUT", "/assets/a/front-ends", `{"switched_off":["browser","browser"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a repeated kind answered %d", rec.Code)
	}
}

// Fails if the setting is not kept: the next read, and the asset itself, say so.
func TestTheSwitchIsKeptAndCanBeSwitchedBackOn(t *testing.T) {
	h, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", DeviceFrontEnds: []string{"installed_app", "browser"}})
	if rec := do(r, "PUT", "/assets/a/front-ends", `{"switched_off":["browser"]}`); rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	a, _, _ := h.Store.GetAsset("a")
	if why := a.FrontEndRefusal("browser"); !strings.Contains(why, "switched off") {
		t.Fatalf("the saved asset admits a switched-off front end: %q", why)
	}
	if why := a.FrontEndRefusal("installed_app"); why != "" {
		t.Fatalf("the front end left on is refused: %q", why)
	}
	rec := do(r, "GET", "/assets/a/front-ends", "")
	if !strings.Contains(rec.Body.String(), `"switched_off":["browser"]`) || !strings.Contains(rec.Body.String(), `"installed_app","browser"`) {
		t.Fatalf("the read says %s", rec.Body)
	}
	do(r, "PUT", "/assets/a/front-ends", `{"switched_off":[]}`)
	a, _, _ = h.Store.GetAsset("a")
	if why := a.FrontEndRefusal("browser"); why != "" {
		t.Fatalf("a front end switched back on is still refused: %q", why)
	}
}

func TestOnlyAUtilityAppHasFrontEnds(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "w", AssetType: "website"})
	if rec := do(r, "GET", "/assets/w/front-ends", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("a website answered %d", rec.Code)
	}
	if rec := do(r, "GET", "/assets/none/front-ends", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("no asset answered %d", rec.Code)
	}
	if err := CheckOfferedFrontEnds("website", []string{"browser"}); err == nil {
		t.Fatal("a website was given front ends")
	}
	if err := CheckOfferedFrontEnds("app", []string{"browser", "x"}); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
}

// An enrolment token carries the front ends the owner says the app offers, and
// the machine that spends it cannot choose them.
func TestAnEnrolmentCarriesTheFrontEndsTheOwnerNamed(t *testing.T) {
	h, err := NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Post("/enrolments", h.HandleCreateEnrolment)
	rec := do(r, "POST", "/enrolments", `{"display_name":"dialler","asset_type":"app","origin":"https://x.example","device_front_ends":["installed_app"]}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"device_front_ends":["installed_app"]`) {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	if rec := do(r, "POST", "/enrolments", `{"display_name":"site","asset_type":"website","origin":"https://x.example","device_front_ends":["browser"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("front ends on a website answered %d", rec.Code)
	}
}

// Fails without requiring the field: a body that leaves switched_off out must
// not quietly switch every front end back on.
func TestABodyWithoutTheListChangesNothing(t *testing.T) {
	h, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", DeviceFrontEnds: []string{"browser"}, FrontEndsOff: []string{"browser"}})
	for _, body := range []string{`{}`, `{"switched_off":null}`, `{"switchedOff":[]}`} {
		if rec := do(r, "PUT", "/assets/a/front-ends", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d", body, rec.Code)
		}
	}
	a, _, _ := h.Store.GetAsset("a")
	if len(a.FrontEndsOff) != 1 {
		t.Fatalf("the switch was cleared: %v", a.FrontEndsOff)
	}
}
