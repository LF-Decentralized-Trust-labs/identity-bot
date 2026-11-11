package asset

import (
	"bytes"
	"encoding/json"
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
	r.Put("/assets/{id}/front-ends/offered", h.HandleSetOfferedFrontEnds)
	r.Post("/assets", h.HandleCreateAsset)
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
	_, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", FrontEndsDeclared: true, DeviceFrontEnds: []string{"browser"}})
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
	h, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", FrontEndsDeclared: true, DeviceFrontEnds: []string{"installed_app", "browser"}})
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
	h, r := anAppHandler(t, Asset{ID: "a", AssetType: "app", FrontEndsDeclared: true, DeviceFrontEnds: []string{"browser"}, FrontEndsOff: []string{"browser"}})
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

// The four cases of an app's list (ADR-072 section 3, older apps). Each fails
// if "not declared" and "declared none" are read alike.
func TestAnAppThatNeverDeclaredSignsInAsBefore(t *testing.T) {
	old := Asset{ID: "old", AssetType: "app"}
	for _, kind := range []string{"", "browser", "installed_app"} {
		if why := old.FrontEndRefusal(kind); why != "" {
			t.Fatalf("an app made before it could declare refused kind %q: %s", kind, why)
		}
	}
}

func TestAnAppThatDeclaredNoneRefusesEveryKind(t *testing.T) {
	none := Asset{ID: "none", AssetType: "app", FrontEndsDeclared: true}
	for _, kind := range []string{"", "browser", "installed_app"} {
		if why := none.FrontEndRefusal(kind); why == "" {
			t.Fatalf("an app that declared it offers none admitted kind %q", kind)
		}
	}
}

// The distinction survives being stored and read back, which is where
// omitempty would have lost it.
func TestDeclaredNoneIsNotLostInStorage(t *testing.T) {
	h, _ := anAppHandler(t, Asset{ID: "none", AssetType: "app", FrontEndsDeclared: true, DeviceFrontEnds: []string{}})
	got, _, _ := h.Store.GetAsset("none")
	if !got.FrontEndsAreDeclared() || got.FrontEndRefusal("browser") == "" {
		t.Fatalf("a declared-empty list read back as not declared: %+v", got)
	}
	h, _ = anAppHandler(t, Asset{ID: "old", AssetType: "app"})
	got, _, _ = h.Store.GetAsset("old")
	if got.FrontEndsAreDeclared() {
		t.Fatalf("an older app read back as declared: %+v", got)
	}
}

func TestAnEmptyListGivenAtCreateIsADeclarationAndNoListIsNot(t *testing.T) {
	if !DeclaresFrontEnds("app", []string{}) {
		t.Fatal("an empty list given for an app is not a declaration")
	}
	if DeclaresFrontEnds("app", nil) {
		t.Fatal("no list given for an app is a declaration")
	}
	if DeclaresFrontEnds("website", []string{}) {
		t.Fatal("a website declares front ends")
	}
	var body struct {
		DeviceFrontEnds []string `json:"device_front_ends"`
	}
	for in, want := range map[string]bool{`{}`: false, `{"device_front_ends":null}`: false, `{"device_front_ends":[]}`: true} {
		body.DeviceFrontEnds = nil
		_ = json.Unmarshal([]byte(in), &body)
		if got := DeclaresFrontEnds("app", body.DeviceFrontEnds); got != want {
			t.Fatalf("%s: declared %v, want %v", in, got, want)
		}
	}
}

// An older app has nothing to switch off until its owner declares what it offers.
func TestAnOlderAppCannotBeSwitchedUntilItIsDeclared(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "old", AssetType: "app"})
	if rec := do(r, "PUT", "/assets/old/front-ends", `{"switched_off":[]}`); rec.Code != http.StatusConflict {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	rec := do(r, "GET", "/assets/old/front-ends", "")
	if !strings.Contains(rec.Body.String(), `"declared":false`) {
		t.Fatalf("the read does not say the app has not declared: %s", rec.Body)
	}
}

// The once-only set: from the manifest's list, for an app that has none.
func TestAnOlderAppCanDeclareItsFrontEndsOnce(t *testing.T) {
	h, r := anAppHandler(t, Asset{ID: "old", AssetType: "app"})
	if rec := do(r, "PUT", "/assets/old/front-ends/offered", `{"device_front_ends":["browser","installed_app"]}`); rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	got, _, _ := h.Store.GetAsset("old")
	if !got.FrontEndsAreDeclared() || len(got.DeviceFrontEnds) != 2 {
		t.Fatalf("not kept: %+v", got)
	}
	// Once only: a second declaration is refused and changes nothing, so the
	// switches cannot be used to widen what an app offers.
	if rec := do(r, "PUT", "/assets/old/front-ends/offered", `{"device_front_ends":["browser"]}`); rec.Code != http.StatusConflict {
		t.Fatalf("a second declaration answered %d", rec.Code)
	}
	got, _, _ = h.Store.GetAsset("old")
	if len(got.DeviceFrontEnds) != 2 {
		t.Fatalf("a second declaration changed the list: %v", got.DeviceFrontEnds)
	}
	// And the switches now work on it.
	if rec := do(r, "PUT", "/assets/old/front-ends", `{"switched_off":["browser"]}`); rec.Code != http.StatusOK {
		t.Fatalf("switching a declared app answered %d: %s", rec.Code, rec.Body)
	}
}

// An app that declared none cannot be given a list afterwards either.
func TestAnAppThatDeclaredNoneCannotDeclareLater(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "none", AssetType: "app", FrontEndsDeclared: true})
	if rec := do(r, "PUT", "/assets/none/front-ends/offered", `{"device_front_ends":["browser"]}`); rec.Code != http.StatusConflict {
		t.Fatalf("answered %d", rec.Code)
	}
}

func TestTheOnceOnlySetRefusesWhatIsNotAnAppListFromAnApp(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "old", AssetType: "app"})
	for _, body := range []string{`{}`, `{"device_front_ends":null}`, `{"device_front_ends":["tablet"]}`, `{"device_front_ends":["browser","browser"]}`} {
		if rec := do(r, "PUT", "/assets/old/front-ends/offered", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d", body, rec.Code)
		}
	}
	_, r = anAppHandler(t, Asset{ID: "w", AssetType: "website"})
	if rec := do(r, "PUT", "/assets/w/front-ends/offered", `{"device_front_ends":["browser"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a website answered %d", rec.Code)
	}
}

// ProvisionAppAsset's own front-end list is tested with a real provisioning, in
// the server package (TestProvisionAppAssetTakesAFrontEndList).
func TestProvisionAppAssetRefusesAnUnknownKindBeforeMinting(t *testing.T) {
	h, _ := newAgentForTest(t, nil)
	if _, err := h.ProvisionAppAsset("Bad", []string{"a.b"}, nil, nil, []string{"tablet"}); err == nil || !strings.Contains(err.Error(), "device_front_ends") {
		t.Fatalf("an unknown kind: %v", err)
	}
}

// The check is made where an asset is created.
func TestCreatingAnAssetChecksItsFrontEnds(t *testing.T) {
	_, r := anAppHandler(t, Asset{ID: "x", AssetType: "app"})
	for _, body := range []string{
		`{"display_name":"s","origin":"https://s.example","asset_type":"website","device_front_ends":["browser"]}`,
		`{"display_name":"a","origin":"https://a.example","asset_type":"app","device_front_ends":["tablet"]}`,
		`{"display_name":"a","origin":"https://a.example","asset_type":"app","device_front_ends":["browser","browser"]}`,
	} {
		if rec := do(r, "POST", "/assets", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d: %s", body, rec.Code, rec.Body)
		}
	}
}

// The offered list comes from the owner's token, never from the machine that
// enrols: a machine that sends its own list gets the token's.
func TestTheOfferedListIsTheTokensNotTheMachines(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	token, err := h.Store.CreateEnrolment(Enrolment{DisplayName: "dialler", AssetType: "app", Origin: "https://d.example",
		DeviceFrontEnds: []string{"browser"}, FrontEndsDeclared: true})
	if err != nil {
		t.Fatal(err)
	}
	m := newTestMachine(t)
	raw, _ := json.Marshal(map[string]interface{}{
		"token": token.Token, "public_key": m.pub, "next_public_key": m.next, "signature": m.sign(token.Token),
		"device_front_ends": []string{"browser", "installed_app"}, "front_ends_declared": true,
	})
	w := httptest.NewRecorder()
	h.HandleEnrol(w, httptest.NewRequest(http.MethodPost, "/api/enrol", bytes.NewReader(raw)))
	if w.Code != http.StatusCreated {
		t.Fatalf("enrolment answered %d: %s", w.Code, w.Body)
	}
	var out struct{ Asset Asset }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	got, _, _ := h.Store.GetAsset(out.Asset.ID)
	if len(got.DeviceFrontEnds) != 1 || got.DeviceFrontEnds[0] != "browser" || !got.FrontEndsDeclared {
		t.Fatalf("the machine chose the list: %+v", got)
	}
	// And a token that declared nothing enrols an app that has not declared.
	token, _ = h.Store.CreateEnrolment(Enrolment{DisplayName: "old", AssetType: "app", Origin: "https://o.example"})
	m = newTestMachine(t)
	w = enrol(t, h, token.Token, m)
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	got, _, _ = h.Store.GetAsset(out.Asset.ID)
	if got.FrontEndsAreDeclared() {
		t.Fatalf("a token that declared nothing made a declared app: %+v", got)
	}
}
