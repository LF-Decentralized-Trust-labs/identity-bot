package asset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSavingAGateTheCoreCannotCheckIsRefused(t *testing.T) {
	cases := map[string]string{
		`{"mode":"open","required_ofa_score":70}`:  "minimum score gate",
		`{"mode":"open","required_ofa_score":-5}`:  "minimum score gate",
		`{"mode":"open","required_badge":"green"}`: "badge gate",
		`{"mode":"open","required_aal":2}`:         "assurance level gate",
		`{"mode":"open","required_aal":-1}`:        "assurance level gate",
	}
	for pol, want := range cases {
		h, err := NewHandler(t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Store.UpsertAsset(Asset{ID: "a1"}); err != nil {
			t.Fatal(err)
		}
		// update path
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", "a1")
		req := httptest.NewRequest("PUT", "/", strings.NewReader(pol))
		req = req.WithContext(contextWithRoute(req, rc))
		w := httptest.NewRecorder()
		h.HandleUpdatePolicy(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Errorf("update %s: %d %s", pol, w.Code, w.Body.String())
		}
		if a, _, _ := h.Store.GetAsset("a1"); a.Policy.UnsupportedGate() != "" {
			t.Errorf("update %s: policy was stored", pol)
		}
		// create path
		body := `{"display_name":"d","origin":"o","asset_type":"domain","policy":` + pol + `}`
		w = httptest.NewRecorder()
		h.HandleCreateAsset(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
			t.Errorf("create %s: %d %s", pol, w.Code, w.Body.String())
		}
	}
}

func TestSavingAnOrdinaryPolicyIsStillAccepted(t *testing.T) {
	h, _ := NewHandler(t.TempDir(), nil)
	_ = h.Store.UpsertAsset(Asset{ID: "a1"})
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", "a1")
	req := httptest.NewRequest("PUT", "/", strings.NewReader(`{"mode":"invite"}`))
	req = req.WithContext(contextWithRoute(req, rc))
	w := httptest.NewRecorder()
	h.HandleUpdatePolicy(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func contextWithRoute(r *http.Request, rc *chi.Context) context.Context {
	return context.WithValue(r.Context(), chi.RouteCtxKey, rc)
}
