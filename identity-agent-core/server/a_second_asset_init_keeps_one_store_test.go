package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/asset"

	"github.com/go-chi/chi/v5"
)

// An add-on that readies the asset handler again (an add-on that hosts utility apps does, on every
// one it makes) must not make a second asset store. The routes are mounted on the
// first handler; an asset written through a second one was a 404 on them, and
// either's next save wrote its stale list over the other's.
func TestReadyingTheAssetHandlerAgainKeepsOneStore(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	s.mountAssetRoutes(r)
	first := s.assetHandler

	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	if s.assetHandler != first {
		t.Fatal("readying the asset handler again made a second handler, and so a second copy of assets.json")
	}
	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{ID: "app-1", DisplayName: "an app", AssetType: "app"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app-1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("an asset made after the handler was readied again: GET /assets/app-1 = %d, want 200", w.Code)
	}
	// and a save through the routes' handler does not erase it
	if err := first.Store.UpsertAsset(asset.Asset{ID: "app-2", DisplayName: "another", AssetType: "app"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.assetHandler.Store.GetAsset("app-1"); !ok {
		t.Fatal("a later save erased an asset another path had written")
	}
}
