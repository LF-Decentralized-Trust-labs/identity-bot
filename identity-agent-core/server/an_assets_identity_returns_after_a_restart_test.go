package server

import (
	"testing"

	"identity-agent-core/keriengine"
)

// After a restart the key engine holds only the owner's own identity; an
// asset's returns when an add-on asks for it (Host.ReviveAssetIdentity, which an
// add-on that reads a utility app's key log calls when the engine has none), with the
// same identifier, as the OOBI route does.
func TestAnAssetsIdentityIsRevivedByTheHostAfterARestart(t *testing.T) {
	s, aid, _ := provisionedApp(t)
	app, ok, err := s.assetHandler.Store.GetAsset(appIDByAID(t, s, aid))
	if err != nil || !ok {
		t.Fatalf("the app: %v %v", ok, err)
	}
	s.KeriDriver = keriengine.New()
	s.engineSigns()
	s.reloadIdentityIntoDriver()
	if _, err := s.KeriDriver.GetKel(app.DisplayName); err == nil {
		t.Fatal("the engine still holds the app's identity after a restart, so this tests nothing")
	}
	if err := (hostWrapper{s}).ReviveAssetIdentity("no-such-asset"); err == nil {
		t.Fatal("an asset the store does not hold was revived")
	}
	if err := (hostWrapper{s}).ReviveAssetIdentity(app.ID); err != nil {
		t.Fatalf("revive: %v", err)
	}
	kel, err := s.KeriDriver.GetKel(app.DisplayName)
	if err != nil || kel.AID != aid {
		t.Fatalf("after reviving: %v, %+v (want %s)", err, kel, aid)
	}
}

func appIDByAID(t *testing.T, s *CoreServer, aid string) string {
	t.Helper()
	all, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.PairwiseAID == aid {
			return a.ID
		}
	}
	t.Fatalf("no asset with %s", aid)
	return ""
}
