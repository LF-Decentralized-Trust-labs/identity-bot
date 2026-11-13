package login

import "testing"

func TestOnlyAnInstalledAppsSignInIsKeptInTheInstalledAppList(t *testing.T) {
	h := &Handler{}
	var err error
	if h.InstalledApps, err = NewInstalledAppSignInStore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	rel := &SiteRelationship{PairwiseAID: "Dperson"}
	key := "k8Wm0nZtVq3dYxq0yq9mY3gQp1G5mXJ0u2nq1Zk8s-A"
	for _, fe := range []string{FrontEndBrowser, ""} {
		if _, err := h.recordInstalledAppSignIn(rel, &ChallengeBundle{SiteAID: "Dsite", BrowserKey: key, FrontEnd: fe}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.InstalledApps.List()); n != 0 {
		t.Fatalf("a browser's sign-in was kept as an installed app's: %d", n)
	}
	undo, err := h.recordInstalledAppSignIn(rel, &ChallengeBundle{SiteAID: "Dsite", BrowserKey: key, FrontEnd: FrontEndInstalledApp, CallbackURL: "https://x.example/api/login/callback"})
	if err != nil {
		t.Fatal(err)
	}
	got := h.InstalledApps.List()
	if len(got) != 1 || got[0].EndBase != "https://x.example/api/login" {
		t.Fatalf("%+v", got)
	}
	undo()
	if n := len(h.InstalledApps.List()); n != 0 {
		t.Fatal("a sign-in the host refused stayed on the list")
	}
}
