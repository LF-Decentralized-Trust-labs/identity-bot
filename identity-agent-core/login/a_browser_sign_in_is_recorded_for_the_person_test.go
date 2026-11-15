package login

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func aBrowserRecordHandler(t *testing.T) *Handler {
	t.Helper()
	h := &Handler{}
	var err error
	if h.BrowserSignIns, err = NewBrowserSignInStore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if h.InstalledApps, err = NewInstalledAppSignInStore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAPersonsBrowserSignInIsRecordedForThemAndNotAsAnInstalledApp(t *testing.T) {
	h := aBrowserRecordHandler(t)
	rel := &SiteRelationship{PairwiseAID: "Dperson"}
	for _, fe := range []string{FrontEndInstalledApp, ""} { // neither is a browser's
		if _, err := h.recordBrowserSignIn(rel, &ChallengeBundle{SiteAID: "Dsite", BrowserKey: aTestKey, FrontEnd: fe}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.BrowserSignIns.List()); n != 0 {
		t.Fatalf("a sign-in that is not a browser's was kept as one: %d", n)
	}
	undo, err := h.recordBrowserSignIn(rel, &ChallengeBundle{SiteAID: "Dsite", BrowserKey: aTestKey, FrontEnd: FrontEndBrowser})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.HandleBrowserSignIns(w, httptest.NewRequest("GET", "/login/browser-sign-ins", nil))
	if !strings.Contains(w.Body.String(), aTestKey) || !strings.Contains(w.Body.String(), "Dsite") {
		t.Fatalf("the person's list does not show it: %s", w.Body.String())
	}
	if n := len(h.InstalledApps.List()); n != 0 {
		t.Fatal("a browser's sign-in reached the installed-app list")
	}
	undo()
	if n := len(h.BrowserSignIns.List()); n != 0 {
		t.Fatal("a sign-in the app refused stayed on the list")
	}
}

func TestAPersonClearsALineFromTheirBrowserRecord(t *testing.T) {
	h := aBrowserRecordHandler(t)
	_, _ = h.recordBrowserSignIn(&SiteRelationship{PairwiseAID: "Dp"}, &ChallengeBundle{SiteAID: "Dsite", BrowserKey: aTestKey, FrontEnd: FrontEndBrowser})
	w := httptest.NewRecorder()
	h.HandleForgetBrowserSignIn(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"site_aid":"Dsite","key":"`+aTestKey+`"}`)))
	if w.Code != 200 || len(h.BrowserSignIns.List()) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.HandleForgetBrowserSignIn(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"site_aid":"Dsite","key":"short"}`)))
	if w.Code != 400 {
		t.Fatalf("a bad key was accepted: %d", w.Code)
	}
}

func TestTheBrowserRecordKeepsOnlyTheMostRecentApprovals(t *testing.T) {
	s, err := NewBrowserSignInStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	for i := 0; i < MaxBrowserSignIns+5; i++ {
		_ = s.Put(InstalledAppSignIn{SiteAID: "D" + strings.Repeat("x", i), Key: aTestKey, ApprovedAt: base.Add(time.Duration(i) * time.Second)})
	}
	got := s.List()
	if len(got) != MaxBrowserSignIns {
		t.Fatalf("kept %d", len(got))
	}
	if _, ok := s.Get("D", aTestKey); ok {
		t.Fatal("the oldest approval was kept over a newer one")
	}
}
