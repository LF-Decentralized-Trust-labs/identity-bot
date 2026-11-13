package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/secureenclave"
)

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

// A host that lies in /begin about what is to be signed.
type aFakeEndHost struct {
	srv      *httptest.Server
	ask      map[string]string
	endPosts int32
}

func anEndHost(t *testing.T, ask map[string]string) *aFakeEndHost {
	t.Helper()
	f := &aFakeEndHost{ask: ask}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/app-key/end/begin"):
			_ = json.NewEncoder(w).Encode(f.ask)
		case strings.HasSuffix(r.URL.Path, "/app-key/end"):
			atomic.AddInt32(&f.endPosts, 1)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

const aTestKey = "k8Wm0nZtVq3dYxq0yq9mY3gQp1G5mXJ0u2nq1Zk8s-A"

// aPersonWhoApprovedAnInstalledApp has a real relationship and a kept record.
func aPersonWhoApprovedAnInstalledApp(t *testing.T, endBase string, makeRelationship bool) (*Handler, InstalledAppSignIn) {
	t.Helper()
	store, err := NewRelationshipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: store, dataDir: t.TempDir(), HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	root := make([]byte, 64)
	copy(root, "testrootseedforhdderivationtestonly0000000000000000000000000000")
	if err := secureenclave.StoreDeviceLocalSeed(h.dataDir, root); err != nil {
		t.Fatal(err)
	}
	if h.InstalledApps, err = NewInstalledAppSignInStore(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if makeRelationship {
		if _, err := h.getOrCreateRelationship("EsiteAAA", &ChallengeBundle{SiteAID: "EsiteAAA"}); err != nil {
			t.Fatal(err)
		}
	}
	rec := InstalledAppSignIn{Key: aTestKey, SiteAID: "EsiteAAA", RelationshipKey: "EsiteAAA", EndBase: endBase, ApprovedAt: time.Now()}
	if err := h.InstalledApps.Put(rec); err != nil {
		t.Fatal(err)
	}
	return h, rec
}

func theHonestAsk() map[string]string {
	return map[string]string{
		"nonce": "n1", "audience": EndAppKeyAudience, "site_aid": "EsiteAAA",
		"browser_key": aTestKey, "front_end": FrontEndInstalledApp,
	}
}

func TestEndingASignInSignsNothingTheHostChoosesToName(t *testing.T) {
	for name, change := range map[string]func(map[string]string){
		"another audience":  func(a map[string]string) { a["audience"] = "https://other.example" },
		"an empty audience": func(a map[string]string) { a["audience"] = "" },
		"another site":      func(a map[string]string) { a["site_aid"] = "EsiteSIBLING" },
		"another key":       func(a map[string]string) { a["browser_key"] = "k8Wm0nZtVq3dYxq0yq9mY3gQp1G5mXJ0u2nq1Zk8s-B" },
		"another front end": func(a map[string]string) { a["front_end"] = FrontEndBrowser },
	} {
		t.Run(name, func(t *testing.T) {
			ask := theHonestAsk()
			change(ask)
			host := anEndHost(t, ask)
			h, rec := aPersonWhoApprovedAnInstalledApp(t, host.srv.URL, true)
			_, _, err := h.EndInstalledAppSignIn(rec.SiteAID, rec.Key)
			if err == nil {
				t.Fatal("a sign-in was made for what the host chose")
			}
			if n := atomic.LoadInt32(&host.endPosts); n != 0 {
				t.Fatalf("an assertion was posted to the host: %d", n)
			}
			if _, kept := h.InstalledApps.Get(rec.SiteAID, rec.Key); !kept {
				t.Fatal("the record was dropped for a host that lied")
			}
		})
	}
}

func TestEndingASignInNeverMakesARelationship(t *testing.T) {
	host := anEndHost(t, theHonestAsk())
	h, rec := aPersonWhoApprovedAnInstalledApp(t, host.srv.URL, false)
	before := h.Store.AllocateNextRelationshipIndex()
	_, status, err := h.EndInstalledAppSignIn(rec.SiteAID, rec.Key)
	if err == nil || status != http.StatusConflict {
		t.Fatalf("%d %v", status, err)
	}
	if _, made := h.Store.Get("EsiteAAA"); made || h.Store.AllocateNextRelationshipIndex() != before+1 || atomic.LoadInt32(&host.endPosts) != 0 {
		t.Fatal("ending made a relationship or posted without one")
	}
}

func TestEndingASignInThatTheHostAsksForHonestlyIsSignedForTheEndAudienceOnly(t *testing.T) {
	var got Assertion
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/app-key/end/begin") {
			_ = json.NewEncoder(w).Encode(theHonestAsk())
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	h, rec := aPersonWhoApprovedAnInstalledApp(t, srv.URL, true)
	if _, _, err := h.EndInstalledAppSignIn(rec.SiteAID, rec.Key); err != nil {
		t.Fatal(err)
	}
	if got.Audience != EndAppKeyAudience || got.Nonce != "n1" {
		t.Fatalf("signed %q / %q", got.Audience, got.Nonce)
	}
	if _, kept := h.InstalledApps.Get(rec.SiteAID, rec.Key); kept {
		t.Fatal("an ended sign-in stayed on the list")
	}
}

func TestATimeoutAfterTheHostMayHaveAcceptedKeepsTheRecordButARefusalDropsIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		handler  http.HandlerFunc
		wantKept bool
	}{
		{"timeout", func(w http.ResponseWriter, r *http.Request) { time.Sleep(400 * time.Millisecond) }, true},
		{"server error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }, true},
		{"refused", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			h, _ := aPersonWhoApprovedAnInstalledApp(t, srv.URL, true)
			_ = h.InstalledApps.Delete("EsiteAAA", aTestKey) // nothing recorded before this sign-in
			h.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
			rel, _ := h.Store.Get("EsiteAAA")
			b := &ChallengeBundle{SiteAID: "EsiteAAA", BrowserKey: aTestKey, FrontEnd: FrontEndInstalledApp,
				Audience: "https://a.example", Nonce: "n", Expiry: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), CallbackURL: srv.URL + "/api/login/callback"}
			_, err := h.completeLogin(&pendingLogin{Bundle: b, Relationship: &rel})
			if err == nil {
				t.Fatal("the sign-in did not fail")
			}
			if _, kept := h.InstalledApps.Get("EsiteAAA", aTestKey); kept != tc.wantKept {
				t.Fatalf("kept=%v, want %v", kept, tc.wantKept)
			}
		})
	}
}
