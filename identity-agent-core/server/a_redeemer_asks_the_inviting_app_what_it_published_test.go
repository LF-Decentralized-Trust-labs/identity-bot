package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// A stand-in for an app that issues invites. It records the key the redeem was
// made with and then answers a poll the way a real one must: only for a request
// signed by that key, over this invite, with a current clock.
type anInvitingApp struct {
	*httptest.Server
	mu        sync.Mutex
	key       string
	published string // "" until it has something
	polls     int
	refuse    int // when non-zero, answer every poll with this status
	namesPath bool
	nonces    []string
}

func newInvitingApp(t *testing.T) *anInvitingApp {
	t.Helper()
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	a := &anInvitingApp{namesPath: true}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/redeem"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			a.key = b["public_key"]
			answer := map[string]any{"status": "accepted"}
			if a.namesPath {
				answer["published_at"] = "/some/app/own/path/tok/ready"
			}
			_ = json.NewEncoder(w).Encode(answer)
		case strings.HasPrefix(r.URL.Path, "/some/app/own/path/"):
			a.polls++
			if a.refuse != 0 {
				http.Error(w, "refused on purpose", a.refuse)
				return
			}
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			token := parts[len(parts)-2]
			nonce, err := VerifyInvitePoll(r, token, a.key, time.Now())
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			a.nonces = append(a.nonces, nonce)
			if a.published == "" {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"ready":false}`))
				return
			}
			_, _ = w.Write([]byte(a.published))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func askWhatWasPublished(s *CoreServer, token string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	s.mountRedeemedInviteRoutes(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/redeemed-invites/published",
		strings.NewReader(`{"invite_token":"`+token+`"}`)))
	return w
}

func redeemedAgent(t *testing.T, app *anInvitingApp) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t)
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	if err := signOrgRedeemFor(t, s, app.URL); err != nil {
		t.Fatalf("redeem failed: %v", err)
	}
	return s
}

// The redeemer waits, then receives exactly what the inviting app published.
// Fails before this change: there is no route, and the inviting app would have
// to be scanned a second time.
func TestAnInviteRedeemedHereCanAskWhatItsAppPublished(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)

	w := askWhatWasPublished(s, "tok")
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"ready":false`) {
		t.Fatalf("before anything is published: %d %s", w.Code, w.Body)
	}
	app.mu.Lock()
	app.published = `{"agent_url":"https://box.example","adoption_code":"ABCD-1234"}`
	app.mu.Unlock()

	w = askWhatWasPublished(s, "tok")
	var got struct {
		Ready     bool              `json:"ready"`
		Published map[string]string `json:"published"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || !got.Ready || got.Published["agent_url"] != "https://box.example" ||
		got.Published["adoption_code"] != "ABCD-1234" {
		t.Fatalf("after it published: %d %s", w.Code, w.Body)
	}
}

// The poll is signed by the key the redeem handed over: the inviting app, which
// checks it against that key alone, accepts it. If the poll were signed by any
// other key the stand-in would answer 403 and the first test would fail; this
// one states the check on its own.
func TestThePollIsSignedByTheKeyTheRedeemUsed(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)
	if app.key == "" {
		t.Fatal("the redeem carried no key to check a poll against")
	}
	if w := askWhatWasPublished(s, "tok"); w.Code == http.StatusForbidden {
		t.Fatalf("the inviting app did not recognise the poll's signature: %s", w.Body)
	}
}

// An invite this agent never redeemed is not asked about, and nothing is sent:
// the route cannot be used to make this agent sign a request to anywhere.
func TestAnInviteNotRedeemedHereIsNotAskedAbout(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)
	before := app.polls

	if w := askWhatWasPublished(s, "some-other-token"); w.Code != http.StatusNotFound {
		t.Fatalf("an invite never redeemed here: %d", w.Code)
	}
	if app.polls != before {
		t.Fatal("a request was signed and sent for an invite this agent never redeemed")
	}
}

// What the invite was redeemed at is remembered at the redeem and expires with
// it: past the memory, the route forgets the invite and sends nothing.
func TestARedeemedInviteIsForgottenAfterItsWindow(t *testing.T) {
	var b redeemedInviteBook
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	b.remember("tok", redeemedInvite{base: "https://app.example", siteAID: "EORG"})
	if _, ok := b.recall("tok"); !ok {
		t.Fatal("forgotten at once")
	}
	now = now.Add(redeemedInviteMemory + time.Second)
	if _, ok := b.recall("tok"); ok {
		t.Fatal("an invite redeemed long ago is still remembered")
	}
}

// The inviting app's refusal reaches the caller with its reason, rather than
// being turned into "not ready" that the caller would poll on for ever.
func TestTheInvitingAppsRefusalIsPassedOn(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusGone} {
		app := newInvitingApp(t)
		s := redeemedAgent(t, app)
		app.mu.Lock()
		app.refuse = code
		app.mu.Unlock()
		w := askWhatWasPublished(s, "tok")
		if w.Code != code || !strings.Contains(w.Body.String(), "refused on purpose") {
			t.Fatalf("a %d from the inviting app reached the caller as %d %q", code, w.Code, w.Body)
		}
	}
}

// The redeem's result tells the caller which invite to ask about and carries the
// identity it minted for a machine.
func TestTheRedeemNamesTheInviteAndTheIdentityMintedForAMachine(t *testing.T) {
	app := newInvitingApp(t)
	s := agentWithDerivedIdentity(t)
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	ask, _ := json.Marshal(signerPayload{OrgName: "X", OrgAID: "EORGAID", SiteAID: "EORGAID", InviteToken: "tok"})
	res, err := addSignerAsk{}.Execute(s, AskContext{Base: app.URL, Token: "tok", AskBytes: ask, T: 4}, ScanDecision{Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	if res["invite_token"] != "tok" || res["invited_by"] != app.URL {
		t.Fatalf("redeem result does not name the invite and its app: %v", res)
	}
	// Empty where no keri driver is present (as here); the caller treats that as
	// "no identity to claim a machine with" and says so.
	if _, present := res["machine_owner_aid"]; !present {
		t.Fatalf("redeem result has no machine_owner_aid field: %v", res)
	}
}

// Every ask carries a nonce of its own, so one captured in transit cannot be sent
// again as though it were fresh.
func TestEveryPollCarriesANonceOfItsOwn(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)
	askWhatWasPublished(s, "tok")
	askWhatWasPublished(s, "tok")
	if len(app.nonces) != 2 || app.nonces[0] == app.nonces[1] || app.nonces[0] == "" {
		t.Fatalf("nonces seen by the inviting app: %q", app.nonces)
	}
}

// The path is the inviting app's to name. An app that names none is not polled at
// all, and one that names a path that could leave its own address is treated as
// naming none.
func TestAnAppThatNamesNoPathIsNotPolled(t *testing.T) {
	app := newInvitingApp(t)
	app.namesPath = false
	s := redeemedAgent(t, app)
	if w := askWhatWasPublished(s, "tok"); w.Code != http.StatusNotFound || app.polls != 0 {
		t.Fatalf("an app that publishes nothing: %d, %d polls", w.Code, app.polls)
	}
	for _, bad := range []string{"https://elsewhere.example/x", "//elsewhere.example/x", "/a/../b", "/a?x=1", "relative/path", "/a#f", ""} {
		if got := publishedPathFrom([]byte(`{"published_at":"` + bad + `"}`)); got != "" {
			t.Errorf("published_at %q was accepted as %q", bad, got)
		}
	}
	if got := publishedPathFrom([]byte(`{"published_at":"/api/x/abc/ready"}`)); got != "/api/x/abc/ready" {
		t.Errorf("a plain path was refused: %q", got)
	}
}

// An overlay's own route is owner-only unless the overlay declares it open, and
// declaring it is checked through the real gate, not a bare router: a forwarded
// request from a stranger reaches the handler of the declared route and none
// other.
func TestAnOverlayRouteIsOpenOnlyWhenTheOverlayDeclaresIt(t *testing.T) {
	for _, declare := range []bool{false, true} {
		s := agentWithDerivedIdentity(t)
		s.MountExtraRoutes(func(r chi.Router) {
			r.Get("/theirs/{token}/ready", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
			r.Get("/theirs/{token}/other", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
		})
		if declare {
			s.OpenExtraRoutes(map[string]string{"GET /api/theirs/{token}/ready": "the redeemer polls"})
		}
		get := func(path string) int {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "203.0.113.9:5000"
			req.Header.Set("X-Forwarded-For", "203.0.113.9")
			w := httptest.NewRecorder()
			s.buildRouter().ServeHTTP(w, req)
			return w.Code
		}
		want := http.StatusForbidden
		if declare {
			want = http.StatusAccepted
		}
		if got := get("/api/theirs/abc/ready"); got != want {
			t.Errorf("declared=%v: stranger got %d, want %d", declare, got, want)
		}
		if got := get("/api/theirs/abc/other"); got != http.StatusForbidden {
			t.Errorf("declared=%v: an undeclared overlay route answered a stranger with %d", declare, got)
		}
	}
	s := agentWithDerivedIdentity(t)
	s.OpenExtraRoutes(map[string]string{"GET /api/nothing/mounts/this": "x"})
	if len(s.extraOpenNotMounted()) != 1 {
		t.Error("an entry no overlay mounts was not reported")
	}
}
