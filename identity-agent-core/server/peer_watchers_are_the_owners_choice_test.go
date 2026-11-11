package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// Failed before: every accepted contact on an always-on agent was a peer.
func TestOnlyContactsTheOwnerChoseAreAskedAboutAnIdentity(t *testing.T) {
	s := watcherAgent(t, "EAID", 1, "Edigest")
	s.DeclaredEntityType = "individual"
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ds.Close() })
	s.DataStore = ds
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(ds.DB()), ds, nil, witness.BackendDesktop)
	for _, aid := range []string{"EOne", "ETwo", "EThree"} {
		if err := s.DataStore.SaveContact(store.ContactRecord{
			AID: aid, Status: "accepted", OobiURL: "https://" + strings.ToLower(aid) + ".example/public/oobi/" + aid,
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{
			ContactAID: aid, BackendType: witness.BackendDesktop, EntityType: "individual",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.peerWatchers(); len(got) != 0 {
		t.Fatalf("with nothing chosen, contacts were peers: %+v", got)
	}
	if err := s.WatcherService.SetChosenPeers([]string{"ETwo"}); err != nil {
		t.Fatal(err)
	}
	got := s.peerWatchers()
	if len(got) != 1 || got[0].AID != "ETwo" {
		t.Fatalf("expected only the chosen contact, got %+v", got)
	}
}

// Failed before: /public/kel-digest and /public/kel-check answered anyone with
// what this agent had seen of any identity it held, at 60 and 20 a minute.
func TestAStrangerGetsNothingFromEitherPublicRoute(t *testing.T) {
	s := watcherAgent(t, "EAID", 1, "Edigest")
	s.WatcherService.SignDigest = func(stmt string) (string, string, error) { return "Ewatcher", "sig", nil }
	router := s.buildRouter()
	get := func(method, path, body string) string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, remote(method, path, body))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	const digestPath = "/public/kel-digest?aid=EAID&seq=1"
	never := get("GET", "/public/kel-digest?aid=ENever&seq=1", "")
	if got := strings.ReplaceAll(get("GET", digestPath, ""), "EAID", "ENever"); got != never || strings.Contains(got, "Edigest") {
		t.Fatalf("an agent that is not a public watcher service answered about an identity it holds:\n%s", got)
	}
	// A stranger's cross-check is one answer whatever it sends, a right digest included.
	for _, body := range []string{
		`{"aid":"EAID","seq":1,"digest":"Edigest"}`,
		`{"aid":"EAID","seq":1,"digest":"Edigest","requester":"EAnybody","at":1,"signature":"x"}`,
	} {
		if got := get("POST", "/public/kel-check", body); got != `{"match":false}`+"\n" && got != `{"match":false}` {
			t.Fatalf("a stranger was answered %q", got)
		}
	}
	// Opted in as a public watcher service, the digest is given and kel-check stays closed.
	if err := s.WatcherService.Store.SetConfig("public_watcher_service", "true"); err != nil {
		t.Fatal(err)
	}
	if got := get("GET", digestPath, ""); !strings.Contains(got, "Edigest") {
		t.Fatalf("an opted-in public watcher service did not answer: %s", got)
	}
	if got := get("POST", "/public/kel-check", `{"aid":"EAID","seq":1,"digest":"Edigest"}`); !strings.Contains(got, `"match":false`) {
		t.Fatalf("being a public watcher service opened the cross-check to strangers: %s", got)
	}
}

// Failed before: kel-check shared one 600-a-minute cap across everybody, so
// about thirty addresses could shut every peer out.
func TestStrangersShareACapAndContactsAreNotCountedInIt(t *testing.T) {
	s := watcherAgent(t, "EAID", 1, "Edigest")
	withAContactWhoMetEAIDAt(s)
	router := s.buildRouter()
	post := func(ip, body string) int {
		req := remote("POST", "/public/kel-check", body)
		req.RemoteAddr = ip + ":4000"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	const stranger = `{"aid":"EAID","seq":1,"digest":"Eguess"}`
	// One caller: 20 a minute.
	for i := 0; i < 20; i++ {
		if code := post("203.0.113.7", stranger); code != http.StatusOK {
			t.Fatalf("request %d refused with %d", i, code)
		}
	}
	if code := post("203.0.113.7", stranger); code != http.StatusTooManyRequests {
		t.Fatalf("21st request from one caller got %d, expected 429", code)
	}
	// Many callers: 600 in all, however they are spread.
	n := 20 // already counted above
	for i := 0; n < 600; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/200, i%200+1)
		for j := 0; j < 20 && n < 600; j++ {
			if code := post(ip, stranger); code != http.StatusOK {
				t.Fatalf("stranger %s request %d refused with %d before the shared cap, at %d", ip, j, code, n)
			}
			n++
		}
	}
	if code := post("192.0.2.77", stranger); code != http.StatusTooManyRequests {
		t.Fatalf("a new stranger past the shared cap got %d, expected 429", code)
	}
	// A contact is not shut out by them.
	at := time.Now().Unix()
	signed := fmt.Sprintf(`{"aid":"EAID","seq":1,"digest":"Edigest","requester":"EContact","at":%d,"signature":"sig"}`, at)
	if code := post("192.0.2.88", signed); code != http.StatusOK {
		t.Fatalf("a contact was refused with %d because strangers used up the cap", code)
	}
}

// A request that came through a relay is counted as the visitor the relay named,
// not as the relay, which would make every caller through it one caller.
func TestRelayedCallersAreCountedByVisitor(t *testing.T) {
	a := httptest.NewRequest("POST", "/public/kel-check", nil)
	a.RemoteAddr = "10.0.0.1:1"
	if got := callerKey(a); got != "10.0.0.1" {
		t.Fatalf("direct caller counted as %q", got)
	}
	for _, c := range []struct{ visitor, want string }{
		{"203.0.113.5", "relayed 203.0.113.5"},
		{"2001:db8:1:2:3:4:5:6", "relayed 2001:db8:1:2::/64"},
		{"", "relayed, address unknown"},
		{"not an address", "relayed, address unknown"},
	} {
		r := httptest.NewRequest("POST", "/public/kel-check", nil)
		r.RemoteAddr = "10.0.0.1:1"
		r = r.WithContext(relayproto.ContextWithPreamble(r.Context(), relayproto.Preamble{Visitor: c.visitor}))
		if got := callerKey(r); got != c.want {
			t.Errorf("visitor %q counted as %q, want %q", c.visitor, got, c.want)
		}
	}
}

// The owner chooses the contacts through the route, and only the owner.
func TestTheOwnerChoosesWhichContactsTheWatcherAsks(t *testing.T) {
	s := watcherAgent(t, "EAID", 1, "Edigest")
	for _, aid := range []string{"EOne", "ETwo", "EThree", "EFour", "EFive", "ESix"} {
		if err := s.DataStore.SaveContact(store.ContactRecord{AID: aid, Status: "accepted"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: "EPending", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	router := s.buildRouter()
	serve := func(m, p, b string, own bool) (int, string) {
		req := remote(m, p, b)
		if own {
			req = local(m, p, b)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	for _, m := range []string{"GET", "PUT"} {
		if code, _ := serve(m, "/api/watcher/peers", `{"aids":["EOne"]}`, false); code != 401 && code != 403 {
			t.Fatalf("a stranger reached %s /api/watcher/peers: %d", m, code)
		}
	}
	if _, body := serve("GET", "/api/watcher/peers", "", true); !strings.Contains(body, `"aids":[]`) || !strings.Contains(body, `"max":5`) {
		t.Fatalf("nothing chosen should read as empty with the limit: %s", body)
	}
	if code, body := serve("PUT", "/api/watcher/peers", `{"aids":["EOne","ETwo","EOne"]}`, true); code != 200 {
		t.Fatalf("owner could not choose: %d %s", code, body)
	}
	if got := s.WatcherService.ChosenPeers(); len(got) != 2 || got[0] != "EOne" || got[1] != "ETwo" {
		t.Fatalf("chosen = %v", got)
	}
	if _, body := serve("GET", "/api/watcher/peers", "", true); !strings.Contains(body, `"EOne","ETwo"`) {
		t.Fatalf("not reported: %s", body)
	}
	for name, body := range map[string]string{
		"more than five":   `{"aids":["EOne","ETwo","EThree","EFour","EFive","ESix"]}`,
		"not a contact":    `{"aids":["EStranger"]}`,
		"not yet accepted": `{"aids":["EPending"]}`,
		"no list at all":   `{}`,
		"not a list":       `{"aids":"EOne"}`,
	} {
		if code, _ := serve("PUT", "/api/watcher/peers", body, true); code != 400 {
			t.Errorf("%s: answered %d, want 400", name, code)
		}
	}
	if got := s.WatcherService.ChosenPeers(); len(got) != 2 {
		t.Fatalf("a refused choice changed what was chosen: %v", got)
	}
	if code, _ := serve("PUT", "/api/watcher/peers", `{"aids":[]}`, true); code != 200 || len(s.WatcherService.ChosenPeers()) != 0 {
		t.Fatal("the owner could not clear the choice")
	}
}
