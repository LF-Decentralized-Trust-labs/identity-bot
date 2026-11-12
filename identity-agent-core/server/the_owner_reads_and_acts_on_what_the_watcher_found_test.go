package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/store"
	"identity-agent-core/watcher"
)

// aWatchedAgent has an alert about forkedAID, a check kept for it, and a
// stranger and the owner who can each call the routes.
func aWatchedAgent(t *testing.T, forkedAID string) (serve func(method, path, body string, owner bool) (int, string)) {
	t.Helper()
	s := watcherAgent(t, forkedAID, 3, "Eours")
	if _, err := s.WatcherService.Store.InsertDuplicityAlert(watcher.DuplicityAlert{
		AID: forkedAID, SequenceNum: 3, OurDigest: "Eours", TheirDigest: "Etheirs",
	}); err != nil {
		t.Fatal(err)
	}
	res := &watcher.VerifyKelResult{AID: forkedAID, Blocked: true, Reason: "L1 digest mismatch at same sequence"}
	if err := s.WatcherService.RecordCheck(res); err != nil {
		t.Fatal(err)
	}
	router := s.buildRouter()
	return func(m, p, b string, own bool) (int, string) {
		req := remote(m, p, b)
		if own {
			req = local(m, p, b)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
}

// The case that would have failed before: there was no route to read an alert,
// so a person had no way to learn that a contact's key history had forked.
func TestOwnerListsAcknowledgesAndResolvesAnAlert(t *testing.T) {
	const aid = "EForkedContact"
	serve := aWatchedAgent(t, aid)

	if code, _ := serve("GET", "/api/watcher/alerts", "", false); code != 401 && code != 403 {
		t.Fatalf("a stranger read the alerts: %d", code)
	}
	code, body := serve("GET", "/api/watcher/alerts?open=true", "", true)
	if code != 200 || !strings.Contains(body, aid) {
		t.Fatalf("the owner did not see the alert: %d %s", code, body)
	}
	if strings.Contains(body, "Eours") || strings.Contains(body, "Etheirs") {
		t.Fatalf("an alert carried a digest: %s", body)
	}
	var list struct {
		Alerts []struct {
			ID           int64 `json:"id"`
			Acknowledged bool  `json:"acknowledged"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list.Alerts) != 1 || list.Alerts[0].Acknowledged {
		t.Fatalf("unexpected list: %s", body)
	}
	id := list.Alerts[0].ID
	ack := "/api/watcher/alerts/" + strconv.FormatInt(id, 10) + "/acknowledge"
	res := "/api/watcher/alerts/" + strconv.FormatInt(id, 10) + "/resolve"

	if code, _ := serve("POST", ack, "", false); code != 401 && code != 403 {
		t.Fatalf("a stranger acknowledged an alert: %d", code)
	}
	if code, body := serve("POST", ack, "", true); code != 200 {
		t.Fatalf("acknowledge: %d %s", code, body)
	}
	if _, body := serve("GET", "/api/watcher/alerts?aid="+aid, "", true); !strings.Contains(body, `"acknowledged":true`) || !strings.Contains(body, `"resolved":false`) {
		t.Fatalf("acknowledging must not resolve: %s", body)
	}
	if code, _ := serve("POST", res, `{"note":"  "}`, true); code != 400 {
		t.Fatalf("an alert was closed with no reason: %d", code)
	}
	if code, body := serve("POST", res, `{"note":"They told me they re-founded the key log."}`, true); code != 200 {
		t.Fatalf("resolve: %d %s", code, body)
	}
	if _, body := serve("GET", "/api/watcher/alerts?open=true", "", true); strings.Contains(body, aid) {
		t.Fatalf("a resolved alert is still open: %s", body)
	}
	if _, body := serve("GET", "/api/watcher/alerts", "", true); !strings.Contains(body, "re-founded") {
		t.Fatalf("a resolved alert must be kept as a record: %s", body)
	}
	if code, _ := serve("POST", "/api/watcher/alerts/9999/acknowledge", "", true); code != 404 {
		t.Fatalf("an unknown alert: %d", code)
	}
}

// An identity the owner opted out is answered as one never seen, in every new read.
func TestAnOptedOutIdentityShowsNoAlertAndNoCheckAndCannotBeActedOn(t *testing.T) {
	const aid = "EOptedOutFork"
	serve := aWatchedAgent(t, aid)
	if code, _ := serve("PUT", "/api/watcher/opt-out", `{"aid":"`+aid+`","opted_out":true}`, true); code != 200 {
		t.Fatal("could not opt out")
	}
	if _, body := serve("GET", "/api/watcher/alerts", "", true); strings.Contains(body, aid) {
		t.Fatalf("alert shown for an opted-out identity: %s", body)
	}
	if code, _ := serve("GET", "/api/watcher/checks/"+aid, "", true); code != 404 {
		t.Fatalf("check shown for an opted-out identity: %d", code)
	}
	if _, body := serve("GET", "/api/watcher/checks", "", true); strings.Contains(body, aid) {
		t.Fatalf("check listed for an opted-out identity: %s", body)
	}
	if code, _ := serve("POST", "/api/watcher/alerts/1/acknowledge", "", true); code != 404 {
		t.Fatalf("an opted-out identity's alert could be acknowledged, which says it exists: %d", code)
	}
}

func TestTheLastCheckOfAContactIsKeptAndUncheckedIsNotConfirmed(t *testing.T) {
	const aid = "EForkedContact"
	serve := aWatchedAgent(t, aid)
	code, body := serve("GET", "/api/watcher/checks/"+aid, "", true)
	if code != 200 || !strings.Contains(body, `"verdict":"duplicity"`) {
		t.Fatalf("the check was not kept: %d %s", code, body)
	}
	if code, _ := serve("GET", "/api/watcher/checks/ENeverChecked", "", true); code != 404 {
		t.Fatalf("a contact never checked must read as not checked, got %d", code)
	}
}

func TestTheOwnerSetsTheTrustedWatchersAndStatusSaysSo(t *testing.T) {
	serve := aWatchedAgent(t, "EForkedContact")
	_, body := serve("GET", "/api/watcher/status", "", true)
	if !strings.Contains(body, `"state":"own_record_only"`) || !strings.Contains(body, `"open_alerts":1`) {
		t.Fatalf("with no trusted watcher the status must say only its own record is used: %s", body)
	}
	if code, _ := serve("PUT", "/api/watcher/trusted", `{"aids":["not-a-watcher"]}`, true); code != 400 {
		t.Fatalf("a malformed watcher was stored: %d", code)
	}
	if code, _ := serve("PUT", "/api/watcher/trusted", `{"aids":[]}`, false); code != 401 && code != 403 {
		t.Fatalf("a stranger set the trusted list: %d", code)
	}
	if code, _ := serve("PUT", "/api/watcher/trusted", `{"aids":[]}`, true); code != 200 {
		t.Fatal("the owner could not clear the list")
	}
	if code, _ := serve("PUT", "/api/watcher/hints", `{"urls":["http://insecure.example"]}`, true); code != 400 {
		t.Fatalf("a plain-http hint was stored: %d", code)
	}
	if code, body := serve("PUT", "/api/watcher/hints", `{"urls":["https://w.example/a"]}`, true); code != 200 || !strings.Contains(body, "w.example") {
		t.Fatalf("hints: %d %s", code, body)
	}
	if _, body := serve("GET", "/api/watcher/hints", "", true); !strings.Contains(body, "w.example") {
		t.Fatalf("hints not kept: %s", body)
	}
}

func TestAnAgentWithNoWatcherSaysItIsOffAndNotThatNothingWasFound(t *testing.T) {
	s := newAuthTestServer(t)
	s.WatcherService = nil
	router := s.buildRouter()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, local("GET", "/api/watcher/status", ""))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"state":"off"`) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, local("GET", "/api/watcher/alerts", ""))
	if rec.Code != 404 {
		t.Fatalf("an off watcher answered an alert list as if there were none: %d", rec.Code)
	}
}

// A digest this agent holds from a log that proved nothing refuses nobody: it
// could have been planted by whoever showed it. (A proven fork refusing on this
// route is TestAProvenForkStopsOobiResolveAndAddContact.)
func TestAddContactIsNotRefusedOnADigestFromALogThatProvedNothing(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	// A numbered log, as the watcher reads one; the test logs of the other
	// intake tests carry no sequence numbers and are refused as unreadable.
	const aid = "EForkedByNumber0000000000000000000000000000"
	kel := []map[string]interface{}{}
	for i := 0; i < 3; i++ {
		kel = append(kel, map[string]interface{}{
			"v": "KERI10JSON000160_", "t": map[bool]string{true: "icp", false: "ixn"}[i == 0],
			"i": aid, "s": strconv.FormatInt(int64(i), 16), "d": "Eevent-" + strconv.Itoa(i),
		})
	}
	s := witnessWithSeed(t, 7)
	s.KeriDriver = anEngineThatVerifies("Dkey", len(kel))
	ws := watcher.NewService(watcher.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()))
	if err := ws.Store.SetConfig("default_l2_url", "http://127.0.0.1:1/public/kel-digest"); err != nil {
		t.Fatal(err)
	}
	s.WatcherService = ws
	// This agent was shown a different log at the sequence the fork reaches.
	if err := ws.RecordFirstSeen(aid, 2, "Eadifferentlog", watcher.SourceOOBI, "http://test/oobi"); err != nil {
		t.Fatal(err)
	}
	srv := aPeerServing(t, aid, "Dkey", kel)

	body, _ := json.Marshal(map[string]interface{}{"oobi_url": srv.URL + "/oobi/" + aid, "alias": "x"})
	rec := httptest.NewRecorder()
	s.handleAddContact(rec, httptest.NewRequest("POST", "/api/contacts", strings.NewReader(string(body))))
	if rec.Code == 409 {
		t.Fatalf("refused on a digest that proves nothing: %s", rec.Body.String())
	}
	if open, _ := ws.DisclosableAlerts(aid); len(open) != 0 {
		t.Fatalf("a duplicity alert was raised without proof: %+v", open)
	}
}

func TestResolvingAnAlertASecondTimeIsRefusedAndKeepsTheFirstNote(t *testing.T) {
	serve := aWatchedAgent(t, "EForkedContact")
	_, body := serve("GET", "/api/watcher/alerts", "", true)
	var list struct{ Alerts []struct{ ID int64 } }
	_ = json.Unmarshal([]byte(body), &list)
	res := "/api/watcher/alerts/" + strconv.FormatInt(list.Alerts[0].ID, 10) + "/resolve"
	if code, _ := serve("POST", res, `{"note":"first"}`, true); code != 200 {
		t.Fatal("first resolve failed")
	}
	code, body := serve("POST", res, `{"note":"second"}`, true)
	if code != 409 || !strings.Contains(body, `"code":"already_resolved"`) {
		t.Fatalf("second resolve: %d %s", code, body)
	}
	if _, body := serve("GET", "/api/watcher/alerts", "", true); !strings.Contains(body, "first") || strings.Contains(body, "second") {
		t.Fatalf("the audit note changed: %s", body)
	}
}

func TestOffAndNeverCheckedCarryDifferentCodes(t *testing.T) {
	serve := aWatchedAgent(t, "EForkedContact")
	if code, body := serve("GET", "/api/watcher/checks/ENever", "", true); code != 404 || !strings.Contains(body, `"code":"never_checked"`) {
		t.Fatalf("never checked: %d %s", code, body)
	}
	s := newAuthTestServer(t)
	s.WatcherService = nil
	rec := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(rec, local("GET", "/api/watcher/alerts", ""))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"code":"watcher_off"`) {
		t.Fatalf("off: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAContactNamesAtMostThreeDistinctWatchers(t *testing.T) {
	got := cappedWatcherHints([]string{"https://a.example", "https://a.example", "", "http://plain.example",
		"https://b.example", "https://c.example", "https://d.example", "https://e.example"})
	if strings.Join(got, ",") != "https://a.example,https://b.example,https://c.example" {
		t.Fatalf("%v", got)
	}
}

// countingTransport records which hosts were asked and answers none of them.
type countingTransport struct {
	mu    sync.Mutex
	hosts map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts[r.URL.Host]++
	c.mu.Unlock()
	return nil, errors.New("nobody answers")
}

// Where the cap is used: a contact that names more than three watchers, some
// of them plain http, gets at most three queried, all of them https.
// Fails when runWatcherOnKel stops passing its hints through cappedWatcherHints.
func TestAddingAContactQueriesAtMostThreeOfTheWatchersItNames(t *testing.T) {
	s := watcherAgent(t, "EOther", 1, "Ed")
	tr := &countingTransport{hosts: map[string]int{}}
	s.WatcherService.L2 = &watcher.L2Client{HTTPClient: &http.Client{Transport: tr}}
	kel := []map[string]interface{}{{"v": "KERI10JSON000160_", "t": "icp", "i": "ENamer", "s": "0", "d": "Eevent-0"}}
	res := s.runWatcherOnKel(context.Background(), "ENamer", kel, watcher.SourceOOBI, "https://x.example/oobi", []string{
		"http://plain.example", "https://h1.example", "https://h2.example", "https://h1.example",
		"https://h3.example", "https://h4.example", "https://h5.example"})
	if res == nil {
		t.Fatal("no result")
	}
	asked := 0
	for host, n := range tr.hosts {
		if strings.HasPrefix(host, "h") && strings.HasSuffix(host, ".example") {
			asked += n
		}
		if host == "plain.example" {
			t.Fatal("a plain http watcher named by a contact was queried")
		}
	}
	if asked != 3 || tr.hosts["h4.example"] != 0 || tr.hosts["h5.example"] != 0 {
		t.Fatalf("hosts asked: %v", tr.hosts)
	}
}

// The alerts show their kind and status counts the kinds apart, so an
// escalation never reads as a blocked contact.
func TestAlertsShowTheirKindAndStatusCountsKindsSeparately(t *testing.T) {
	s := watcherAgent(t, "EForkedContact", 3, "Eours")
	st := s.WatcherService.Store
	_, _ = st.InsertDuplicityAlert(watcher.DuplicityAlert{AID: "EForkedContact", SequenceNum: 3, OurDigest: "Eours", TheirDigest: "x"})
	_, _ = st.InsertDuplicityAlert(watcher.DuplicityAlert{AID: "EPeerSaid", SequenceNum: 1, OurDigest: "a", Kind: watcher.AlertKindEscalation})
	router := s.buildRouter()
	get := func(p string) string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, local("GET", p, ""))
		return rec.Body.String()
	}
	status := get("/api/watcher/status")
	if !strings.Contains(status, `"open_alerts":1`) || !strings.Contains(status, `"open_escalations":1`) {
		t.Fatalf("status: %s", status)
	}
	list := get("/api/watcher/alerts")
	if !strings.Contains(list, `"kind":"duplicity"`) || !strings.Contains(list, `"kind":"escalation"`) {
		t.Fatalf("alerts: %s", list)
	}
}
