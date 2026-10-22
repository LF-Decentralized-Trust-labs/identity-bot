package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay/relaytest"
	"identity-agent-core/store"
)

// asOwner calls a route as the owner on this machine; asStranger as anybody
// else.
func asOwner(t *testing.T, s *CoreServer, method, path, body string) (int, map[string]interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, local(method, path, body))
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func asStranger(t *testing.T, s *CoreServer, method, path, body string) int {
	t.Helper()
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, remote(method, path, body))
	return w.Code
}

func relayView(t *testing.T, out map[string]interface{}) map[string]interface{} {
	t.Helper()
	if v, ok := out["relay"].(map[string]interface{}); ok {
		return v
	}
	return out
}

func waitForState(t *testing.T, s *CoreServer, state string) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, out := asOwner(t, s, "GET", "/api/settings/reachability/relay", "")
		if out["state"] == state {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay never reached %q: %v", state, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Every route here is the owner's. Somebody else is refused before anything
// happens.
func TestTheRelayRoutesAreTheOwners(t *testing.T) {
	s := newAuthTestServer(t)
	s.router = s.buildRouter("")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/settings/reachability/relay"},
		{"PUT", "/api/settings/reachability"},
		{"POST", "/api/settings/reachability/name/release"},
		{"GET", "/api/settings/reachability/domains"},
		{"POST", "/api/settings/reachability/domains"},
		{"POST", "/api/settings/reachability/domains/verify"},
	} {
		if code := asStranger(t, s, c.method, c.path, `{"domain":"id.example.org","mode":"direct"}`); code != http.StatusForbidden {
			t.Errorf("%s %s answered a stranger with %d", c.method, c.path, code)
		}
	}
}

// The status says how this Identity Agent is reached right now.
func TestTheRelayStatusSaysWhereThisIdentityAgentIsReached(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)

	out := waitForState(t, s, "active")
	if out["mode"] != "relay" || out["url"] != url {
		t.Fatalf("status: %v", out)
	}
	addrs, _ := out["addresses"].([]interface{})
	if len(addrs) != 1 || addrs[0].(map[string]interface{})["url"] != url {
		t.Fatalf("addresses: %v", out["addresses"])
	}
	if strings.Contains(string(mustJSON(t, out)), "secret") {
		t.Fatal("the status shows a private address's secret")
	}
}

// A name somebody else holds is reported as that, in plain words, and not
// retried for ever.
func TestANameSomebodyElseHoldsIsReportedPlainly(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	rl.HoldName("acme", "EOTHERIDENTITY")
	go s.startRelay()
	defer s.Stop()

	out := waitForState(t, s, "failed")
	if out["reason_code"] != "taken" || !strings.Contains(out["reason"].(string), "already held") {
		t.Fatalf("status: %v", out)
	}
	tries := rl.ClaimCount()
	time.Sleep(2500 * time.Millisecond) // longer than the first two waits between tries
	if rl.ClaimCount() != tries {
		t.Fatalf("a name somebody else holds was asked for again (%d, then %d)", tries, rl.ClaimCount())
	}
}

// A reserved name is reported as reserved.
func TestAReservedNameIsReportedPlainly(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	if err := s.DataStore.SaveSettings(store.SettingsData{PublicRelayName: "support"}); err != nil {
		t.Fatal(err)
	}
	go s.startRelay()
	defer s.Stop()
	if out := waitForState(t, s, "failed"); out["reason_code"] != "reserved" {
		t.Fatalf("status: %v", out)
	}
}

// Saving applies it: a new name is claimed without a restart, and the answer
// says what came of it.
func TestSavingReachabilityAppliesIt(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	rl.HoldName("acme", "EOTHERIDENTITY")
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "failed")

	code, out := asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":"acme-two"}`)
	v := relayView(t, out)
	if code != http.StatusOK || v["state"] != "active" || !strings.Contains(v["url"].(string), "acme-two.") {
		t.Fatalf("saving a new name: %d %v", code, out)
	}

	// And a mode with no relay stops it.
	code, out = asOwner(t, s, "PUT", "/api/settings/reachability", `{"mode":"direct"}`)
	if v := relayView(t, out); code != http.StatusOK || v["state"] != "off" {
		t.Fatalf("saving direct: %d %v", code, out)
	}
	if s.currentRelay() != nil {
		t.Fatal("the relay is still running in direct mode")
	}
}

// Releasing the public name gives it back to the relay and forgets it.
func TestThePublicNameCanBeReleased(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "active")

	code, out := asOwner(t, s, "POST", "/api/settings/reachability/name/release", "")
	if code != http.StatusOK || out["released"] != "acme" {
		t.Fatalf("release: %d %v", code, out)
	}
	if rl.Holds("acme") {
		t.Fatal("the relay still holds the name")
	}
	if st, _ := s.DataStore.GetSettings(); st != nil && st.PublicRelayName != "" {
		t.Fatal("the name is still in settings, so it would be claimed again")
	}
}

// A custom domain: asking returns the exact DNS record to add, it waits for
// it, and once the record is there it becomes an address.
func TestACustomDomainIsProvedByDNS(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "active")

	code, out := asOwner(t, s, "POST", "/api/settings/reachability/domains", `{"domain":"ID.Example.org"}`)
	if code != http.StatusOK || out["txt_name"] != "_iarelay.id.example.org" || !strings.HasPrefix(out["txt_value"].(string), "iarelay-aid=") {
		t.Fatalf("request: %d %v", code, out)
	}
	txtName, txtValue := out["txt_name"].(string), out["txt_value"].(string)

	_, out = asOwner(t, s, "GET", "/api/settings/reachability/domains", "")
	if !strings.Contains(string(mustJSON(t, out)), `"waiting_for_dns"`) {
		t.Fatalf("list before proof: %v", out)
	}
	if code, out = asOwner(t, s, "POST", "/api/settings/reachability/domains/verify", `{"domain":"id.example.org"}`); code == http.StatusOK {
		t.Fatalf("a domain was verified with no DNS record: %v", out)
	}

	rl.PublishTXT(txtName, txtValue)
	code, out = asOwner(t, s, "POST", "/api/settings/reachability/domains/verify", `{"domain":"id.example.org"}`)
	if code != http.StatusOK || out["state"] != "active" {
		t.Fatalf("verify: %d %v", code, out)
	}
	// Verifying again is harmless, and the domain is held once.
	if code, out = asOwner(t, s, "POST", "/api/settings/reachability/domains/verify", `{"domain":"id.example.org"}`); code != http.StatusOK {
		t.Fatalf("verifying again: %d %v", code, out)
	}
	_, out = asOwner(t, s, "GET", "/api/settings/reachability/domains", "")
	if j := string(mustJSON(t, out)); !strings.Contains(j, `"active"`) || strings.Contains(j, "waiting_for_dns") ||
		strings.Count(j, "id.example.org") != 2 { // the domain and its URL, once each
		t.Fatalf("list after proof: %v", out)
	}
	if rec, ok := s.publicRelayRecord(); !ok || len(rec.PendingDomains) != 0 {
		t.Fatalf("a proved domain is still recorded as waiting: %+v", rec)
	}
	// And the domain reaches this Identity Agent.
	if code, _ := through(t, rl.Caller(), "GET", "https://id.example.org/api/health", ""); code != http.StatusOK {
		t.Fatalf("the domain does not reach the Identity Agent: %d", code)
	}
}

// Switching mode while the old relay is still being reached ends the old
// one: it never comes up later, serving the old mode's address after the
// owner moved away from it.
func TestSwitchingModeEndsTheOldRelayStillStarting(t *testing.T) {
	old := relayRetryWait
	relayRetryWait = 100 * time.Millisecond
	defer func() { relayRetryWait = old }()

	s, priv, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	pub := relaytest.New(relayproto.ModePublic)
	defer pub.Close()
	t.Setenv("PUBLIC_RELAY_BASE_URL", pub.URL())
	recordedEnrolment(t, s.DataDir, publicRelay.record, pub.URL(), 5)
	pubAID := func() string {
		r, _, _ := loadRelayEnrollment(s.DataDir, publicRelay.record)
		return r.AID
	}()
	s.relayTLS = nil // two relays, two certificates: trust both through the pool below
	pool := priv.TLS()
	pool.RootCAs.AddCert(pub.Server.Certificate())
	s.relayTLS = pool
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "public", PublicRelayName: "acme"}); err != nil {
		t.Fatal(err)
	}

	pub.Down(true) // the public relay cannot be reached yet
	go s.startRelay()
	defer s.Stop()
	time.Sleep(300 * time.Millisecond)

	code, out := asOwner(t, s, "PUT", "/api/settings/reachability", `{"mode":"relay"}`)
	if v := relayView(t, out); code != http.StatusOK || v["state"] != "active" || v["mode"] != "relay" {
		t.Fatalf("switching to private: %d %v", code, out)
	}
	pub.Down(false) // the public relay comes back
	time.Sleep(1500 * time.Millisecond)
	if pub.Connected(pubAID) {
		t.Fatal("the old public relay came up after the owner switched to private")
	}
	if st := s.relayStatus(); st.Mode != "relay" || st.State != "active" {
		t.Fatalf("status after the switch: %+v", st)
	}
}

// A relay that gives up before it runs says so, instead of connecting for
// ever.
func TestARelayThatGivesUpSaysWhy(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	// A claimed machine whose seed is gone: there is no enrolment key.
	if err := os.RemoveAll(filepath.Join(s.DataDir, "secureenclave")); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: "ECLAIMEDIDENTITY"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.DataDir, relayEnrollmentFileName)); err != nil {
		t.Fatal(err)
	}
	s.startRelay()
	defer s.Stop()
	out := waitForState(t, s, "failed")
	if out["reason_code"] != "no_enrolment" {
		t.Fatalf("status: %v", out)
	}
}

// Through a relay, the address this Identity Agent learns for itself is its
// own record's, never what a caller's forwarding headers claim; and the web app
// is not served there at all, so no caller can set the page's base either.
func TestACallerThroughARelayCannotSetTheAddressOrReachThePage(t *testing.T) {
	t.Setenv("TRUST_FORWARDED_HEADERS", "1")
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	rl.KeepCallerPrefix = true
	defer cancel()
	web := t.TempDir()
	if err := os.WriteFile(filepath.Join(web, "index.html"), []byte(`<html><head><base href="/"></head></html>`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.router = s.buildRouter(web)
	go s.startRelay()
	defer s.Stop()
	url := s.waitForRelay(t)

	req, _ := http.NewRequest("GET", url+"/", nil)
	req.Header.Set("X-Forwarded-Prefix", "/evil")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := rl.Caller().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || strings.Contains(string(body[:n]), "<html") {
		t.Fatalf("the web app was served through a relay: %d %s", resp.StatusCode, body[:n])
	}
	if strings.Contains(s.EndpointService.CurrentURL(), "evil.example") {
		t.Fatalf("a caller set this Identity Agent's address: %s", s.EndpointService.CurrentURL())
	}
}

// Choosing a new public name gives the old one back, rather than leaving it
// held at the relay with nothing behind it.
func TestANewPublicNameReleasesTheOldOne(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "active")

	code, out := asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":"acme-two"}`)
	if v := relayView(t, out); code != http.StatusOK || v["state"] != "active" {
		t.Fatalf("saving a new name: %d %v", code, out)
	}
	if rl.Holds("acme") {
		t.Fatal("the old name is still held")
	}
	if !rl.Holds("acme-two") {
		t.Fatal("the new name is not held")
	}
}

// An instance that used the retired tunnel provider comes up on a public
// relay address under the name it had, and the owner is told why.
func TestTheRetiredTunnelProviderMovesToAPublicRelay(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	s.DefaultIngressMode = nil
	if err := s.DataStore.SaveSettings(store.SettingsData{TunnelProvider: "grapeid", RetiredTunnelName: "green-hawk",
		IngressMode: "tunnel"}); err != nil {
		t.Fatal(err)
	}
	s.retireTunnelHubSettings()

	st, _ := s.DataStore.GetSettings()
	if st.TunnelProvider != "none" || st.IngressMode != "public" || st.PublicRelayName != "green-hawk" || st.RetiredTunnelName != "" {
		t.Fatalf("settings after the move: %+v", st)
	}
	go s.startRelay()
	defer s.Stop()
	out := waitForState(t, s, "active")
	if !strings.Contains(out["url"].(string), "green-hawk.") || !strings.Contains(out["notice"].(string), "retired") {
		t.Fatalf("status: %v", out)
	}

	// Once the owner saves reachability, the notice has been seen.
	asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":"green-hawk"}`)
	if st, _ := s.DataStore.GetSettings(); st.ReachabilityNotice != "" {
		t.Fatal("the notice outlived the owner's choice")
	}
}

// An instance set to be reached publicly with no name to be reached at is told
// so in plain words, in both status endpoints, and the relay says the same.
// A product can make public the default before the owner has chosen a name.
func TestAPublicAddressWithNoNameTellsTheOwner(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "public"}); err != nil {
		t.Fatal(err)
	}
	s.noticeMissingPublicName()

	go s.startRelay()
	defer s.Stop()
	out := waitForState(t, s, "failed")
	if out["notice"] != noPublicNameNotice {
		t.Fatalf("relay status notice: %v", out["notice"])
	}
	if reason, _ := out["reason"].(string); !strings.HasPrefix(reason, "Choose a name for your public address") {
		t.Fatalf("relay status reason: %q", reason)
	}
	_, settings := asOwner(t, s, "GET", "/api/settings/reachability", "")
	if settings["notice"] != noPublicNameNotice {
		t.Fatalf("reachability settings notice: %v", settings["notice"])
	}

	// Choosing a name is the owner having seen it.
	asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":"acme"}`)
	if st, _ := s.DataStore.GetSettings(); st.ReachabilityNotice != "" {
		t.Fatal("the notice outlived the owner's choice")
	}
}

// An instance that already has a name is left alone.
func TestAPublicAddressWithANameGetsNoNotice(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	s.noticeMissingPublicName()
	if st, _ := s.DataStore.GetSettings(); st != nil && st.ReachabilityNotice != "" {
		t.Fatalf("notice with a name set: %q", st.ReachabilityNotice)
	}
}

// A name the relay refuses is not kept: kept, it was asked for again at every
// start and refused every time, while the save had cleared the notice that
// should have said so.
func TestARefusedNameIsForgottenAndTheOwnerTold(t *testing.T) {
	s, rl, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	rl.HoldName("taken-one", "EOTHERIDENTITY")
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "active")

	code, out := asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":"taken-one"}`)
	v := relayView(t, out)
	if code != http.StatusOK || v["reason_code"] != "taken" {
		t.Fatalf("saving a taken name: %d %v", code, out)
	}
	st, _ := s.DataStore.GetSettings()
	if st.PublicRelayName != "" {
		t.Fatalf("the refused name was kept: %q", st.PublicRelayName)
	}
	if !strings.Contains(st.ReachabilityNotice, "taken-one") || !strings.Contains(st.ReachabilityNotice, "already held") {
		t.Fatalf("notice: %q", st.ReachabilityNotice)
	}
	if n, _ := v["notice"].(string); n != st.ReachabilityNotice {
		t.Fatalf("the answer's notice %q is not the one kept %q", n, st.ReachabilityNotice)
	}
}

// Clearing the name of a public address brings the no-name notice back rather
// than leaving the owner unreachable and untold.
func TestClearingThePublicNameTellsTheOwner(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	go s.startRelay()
	defer s.Stop()
	waitForState(t, s, "active")

	asOwner(t, s, "PUT", "/api/settings/reachability", `{"public_relay_name":""}`)
	if st, _ := s.DataStore.GetSettings(); st.ReachabilityNotice != noPublicNameNotice {
		t.Fatalf("notice: %q", st.ReachabilityNotice)
	}
}

// A name that can never be had, and a relay address that is not https, are
// refused before anything is saved.
func TestImpossibleSettingsAreRefusedBeforeSaving(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePublic)
	defer cancel()
	for _, body := range []string{
		`{"public_relay_name":"Not A Name"}`,
		`{"public_relay_name":"ac--me"}`,
		`{"public_relay_operator":"http://relay.example.org"}`,
		`{"relay_operator":"relay.example.org"}`,
	} {
		code, out := asOwner(t, s, "PUT", "/api/settings/reachability", body)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", body, code, out)
		}
	}
	if st, _ := s.DataStore.GetSettings(); st.PublicRelayName != "acme" || st.PublicRelayOperator != "" || st.RelayOperator != "" {
		t.Fatalf("settings changed: %+v", st)
	}
}

