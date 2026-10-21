package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

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
	_, out = asOwner(t, s, "GET", "/api/settings/reachability/domains", "")
	if j := string(mustJSON(t, out)); !strings.Contains(j, `"active"`) || strings.Contains(j, "waiting_for_dns") {
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
