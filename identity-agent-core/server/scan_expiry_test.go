package server

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
)

// probeT is a scan Ask action used only by these tests; no real action holds
// it (actions/registry.json).
const probeT = 71

// probeAsk is self-verifying, so the scan gate reaches its Execute without
// fetching a signer key over the network, and it counts the signatures it
// makes, so a test can tell whether an Ask got as far as signing.
type probeAsk struct{ signed *int }

func (probeAsk) Action() string   { return "probe" }
func (probeAsk) AskAuth() askAuth { return authSelfVerifying }
func (probeAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	return GenericPreview{T: probeT, Action: "probe"}, nil
}
func (p probeAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	if _, err := login.SignAsk([]byte(`{"probe":true}`), make([]byte, ed25519.SeedSize)); err != nil {
		return nil, err
	}
	*p.signed++
	return map[string]interface{}{"ok": true}, nil
}

// withProbe registers the probe action for one test and returns the count of
// signatures it makes.
func withProbe(t *testing.T) *int {
	t.Helper()
	before, had := askRegistry[probeT]
	if had {
		t.Fatalf("action t=%d is taken; pick another probe", probeT)
	}
	signed := new(int)
	registerAsk(probeT, probeAsk{signed: signed})
	t.Cleanup(func() {
		if had {
			askRegistry[probeT] = before
		} else {
			delete(askRegistry, probeT)
		}
	})
	return signed
}

// serveAsk serves the Ask bytes at /i/probe, as a relay would.
func serveAsk(t *testing.T, ask []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/i/probe" {
			_, _ = w.Write(ask)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/i/probe"
}

// scanExecute posts an Ask to the execute gate the way the scanner does.
func scanExecute(t *testing.T, ask []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"url": serveAsk(t, ask), "approved": true, "ask_digest": askDigest(ask),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	s.handleScanExecute(rec, httptest.NewRequest(http.MethodPost, "/api/scan/execute", strings.NewReader(string(body))))
	return rec
}

// scanDecode posts an Ask to the route that builds the consent screen.
func scanDecode(t *testing.T, ask []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"url": serveAsk(t, ask)})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	s.handleScanDecode(rec, httptest.NewRequest(http.MethodPost, "/api/scan/decode", strings.NewReader(string(body))))
	return rec
}

// probeAskWith builds a probe Ask; expiry is set only when withExpiry is true,
// so a test can send no expiry field at all.
func probeAskWith(t *testing.T, expiry interface{}, withExpiry bool) []byte {
	t.Helper()
	fields := map[string]interface{}{"v": "ASK1", "t": probeT}
	if withExpiry {
		fields["expiry"] = expiry
	}
	ask, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return ask
}

func in(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

// An expired Ask is refused with 410 before anything is signed, and gets no
// consent screen.
func TestAnExpiredAskIsRefusedAndNothingIsSigned(t *testing.T) {
	signed := withProbe(t)
	ask := probeAskWith(t, in(-2*time.Minute), true)
	if rec := scanDecode(t, ask); rec.Code != http.StatusGone {
		t.Fatalf("an expired Ask was shown for consent: %d %s", rec.Code, rec.Body.String())
	}
	rec := scanExecute(t, ask)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("an expired Ask was answered %d %q, want 410 saying it expired", rec.Code, rec.Body.String())
	}
	if *signed != 0 {
		t.Fatalf("an expired Ask got as far as signing: %d signature(s)", *signed)
	}
}

// A live Ask, and one expired by less than the skew allowance, still execute.
func TestALiveAskStillWorks(t *testing.T) {
	signed := withProbe(t)
	for name, expiry := range map[string]string{"live": in(time.Hour), "inside the skew": in(-30 * time.Second)} {
		if rec := scanExecute(t, probeAskWith(t, expiry, true)); rec.Code != http.StatusOK {
			t.Fatalf("%s: answered %d, want 200: %s", name, rec.Code, rec.Body.String())
		}
	}
	if *signed != 2 {
		t.Fatalf("live Asks made %d signature(s), want 2", *signed)
	}
}

// An expiry that is present but unreadable is refused with 400: a field that
// is there and says nothing usable is not the same as no field.
func TestAnAskWithAnUnreadableExpiryIsRefused(t *testing.T) {
	signed := withProbe(t)
	for name, expiry := range map[string]interface{}{
		"empty":      "",
		"null":       nil,
		"a number":   12345,
		"not a time": "not-a-time",
		"bad shape":  "2025-13-45T99:99:99Z",
	} {
		ask := probeAskWith(t, expiry, true)
		if err := askExpiryFresh(ask, time.Now()); !errors.Is(err, login.ErrExpiryUnreadable) {
			t.Errorf("%s: passed the freshness check: %v", name, err)
			continue
		}
		if rec := scanExecute(t, ask); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d, want 400", name, rec.Code)
		}
	}
	if *signed != 0 {
		t.Fatalf("an Ask with an unreadable expiry signed something: %d signature(s)", *signed)
	}
}

// A login must carry an expiry. The Asks an Identity Agent mints itself carry
// none today, and a scanned add-contact code must keep working.
func TestOnlyALoginAskMustCarryAnExpiry(t *testing.T) {
	loginAsk, err := json.Marshal(map[string]interface{}{"v": "ASK1", "t": 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := askExpiryFresh(loginAsk, time.Now()); !errors.Is(err, login.ErrExpiryUnreadable) {
		t.Fatalf("a login Ask with no expiry passed the freshness check: %v", err)
	}
	contact, err := json.Marshal(map[string]interface{}{"v": "ASK1", "t": 2, "asker_aid": "EPAIRWISE"})
	if err != nil {
		t.Fatal(err)
	}
	if err := askExpiryFresh(contact, time.Now()); err != nil {
		t.Fatalf("an add-contact Ask with no expiry was refused: %v", err)
	}
	signed := withProbe(t)
	if rec := scanExecute(t, probeAskWith(t, nil, false)); rec.Code != http.StatusOK || *signed != 1 {
		t.Fatalf("a minted Ask with no expiry field was answered %d with %d signature(s)", rec.Code, *signed)
	}
}
