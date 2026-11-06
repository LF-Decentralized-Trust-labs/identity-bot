package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

const thePhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func phraseCall(s *CoreServer, method, path string, body any, owner bool) *httptest.ResponseRecorder {
	var rd bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = *bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, &rd)
	req.RemoteAddr = "127.0.0.1:9999"
	if owner {
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	}
	w := httptest.NewRecorder()
	switch {
	case method == http.MethodPut:
		s.handleHoldRecoveryPhrase(w, req)
	case method == http.MethodDelete:
		s.handleForgetRecoveryPhrase(w, req)
	case method == http.MethodPost:
		s.handleOpenRecoveryPhrase(w, req)
	default:
		s.handleRecoveryPhraseStatus(w, req)
	}
	return w
}

const phrasePath = "/api/keystore/recovery-phrase"

// Held until the owner confirms, read back when needed, gone on confirmation.
func TestThePhraseIsHeldReadBackAndForgotten(t *testing.T) {
	s := rootSeedServer(t)
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, true)

	if w := phraseCall(s, http.MethodPut, phrasePath, map[string]string{"phrase": thePhrase}, true); w.Code != http.StatusCreated {
		t.Fatalf("hold: %d %s", w.Code, w.Body)
	}
	raw, _ := os.ReadFile(filepath.Join(s.DataDir, "secureenclave", "recovery_phrase.key"))
	if strings.Contains(string(raw), "abandon") || !bytes.Contains(raw, []byte(`"wrap":"test-wrap"`)) {
		t.Fatalf("not wrapped: %s", raw)
	}
	st := phraseCall(s, http.MethodGet, phrasePath, nil, true)
	if strings.Contains(st.Body.String(), "abandon") || !strings.Contains(st.Body.String(), `"hardware-wrapped"`) {
		t.Fatalf("status must say what protects it and never the words: %s", st.Body)
	}
	o := phraseCall(s, http.MethodPost, phrasePath+"/open", nil, true)
	var got recoveryPhraseBody
	_ = json.Unmarshal(o.Body.Bytes(), &got)
	if o.Code != 200 || got.Phrase != thePhrase || o.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("open: %d %s", o.Code, o.Body)
	}
	if w := phraseCall(s, http.MethodDelete, phrasePath, nil, true); w.Code != 200 {
		t.Fatalf("forget: %d %s", w.Code, w.Body)
	}
	if w := phraseCall(s, http.MethodPost, phrasePath+"/open", nil, true); w.Code != http.StatusNotFound {
		t.Fatalf("after forgetting: %d", w.Code)
	}
}

// Production on a machine that cannot wrap: the root-seed refusal, so the app
// shows the same thing it shows for the seed, and nothing is written.
func TestTheRouteRefusesAPhraseItCannotWrap(t *testing.T) {
	s := rootSeedServer(t)
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, false)
	w := phraseCall(s, http.MethodPut, phrasePath, map[string]string{"phrase": thePhrase}, true)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), rootSeedRefusedCode) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "secureenclave", "recovery_phrase.key")); err == nil {
		t.Fatal("written")
	}
}

// Whoever reads the phrase becomes the identity: no owner secret, no answer, on
// any of the four routes.
func TestOnlyTheOwnerReachesThePhrase(t *testing.T) {
	s := rootSeedServer(t)
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, true)
	phraseCall(s, http.MethodPut, phrasePath, map[string]string{"phrase": thePhrase}, true)
	for _, c := range []struct{ m, p string }{
		{http.MethodPut, phrasePath}, {http.MethodGet, phrasePath},
		{http.MethodPost, phrasePath + "/open"}, {http.MethodDelete, phrasePath},
	} {
		w := phraseCall(s, c.m, c.p, map[string]string{"phrase": thePhrase}, false)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "abandon") {
			t.Fatalf("%s %s: %d %s", c.m, c.p, w.Code, w.Body)
		}
	}
	// and none is open to a browser session or to a controller (ADR-050)
	for _, k := range []string{"PUT /api/keystore/recovery-phrase", "GET /api/keystore/recovery-phrase",
		"POST /api/keystore/recovery-phrase/open", "DELETE /api/keystore/recovery-phrase"} {
		if _, ok := sessionForbidden[k]; !ok {
			t.Errorf("a browser session may reach %s", k)
		}
		if _, ok := controllerOwnerOnly[k]; !ok {
			t.Errorf("a controller may reach %s", k)
		}
	}
}

func TestSomethingThatIsNotAPhraseIsNotFiled(t *testing.T) {
	s := rootSeedServer(t)
	for _, bad := range []string{"", "abandon", strings.Repeat("a ", 30), thePhrase + " ABOUT", `{"x":1}`} {
		if w := phraseCall(s, http.MethodPut, phrasePath, map[string]string{"phrase": bad}, true); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", bad, w.Code)
		}
	}
}

func movingToCall(s *CoreServer, method string, body any, owner bool) *httptest.ResponseRecorder {
	var rd bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = *bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, phrasePath+"/moving-to", &rd)
	req.RemoteAddr = "127.0.0.1:9999"
	if owner {
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	}
	w := httptest.NewRecorder()
	switch method {
	case http.MethodPut:
		s.handleHoldPhraseMovingTo(w, req)
	case http.MethodDelete:
		s.handleForgetPhraseMovingTo(w, req)
	case http.MethodPost:
		s.handleOpenPhraseMovingTo(w, req)
	default:
		s.handlePhraseMovingToStatus(w, req)
	}
	return w
}

// The phrase an identity is moving to is held wrapped, beside the phrase in
// force, and the two never answer for each other.
func TestThePhraseMovedToIsHeldWrappedBesideThePhraseInForce(t *testing.T) {
	s := rootSeedServer(t)
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, true)
	const other = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

	phraseCall(s, http.MethodPut, phrasePath, map[string]string{"phrase": thePhrase}, true)
	if w := movingToCall(s, http.MethodPut, map[string]string{"phrase": other}, true); w.Code != http.StatusCreated {
		t.Fatalf("hold: %d %s", w.Code, w.Body)
	}
	raw, _ := os.ReadFile(filepath.Join(s.DataDir, "secureenclave", "recovery_phrase_moving_to.key"))
	if strings.Contains(string(raw), "zoo") || !bytes.Contains(raw, []byte(`"wrap":"test-wrap"`)) {
		t.Fatalf("not wrapped: %s", raw)
	}
	o := movingToCall(s, http.MethodPost, nil, true)
	var got recoveryPhraseBody
	_ = json.Unmarshal(o.Body.Bytes(), &got)
	if o.Code != 200 || got.Phrase != other {
		t.Fatalf("open: %d %s", o.Code, o.Body)
	}
	inForce := phraseCall(s, http.MethodPost, phrasePath+"/open", nil, true)
	_ = json.Unmarshal(inForce.Body.Bytes(), &got)
	if got.Phrase != thePhrase {
		t.Fatalf("the phrase in force changed: %s", inForce.Body)
	}
	if w := movingToCall(s, http.MethodDelete, nil, true); w.Code != 200 {
		t.Fatalf("forget: %d", w.Code)
	}
	if w := movingToCall(s, http.MethodPost, nil, true); w.Code != http.StatusNotFound {
		t.Fatalf("after forgetting: %d", w.Code)
	}
	if w := phraseCall(s, http.MethodPost, phrasePath+"/open", nil, true); w.Code != 200 {
		t.Fatalf("forgetting the move forgot the phrase in force: %d", w.Code)
	}
}

func TestOnlyTheOwnerReachesThePhraseMovedTo(t *testing.T) {
	s := rootSeedServer(t)
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, true)
	movingToCall(s, http.MethodPut, map[string]string{"phrase": thePhrase}, true)
	for _, m := range []string{http.MethodPut, http.MethodGet, http.MethodPost, http.MethodDelete} {
		if w := movingToCall(s, m, map[string]string{"phrase": thePhrase}, false); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", m, w.Code, w.Body)
		}
	}
	for _, k := range []string{"PUT /api/keystore/recovery-phrase/moving-to", "GET /api/keystore/recovery-phrase/moving-to",
		"POST /api/keystore/recovery-phrase/moving-to/open", "DELETE /api/keystore/recovery-phrase/moving-to"} {
		if _, ok := sessionForbidden[k]; !ok {
			t.Errorf("a browser session may reach %s", k)
		}
		if _, ok := controllerOwnerOnly[k]; !ok {
			t.Errorf("a controller may reach %s", k)
		}
	}
}
