package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/buildmode"
	"identity-agent-core/recovery"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

func refusedSeedError() error {
	return fmt.Errorf("could not finish: %w", &secureenclave.ErrRootSeedCannotLiveHere{Reason: "no key hardware"})
}

// The activate route says 412 for a root-seed refusal. It used to carry its own
// switch that sent it to 400, so statusForActivateError (which says 412) was
// only ever called by tests. Reverting the handler to its own switch fails this.
func TestTheActivateRouteAnswers412ForARootSeedRefusal(t *testing.T) {
	prev := activateRecovery
	activateRecovery = func(*CoreServer, string, recovery.ActivateRequest) (*recovery.Session, error) {
		return nil, refusedSeedError()
	}
	t.Cleanup(func() { activateRecovery = prev })

	r := chi.NewRouter()
	s := &CoreServer{}
	r.Post("/sessions/{id}/activate", s.handleRecoveryActivate)
	req := httptest.NewRequest(http.MethodPost, "/sessions/abc/activate", strings.NewReader(`{"mnemonic":"x"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("got %d, want 412: %s", w.Code, w.Body)
	}
	var body ErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Error != rootSeedRefusalTitle || !strings.Contains(body.Details, "no key hardware") {
		t.Fatalf("not the refusal body: %s", w.Body)
	}
}

// The route and the function the tests pin cannot disagree about any refusal.
func TestTheActivateRouteAndItsStatusFunctionAgree(t *testing.T) {
	for name, err := range map[string]error{
		"held":         &recovery.ErrHeldForDuress{Reason: "held"},
		"rotation":     &recovery.ErrRotationMandatory{},
		"not authed":   &recovery.ErrNotAuthenticated{},
		"wrong phrase": errors.New("those words do not open this archive"),
		"seed refused": refusedSeedError(),
	} {
		err := err
		t.Run(name, func(t *testing.T) {
			prev := activateRecovery
			activateRecovery = func(*CoreServer, string, recovery.ActivateRequest) (*recovery.Session, error) { return nil, err }
			t.Cleanup(func() { activateRecovery = prev })
			r := chi.NewRouter()
			s := &CoreServer{}
			r.Post("/sessions/{id}/activate", s.handleRecoveryActivate)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sessions/abc/activate", bytes.NewReader([]byte(`{}`))))
			if want := statusForActivateError(err); w.Code != want {
				t.Fatalf("route answered %d, statusForActivateError says %d", w.Code, want)
			}
		})
	}
}

// A refusal from ensureRootSeed on a path that needs key material is the same
// 412 and body as founding, not an untyped 500 or 503.
func TestARootSeedRefusalFromEnsureRootSeedIsA412(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	resetPairingOfferForTest()
	t.Cleanup(resetPairingOfferForTest)
	s := agentWithNoIdentity(t)

	check := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusPreconditionFailed {
			t.Fatalf("%s: got %d, want 412: %s", name, w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), rootSeedRefusalTitle) {
			t.Fatalf("%s: not the refusal body: %s", name, w.Body)
		}
	}

	w := httptest.NewRecorder()
	s.handleMintMachineOwner(w, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	check("/machines/owner-identity", w)

	w = httptest.NewRecorder()
	s.handlePairingBegin(w, httptest.NewRequest(http.MethodPost, "/api/pairing/begin", nil))
	check("pairing begin", w)
}
