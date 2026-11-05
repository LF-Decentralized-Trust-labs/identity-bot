package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/buildmode"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// Owner's rule, 2026-11-05: a production build on an Android phone whose app has
// registered no seed wrapper must not found an identity by ANY route. The
// platform question ("may an identity be founded here") is yes for a phone, so
// every way in also has to ask whether the root seed can be wrapped.
func TestAPhoneWithNoSeedWrapperIsRefusedFoundingByEveryRoute(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	doors := []struct {
		what, path, body string
		call             func(*CoreServer, http.ResponseWriter, *http.Request)
	}{
		{"founding directly", "/api/inception", `{"public_key":"D1","next_public_key":"D2"}`, (*CoreServer).handleInception},
		{"root rotation that mints a root", "/api/recovery/root-aid-rotation", `{}`, (*CoreServer).handleRecoveryRootAIDRotation},
		{"hybrid inception", "/api/hybrid-inception", `{}`, (*CoreServer).handleHybridInception},
		{"storing an identity", "/api/store/identity", `{"aid":"EWHATEVER","public_key":"D1"}`, (*CoreServer).handleStoreIdentity},
		{"storing an inception event", "/api/store/event", `{"aid":"EWHATEVER","event_type":"icp","sequence_number":0}`, (*CoreServer).handleStoreEvent},
	}
	for _, d := range doors {
		t.Run(d.what, func(t *testing.T) {
			s := agentWithNoIdentity(t)
			seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
			req := httptest.NewRequest(http.MethodPost, d.path, strings.NewReader(d.body))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
			rec := httptest.NewRecorder()
			d.call(s, rec, req)
			if rec.Code != http.StatusPreconditionFailed {
				t.Fatalf("%s got past the seed check on a phone with no wrapper: %d %s", d.what, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), secureenclave.PhoneHardwareUnavailable) {
				t.Fatalf("the refusal does not give the phone's reason: %s", rec.Body.String())
			}
		})
	}
}

func TestAPhoneWithNoSeedWrapperIsRefusedFoundingWhileBeingPaired(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	machine, srv, code := pairableComputer(t)
	_ = beginAt(t, srv.URL)
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)

	body := `{"found_as_root":true,"owner_aid":"EOWNER","adoption_code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/complete", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	rec := httptest.NewRecorder()
	machine.handlePairingComplete(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("a phone with no wrapper founded its own root while being paired: %d %s", rec.Code, rec.Body.String())
	}
}

// And a phone whose app does supply a working wrapper is not stopped here.
func TestAPhoneWithAWorkingSeedWrapperIsNotStoppedByTheSeedCheck(t *testing.T) {
	s := agentWithNoIdentity(t)
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: true})
	t.Cleanup(restore)
	req := httptest.NewRequest(http.MethodPost, "/api/inception",
		strings.NewReader(`{"public_key":"D1","next_public_key":"D2"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	rec := httptest.NewRecorder()
	s.handleInception(rec, req)
	if rec.Code == http.StatusPreconditionFailed || rec.Code == http.StatusForbidden {
		t.Fatalf("a phone that can wrap the seed was refused: %d %s", rec.Code, rec.Body.String())
	}
}
