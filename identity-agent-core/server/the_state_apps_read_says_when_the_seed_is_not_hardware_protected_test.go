package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/buildmode"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// The state the apps read (GET security enclave, keyProtection) must not say a
// phone may hold a root key when its app has supplied no seed key: it carries
// keyProtection.rootKeyPermitted=false with keyProtection.rootKeyRefusal, and
// keyProtection.seedProtection.hardwareProtected=false with notProtectedWhy.
func TestTheStateAppsReadRefusesAPhoneWhoseAppSuppliesNoSeedKey(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleSecurityEnclave(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var got struct {
		KeyProtection KeyProtectionInfo `json:"keyProtection"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	kp := got.KeyProtection
	if kp.RootKeyPermitted || kp.RootKeyRefusal != secureenclave.PhoneHardwareUnavailable {
		t.Fatalf("rootKeyPermitted=%v refusal=%q", kp.RootKeyPermitted, kp.RootKeyRefusal)
	}
	if kp.SeedProtection == nil || kp.SeedProtection.HardwareProtected || kp.SeedProtection.NotProtectedWhy == "" {
		t.Fatalf("seedProtection presents the seed as protected or says nothing: %+v", kp.SeedProtection)
	}
}
