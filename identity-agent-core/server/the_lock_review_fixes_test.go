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

	"identity-agent-core/authprovider"
	"identity-agent-core/lockgate"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

func aCoreOn(t *testing.T, goos, dir string) (*CoreServer, http.Handler) {
	t.Helper()
	defer func(prev string) { thisPlatformGOOS = prev }(thisPlatformGOOS)
	thisPlatformGOOS = goos
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.LocalOwnerSecret = testOwnerSecret
	cfg.ProfileID = "profile-a"
	s, err := New(cfg) // no GateMode: the core decides by what it runs on
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s, s.buildRouter()
}

// Items 1 and 9: a Mac or Windows core, through New() with no GateMode set,
// refuses an unlock with no voucher, and accepts one the root device signed for
// THIS machine's controller identifier (not the black box's, which is nil here).
func TestADesktopCoreStartedWithNoModeRefusesAnUnlockWithNoVoucher(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			seedwraptest.ThisMachineCanProtectASeed(t)
			s, h := aCoreOn(t, goos, t.TempDir())
			if s.boxIdentity != nil {
				t.Fatal("a desktop has no box identity")
			}
			askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
			if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), true); w.Code != http.StatusUnauthorized {
				t.Fatalf("a desktop unlocked on the placeholder's own score: %d %s", w.Code, w.Body.String())
			}
			if st := stateOf(t, h); st.State != "locked" {
				t.Fatalf("%+v", st)
			}
		})
	}
}

func TestADesktopUnlocksWithAVoucherForItsOwnControllerIdentifier(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	defer func(prev func(*CoreServer) string) { theControllerIdentifierOf = prev }(theControllerIdentifierOf)
	theControllerIdentifierOf = func(*CoreServer) string { return "BThisDesktop" }
	// Unlocking starts background work that may still be writing when the test
	// ends, so the directory is removed by hand once the core has stopped.
	dir, err := os.MkdirTemp("", "desktop-unlock")
	if err != nil {
		t.Fatal(err)
	}
	s, h := aCoreOn(t, "darwin", dir)
	t.Cleanup(func() {
		s.Stop()
		time.Sleep(500 * time.Millisecond)
		_ = os.RemoveAll(dir)
	})
	seed := ownerSeedForTest(t, s)
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)

	login := func(controller string, n int) string {
		at := time.Now().UTC().Truncate(time.Second)
		nonce := strings.Repeat("v", 16) + string(rune('a'+n))
		sig, err := loginSign(authprovider.CanonicalUnlockVoucherStatement(s.thisIdentityAgentsIdentifier(), controller, authprovider.LevelVerified, at, 80, nonce), seed)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{
			"profile": "profile-a", "level": authprovider.LevelVerified, "score": 80, "at": at.Format(time.RFC3339), "nonce": nonce,
			"voucher": map[string]string{"agent_aid": s.thisIdentityAgentsIdentifier(), "controller_aid": controller, "signature": sig},
		})
		return string(b)
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", login("BAnotherDesktop", 1), true); w.Code != http.StatusUnauthorized {
		t.Fatalf("a voucher for another machine opened this one: %d %s", w.Code, w.Body.String())
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", login("BThisDesktop", 2), true); w.Code != http.StatusOK {
		t.Fatalf("a voucher for this machine did not open it: %d %s", w.Code, w.Body.String())
	}
	if st := stateOf(t, h); st.State != "open" {
		t.Fatalf("%+v", st)
	}
}

func loginSign(statement string, seed []byte) (string, error) {
	return login.SignString(statement, seed)
}

// Item 2: a Linux core (the black box and the development box) and any core with
// a box identity are not gated.
func TestALinuxCoreAndABoxAreNotGated(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, h := aCoreOn(t, "linux", t.TempDir())
	if st := stateOf(t, h); st.State != "ungated" || st.LockClass != "none" {
		t.Fatalf("%+v", st)
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != http.StatusConflict {
		t.Fatalf("a box can be locked: %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "gate")); !os.IsNotExist(err) {
		t.Fatalf("a gate was made on a box: %v", err)
	}
	if err := secureenclave.StoreIdentityRootSeed(s.DataDir, make([]byte, 32)); err != nil {
		t.Fatalf("a box stores its seed as before: %v", err)
	}
}

// Fix E: a planted box_identity.json does not turn off the gate on a Mac, and
// does not leave a new iOS, Android or Windows profile without one.
func TestAPlantedBoxIdentityFileDoesNotRemoveTheGateOnAnyDesktopOrPhone(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	for goos, mode := range map[string]string{"darwin": "controller", "windows": "controller", "ios": "root-device", "android": "root-device"} {
		t.Run("new profile "+goos, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, boxIdentityFile), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			s, h := aCoreOn(t, goos, dir)
			if st := stateOf(t, h); st.State == "ungated" {
				t.Fatalf("a planted box file left a new %s profile ungated: %+v", goos, st)
			}
			if _, err := os.Stat(filepath.Join(s.DataDir, "gate")); err != nil {
				t.Fatalf("no gate was made on %s: %v", goos, err)
			}
			if s.lock.sess.G.Mode != lockgate.Mode(mode) {
				t.Fatalf("%s mode %q", goos, s.lock.sess.G.Mode)
			}
		})
	}
}

func TestAPlantedBoxIdentityFileOnAGatedMacKeepsTheVoucherRequirement(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s, h := aCoreOn(t, "darwin", dir)
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
	s.Stop()
	if err := os.WriteFile(filepath.Join(dir, boxIdentityFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, h2 := aCoreOn(t, "darwin", dir)
	if s2.lock.sess.G.Mode != lockgate.ModeController {
		t.Fatalf("mode became %q", s2.lock.sess.G.Mode)
	}
	if w := askTheLock(t, h2, http.MethodPost, "/api/lock/unlock", aLogIn(80), true); w.Code == http.StatusOK {
		t.Fatalf("an unlock with no voucher answered 200 after a box file was planted")
	}
}

// Fix F: on a Mac or Windows computer a requested mode other than controller is
// ignored; on Linux the box is still ungated.
func TestAMacOrWindowsCoreIgnoresARequestedRootMode(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		defer func(prev string) { thisPlatformGOOS = prev }(thisPlatformGOOS)
		thisPlatformGOOS = goos
		s := &CoreServer{}
		for _, asked := range []lockgate.Mode{lockgate.ModePhone, lockgate.ModeNone} {
			if got := s.theGateModeFor(Config{DataDir: t.TempDir(), GateMode: asked}); got != lockgate.ModeController {
				t.Fatalf("%s asked %q got %q", goos, asked, got)
			}
		}
	}
	thisPlatformGOOS = "linux"
	if got := (&CoreServer{}).theGateModeFor(Config{DataDir: t.TempDir()}); got != lockgate.ModeNone {
		t.Fatalf("linux %q", got)
	}
}

// Item 7, the reviewer's probe: lock, delete gate/, restart, and the identity is
// still refused.
func TestDeletingTheGateAndRestartingDoesNotReopenTheIdentity(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s, h := aGatedCore(t, dir)
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
	s.Stop()
	if err := os.RemoveAll(filepath.Join(dir, "gate")); err != nil {
		t.Fatal(err)
	}
	_, h2 := aGatedCore(t, dir)
	st := stateOf(t, h2)
	if st.State != "locked" || st.LockClass != "gate_unreadable" || strings.Contains(st.Statement, "made before locking existed") {
		t.Fatalf("a deleted gate reopened or was called ungated: %+v", st)
	}
	if w := askTheLock(t, h2, http.MethodGet, "/api/identity", "", true); w.Code != http.StatusLocked {
		t.Fatalf("GET /api/identity with the gate deleted: %d", w.Code)
	}
}

// Item 10 through New(): if the gate could not be made, nothing is stored, and
// the next start retries.
func TestAFailedFoundingStoresNoSeedAndTheNextStartRetries(t *testing.T) {
	dir := t.TempDir()
	restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: false})
	_, h := aGatedCore(t, dir)
	if st := stateOf(t, h); st.State != "ungated" {
		t.Fatalf("%+v", st)
	}
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err == nil {
		t.Fatal("a seed was stored into an ungated profile in a build that has gates")
	}
	restore()
	seedwraptest.ThisMachineCanProtectASeed(t)
	_, h = aGatedCore(t, dir)
	if st := stateOf(t, h); st.State != "open" {
		t.Fatalf("the next start did not retry the gate: %+v", st)
	}
}

// Item 14: handleLockUnlock checks the owner proof itself, whatever the router
// says, and so does the secret route.
func TestTheUnlockAndSecretHandlersCheckTheOwnerProofThemselves(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, _ := aGatedCore(t, t.TempDir())
	s.lock.sess.Lock()
	for _, c := range []struct {
		name   string
		method string
		h      http.HandlerFunc
	}{
		{"unlock", http.MethodPost, s.handleLockUnlock},
		{"secret", http.MethodPut, s.handleLockSecret},
		{"lock", http.MethodPost, s.handleLockLock},
		{"state", http.MethodGet, s.handleLockState},
	} {
		r := httptest.NewRequest(c.method, "/api/lock/"+c.name, strings.NewReader(aLogIn(80)))
		r.RemoteAddr = "127.0.0.1:52100" // this computer, but without the owner's secret
		w := httptest.NewRecorder()
		c.h(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s with no owner proof: %d", c.name, w.Code)
		}
	}
	if s.lock.sess.State() != lockgate.StateLocked {
		t.Fatal("a handler without the proof changed the lock")
	}
}

// Item 13: an unlock admitted before a log-out began cannot reopen the identity
// after the log-out returned.
func TestAnUnlockAdmittedBeforeALogOutCannotReopenAfterIt(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, h := aGatedCore(t, t.TempDir())
	gen0 := s.lock.generation() // the unlock is past its isLocking() check here
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != http.StatusOK {
		t.Fatalf("log-out: %d", w.Code)
	}
	if release, ok := s.lock.beginChange(gen0); ok {
		release()
		t.Fatal("an unlock admitted before the log-out was allowed to run after it")
	}
	if s.lock.sess.State() != lockgate.StateLocked {
		t.Fatal("the identity is not locked")
	}
}
