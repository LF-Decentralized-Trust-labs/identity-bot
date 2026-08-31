package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"identity-agent-core/store"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

func rootSeedServer(t *testing.T) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: t.TempDir()}
}

func postSeed(s *CoreServer, seedB64 string, remote bool) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"seed_b64": seedB64})
	req := httptest.NewRequest(http.MethodPost, "/api/keystore/root-seed", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	if remote {
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
	}
	w := httptest.NewRecorder()
	s.handleSetRootSeed(w, req)
	return w
}

// The onboarding handoff installs the mnemonic-derived seed exactly once:
// stored, then idempotent for the same seed, refused for a different one.
func TestSetRootSeedLifecycle(t *testing.T) {
	s := rootSeedServer(t)
	seed, err := backup.MnemonicToBIP39Seed(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "")
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(seed)

	if w := postSeed(s, b64, false); w.Code != http.StatusCreated {
		t.Fatalf("first handoff: %d %s", w.Code, w.Body)
	}
	stored, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil || !bytes.Equal(stored, seed) {
		t.Fatalf("stored seed must equal the BIP39 seed: %v", err)
	}

	// 200 exactly, not "200 or 201". The handler answers 201 {"status":"stored"}
	// for a fresh store and 200 {"status":"unchanged"} for the idempotent one,
	// so accepting either lets this pass in the case it exists to catch: the
	// first store having silently failed and this being the first real one.
	if w := postSeed(s, b64, false); w.Code != http.StatusOK {
		t.Fatalf("same-seed handoff must be idempotent: %d %s", w.Code, w.Body)
	}

	other := make([]byte, 64)
	other[0] = 0xFF
	if w := postSeed(s, base64.StdEncoding.EncodeToString(other), false); w.Code != http.StatusConflict {
		t.Fatalf("different seed must be refused: %d %s", w.Code, w.Body)
	}
	after, _ := secureenclave.LoadRootSeed(s.DataDir)
	if !bytes.Equal(after, seed) {
		t.Fatal("refused handoff must not change the established seed")
	}
}

// Keystore management is local-owner only; a tunneled request never reaches it.
func TestSetRootSeedRemoteDenied(t *testing.T) {
	s := rootSeedServer(t)
	seed := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if w := postSeed(s, seed, true); w.Code != http.StatusForbidden {
		t.Fatalf("forwarded request must be denied: %d", w.Code)
	}
}

func TestSetRootSeedRejectsBadInput(t *testing.T) {
	s := rootSeedServer(t)
	if w := postSeed(s, "not-base64!!", false); w.Code != http.StatusBadRequest {
		t.Fatalf("bad base64: %d", w.Code)
	}
	if w := postSeed(s, base64.StdEncoding.EncodeToString([]byte("short")), false); w.Code != http.StatusBadRequest {
		t.Fatalf("short seed: %d", w.Code)
	}
	if w := postSeed(s, base64.StdEncoding.EncodeToString(make([]byte, 96)), false); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized seed: %d", w.Code)
	}
}

// Status reports establishment without ever returning the seed.
func TestRootSeedStatus(t *testing.T) {
	s := rootSeedServer(t)
	get := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/keystore/root-seed", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		s.handleRootSeedStatus(w, req)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if got := get(); got["established"] != false {
		t.Fatalf("expected not established, got %v", got)
	}
	postSeed(s, base64.StdEncoding.EncodeToString(make([]byte, 64)), false)
	got := get()
	if got["established"] != true {
		t.Fatalf("expected established, got %v", got)
	}
	if _, leaked := got["seed"]; leaked || len(got) != 1 {
		t.Fatalf("status must reveal nothing but establishment: %v", got)
	}
}

// The recovery acceptance: phrase -> BIP39 seed -> handoff on a fresh device
// re-derives the identical HD pairwise key.
func TestPhraseAloneRederivesHDKeys(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	seed, _ := backup.MnemonicToBIP39Seed(mnemonic, "")
	b64 := base64.StdEncoding.EncodeToString(seed)

	deviceA := rootSeedServer(t)
	postSeed(deviceA, b64, false)
	seedA, _ := secureenclave.LoadRootSeed(deviceA.DataDir)
	keyA, err := backup.DerivePairwiseSeed(seedA, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	// "Wiped device": a brand-new data dir, only the phrase survives.
	deviceB := rootSeedServer(t)
	postSeed(deviceB, b64, false)
	seedB, _ := secureenclave.LoadRootSeed(deviceB.DataDir)
	keyB, err := backup.DerivePairwiseSeed(seedB, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("the seed phrase alone must re-derive identical HD keys on a fresh device")
	}
}

// A machine that answers to somebody else takes no root seed.
//
// This is the hole the pairing work left open. A paired computer holds its own
// key and names its owner in the event that founded it; the owner's root
// belongs on the device its owner carries. Installing it here would put the
// identifier that identifies a person in every relationship they have onto a
// machine they do not hold, silently, because everything would keep working.
func TestAPairedComputerRefusesARootSeed(t *testing.T) {
	s := agentWithNoIdentity(t)

	// What being paired looks like: an identity of its own, and an owner it was
	// sealed to that is somebody else.
	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID: "EThisComputersOwnIdentity", PublicKey: "DItsOwnKey",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EThePersonWhoOwnsIt",
		PublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
	}); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"seed_b64":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 64)) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/keystore/root-seed", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5050"
	rec := httptest.NewRecorder()
	s.handleSetRootSeed(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("a computer that answers to somebody else accepted their root seed (%d) — "+
			"that key can be copied off it and could never be taken back", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "EThePersonWhoOwnsIt") {
		t.Errorf("refused, but without saying who it answers to: %s", rec.Body.String())
	}
}

// And the case the endpoint exists for is untouched.
//
// A computer that IS the identity — no phone, keys on this machine — answers to
// nobody else, so it must still be able to be given the seed its owner's phrase
// produced. Without this, refusing above would have broken every setup that has
// no second device.
func TestAComputerThatIsTheIdentityStillTakesItsOwnSeed(t *testing.T) {
	s := agentWithNoIdentity(t)

	body := []byte(`{"seed_b64":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 64)) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/keystore/root-seed", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5050"
	rec := httptest.NewRecorder()
	s.handleSetRootSeed(rec, req)

	if rec.Code == http.StatusConflict {
		t.Fatalf("a computer that answers to nobody was refused its own seed, so a setup "+
			"with no second device cannot be completed: %s", rec.Body.String())
	}
}

func TestNotKnowingIsNotAReasonToProceed(t *testing.T) {
	// Unknown used to pass with a warning. The reasoning was that refusing over
	// a non-measurement turns "we did not look" into "you may not use this
	// software" — and that is wrong here, because of WHY unknown is usually
	// returned: not that the machine could not answer, but that the detector
	// for this platform has never been written.
	//
	// A seed on a machine that cannot protect it is a file. Whoever copies that
	// file becomes the identity, undetectably, with no rotation possible. There
	// is no partial version of that to trade against the inconvenience of
	// refusing.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	seed, _ := backup.MnemonicToBIP39Seed(mnemonic, "")
	b64 := base64.StdEncoding.EncodeToString(seed)

	// The machine is MADE to answer unknown, rather than the test relying on
	// this host being unable to answer.
	//
	// That reliance is what this line used to be, and it expired: every
	// supported platform has a detector now, so on any of them the install
	// simply succeeded and the assertions below never ran. A test whose
	// precondition is our own missing code stops testing the day that code is
	// written, and stops silently.
	prev := detectKeyProtection
	detectKeyProtection = func() secureenclave.Capability {
		return secureenclave.NotImplemented("a platform nobody has taught this software to inspect")
	}
	t.Cleanup(func() { detectKeyProtection = prev })

	s := rootSeedServer(t)
	w := postSeed(s, b64, false)
	if w.Code == http.StatusOK {
		t.Fatal("a root seed was installed on a machine this build cannot inspect")
	}
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("refused with %d, which is not the refusal a caller can act on", w.Code)
	}

	// And it says whose gap this is. Telling somebody their laptop is
	// unsuitable, when the truth is that we never wrote the check, would be a
	// false statement about their computer.
	if !strings.Contains(w.Body.String(), "has not been written") {
		t.Fatalf("the refusal blames the machine rather than this software: %s", w.Body)
	}

	// And it is not a dead end. Somebody refused because we never wrote the
	// check is the one person who can get it written, so they are told how and
	// given the environment detail to include — asking them to go and find
	// their architecture is how a report never gets sent.
	body := w.Body.String()
	if !strings.Contains(body, "report it") {
		t.Fatalf("a refusal with no way out: %s", body)
	}
	if !strings.Contains(body, runtime.GOOS) || !strings.Contains(body, runtime.GOARCH) {
		t.Fatalf("the report has nothing in it we could act on: %s", body)
	}

	// A deployment can say where to send it, and one that says nothing does
	// not invent an address.
	t.Setenv(envUnsupportedPlatformURL, "https://example.invalid/unsupported")
	if b := postSeed(s, b64, false).Body.String(); !strings.Contains(b, "example.invalid") {
		t.Fatalf("the configured report address was ignored: %s", b)
	}

	// Nothing was written.
	if _, err := secureenclave.LoadRootSeed(s.DataDir); err == nil {
		t.Fatal("the seed landed on disk despite being refused")
	}

	// The named override is the way through, and it is the only way through.
	t.Setenv(envAllowUnprotectedRootKey, "1")
	if w := postSeed(s, b64, false); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("the development override did not permit an owner-supplied seed: %d %s", w.Code, w.Body)
	}
}
