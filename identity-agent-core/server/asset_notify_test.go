package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// A device asking the identity that owns it to send something.
//
// The signature is the whole gate. Without it, anything that could reach the
// port could send a message that arrives under the owner's name — which is
// worse than not having the endpoint at all, because that name is the thing
// that makes the message worth reading.

// notifyTestServer is an agent with an asset store, which newAuthTestServer
// does not build — it exists to test the authorisation gate and needs nothing
// else.
func notifyTestServer(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	store, err := asset.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &CoreServer{
		DataDir:      dir,
		assetHandler: &asset.Handler{Store: store},
	}
}

func enrolledMachine(t *testing.T, s *CoreServer, aid string) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "a machine's key, fixed for the test")
	key := ed25519.NewKeyFromSeed(seed)

	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID:              "asset-1",
		DisplayName:     "a device this agent owns",
		AssetType:       "host",
		PairwiseAID:     aid,
		PublicKey:       iacrypto.VerkeyQB64(key.Public().(ed25519.PublicKey)),
		DelegationModel: "delegated",
		DelegatorAID:    "EORG-ROOT",
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

func signedNotify(t *testing.T, key ed25519.PrivateKey, aid string, body []byte) *http.Request {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest(http.MethodPost, "/api/notify", stamp, body, key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/notify", bytes.NewReader(body))
	r.Header.Set(headerAssetAID, aid)
	r.Header.Set(headerAssetTimestamp, stamp)
	r.Header.Set(headerAssetSig, sig)
	return r
}

func notifyBody(t *testing.T) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]string{
		"to_aid": "EPERSON", "kind": "maintenance", "severity": "warning",
		"title": "This device restarts on Friday",
	})
	return b
}

// Anything that could reach the port could otherwise send a message that
// arrives wearing the organisation's name.
func TestAnUnsignedNotifyIsRefused(t *testing.T) {
	s := notifyTestServer(t)
	enrolledMachine(t, s, "EMACHINE")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/notify", bytes.NewReader(notifyBody(t)))
	s.handleAssetNotify(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("an unsigned request was not refused: %d %s", w.Code, w.Body.String())
	}
}

// The claimed identifier is only a lookup. Nothing is trusted until the
// signature matches the key that identifier enrolled with.
func TestASignatureFromTheWrongKeyIsRefused(t *testing.T) {
	s := notifyTestServer(t)
	enrolledMachine(t, s, "EMACHINE")

	otherSeed := make([]byte, ed25519.SeedSize)
	copy(otherSeed, "somebody else entirely, not this agent")
	other := ed25519.NewKeyFromSeed(otherSeed)

	body := notifyBody(t)
	w := httptest.NewRecorder()
	s.handleAssetNotify(w, signedNotify(t, other, "EMACHINE", body))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a signature from the wrong key was accepted: %d", w.Code)
	}
}

// A machine this agent has never enrolled is nobody's.
func TestAnUnknownMachineIsRefused(t *testing.T) {
	s := notifyTestServer(t)
	key := enrolledMachine(t, s, "EMACHINE")

	body := notifyBody(t)
	w := httptest.NewRecorder()
	s.handleAssetNotify(w, signedNotify(t, key, "ESOMEONE-ELSES-MACHINE", body))

	if w.Code != http.StatusForbidden {
		t.Fatalf("an unenrolled identifier was accepted: %d", w.Code)
	}
}

// The signature covers the body, so a captured one cannot be reused to send
// different words.
func TestASignatureDoesNotCoverADifferentMessage(t *testing.T) {
	s := notifyTestServer(t)
	key := enrolledMachine(t, s, "EMACHINE")

	r := signedNotify(t, key, "EMACHINE", notifyBody(t))
	tampered, _ := json.Marshal(map[string]string{
		"to_aid": "EPERSON", "title": "Something else entirely",
	})
	r.Body = http.NoBody
	r = func() *http.Request {
		r2 := httptest.NewRequest(http.MethodPost, "/api/notify", bytes.NewReader(tampered))
		r2.Header = r.Header
		return r2
	}()

	w := httptest.NewRecorder()
	s.handleAssetNotify(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a signature was reused with different words: %d", w.Code)
	}
}

// An asset the agent minted itself has no key of its own — its key lives in the
// owner's derivation tree. It must not be able to speak here, or the owner's
// own key would be doing a machine's work.
func TestAnAssetWithNoKeyOfItsOwnCannotSpeak(t *testing.T) {
	s := notifyTestServer(t)
	key := enrolledMachine(t, s, "EMACHINE")

	if err := s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID: "asset-2", DisplayName: "a website", AssetType: "domain",
		PairwiseAID: "EDERIVED", SigningIndex: 1073741824,
	}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.handleAssetNotify(w, signedNotify(t, key, "EDERIVED", notifyBody(t)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an asset with no enrolled key was accepted: %d", w.Code)
	}
}

// A stale signature is a captured one.
func TestAnOldSignatureIsRefused(t *testing.T) {
	s := notifyTestServer(t)
	key := enrolledMachine(t, s, "EMACHINE")

	body := notifyBody(t)
	stamp := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	sig, err := SignOwnerRequest(http.MethodPost, "/api/notify", stamp, body, key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/notify", bytes.NewReader(body))
	r.Header.Set(headerAssetAID, "EMACHINE")
	r.Header.Set(headerAssetTimestamp, stamp)
	r.Header.Set(headerAssetSig, sig)

	w := httptest.NewRecorder()
	s.handleAssetNotify(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a day-old signature was accepted: %d", w.Code)
	}
}

// The machine and the owner are different parties with different authority. A
// signature that satisfied both checks would let the weaker key do the stronger
// key's work.
func TestAMachinesSignatureIsNotAnOwnersSignature(t *testing.T) {
	s := notifyTestServer(t)
	key := enrolledMachine(t, s, "EMACHINE")

	body := notifyBody(t)
	stamp := time.Now().UTC().Format(time.RFC3339)
	sig, err := SignOwnerRequest(http.MethodPost, "/api/profile", stamp, body, key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	// Presented in the OWNER's headers, against an owner-only route.
	r := httptest.NewRequest(http.MethodPost, "/api/profile", bytes.NewReader(body))
	r.Header.Set(headerOwnerAID, "EMACHINE")
	r.Header.Set(headerOwnerTimestamp, stamp)
	r.Header.Set(headerOwnerSig, sig)

	if err := s.verifyOwnerSignature(r); err == nil {
		t.Fatal("a machine's key was accepted as the owner's")
	}
}

// The signature must be constructed the same way on both sides, or the machine
// signs one thing and the agent checks another. Pinned so a change to either
// breaks visibly here rather than as a delivery that silently stops working.
func TestTheMachineAndTheAgentSignTheSameBytes(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "a machine's key, fixed for the test")
	key := ed25519.NewKeyFromSeed(seed)

	body := []byte(`{"to_aid":"EPERSON"}`)
	stamp := "2026-07-31T12:00:00Z"

	sig, err := SignOwnerRequest(http.MethodPost, "/api/notify", stamp, body, key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := login.VerifyString(
		canonicalRequestString(http.MethodPost, "/api/notify", stamp, body),
		sig, key.Public().(ed25519.PublicKey))
	if err != nil || !ok {
		t.Fatalf("the two sides do not agree on what is signed: ok=%v err=%v", ok, err)
	}
}
