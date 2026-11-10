package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/internal/boundedread"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A request signed with the owner's earlier key, naming the key state that key
// was in force at, is told its key state is stale, so the app reads it again.
// Signed by any other key it is refused as an unproved request is, whatever
// key state it names, so nobody who cannot sign as the owner learns anything
// about the owner's key state.
// anOwnerWhoRotated is a core whose owner founded its log on the earlier key
// and rotated to the one in force: the seeds of the key now, the earlier key
// and a stranger, and the key states the log names.
type anOwnerWhoRotated struct {
	s                          *CoreServer
	seedNow, earlier, stranger []byte
	earlierState, currentState string
}

func anOwnerWhoRotatedWorld(t *testing.T) anOwnerWhoRotated {
	t.Helper()
	s := appHeldCore(t)
	seedNow := make([]byte, ed25519.SeedSize)
	for i := range seedNow {
		seedNow[i] = byte(i + 1)
	}
	earlier := make([]byte, ed25519.SeedSize)
	for i := range earlier {
		earlier[i] = byte(90 + i)
	}
	stranger := make([]byte, ed25519.SeedSize)
	for i := range stranger {
		stranger[i] = byte(150 + i)
	}
	// The owner's verified log: founded on the earlier key, rotated to the
	// one in force.
	k0, k1 := verkeyOf(earlier), verkeyOf(seedNow)
	d1, _ := keri.NextDigest(k1)
	icp, err := keri.BuildInception(keri.InceptionInput{Keys: []string{k0}, NextDigests: []string{d1}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, _ := keri.ParseEvent(icp)
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: icpEv.Identifier, Keys: []string{k1}, PriorSAID: icpEv.SAID, SN: 1,
		NextDigests: []string{d1}})
	if err != nil {
		t.Fatal(err)
	}
	rotEv, _ := keri.ParseEvent(rot)
	// The owner is the identifier this log founds: a kept log is read only as
	// the log of the identifier its own events name.
	aid := icpEv.Identifier
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: aid,
		PublicKey: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seedNow).Public().(ed25519.PublicKey))}); err != nil {
		t.Fatal(err)
	}
	// Kept as its bytes, the only form a log is read as verified in.
	a := map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(icp)}
	b := map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(rot)}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: aid, KEL: []map[string]interface{}{a, b},
		KelVerified: true, CurrentPublicKey: k1}); err != nil {
		t.Fatal(err)
	}
	return anOwnerWhoRotated{s: s, seedNow: seedNow, earlier: earlier, stranger: stranger,
		earlierState: "0." + icpEv.SAID, currentState: "1." + rotEv.SAID}
}

func TestAStaleOwnerSignatureIsSaidToBeStale(t *testing.T) {
	w0 := anOwnerWhoRotatedWorld(t)
	s, earlier, stranger := w0.s, w0.earlier, w0.stranger

	r := s.buildRouter()
	ask := func(seed []byte, state string) *httptest.ResponseRecorder {
		resetSeenSignatures(t)
		req := signed(t, "GET", "/api/profile", "", seed, time.Now())
		req.Header.Set(headerOwnerKeyState, state)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	earlierState := w0.earlierState
	if w := ask(earlier, earlierState); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "stale_key_state") {
		t.Fatalf("the owner's earlier key, naming its key state, was answered %d %s", w.Code, w.Body.String())
	}
	if w := ask(stranger, earlierState); w.Code != http.StatusForbidden {
		t.Fatalf("a stranger naming the owner's earlier key state was answered %d %s", w.Code, w.Body.String())
	}
	if w := ask(stranger, w0.currentState); w.Code != http.StatusForbidden {
		t.Fatalf("a stranger naming the key state in force was answered %d", w.Code)
	}
}

// The body a stale request is read under is the bound its route states, as the
// signature check reads it, not the one limit of an ordinary request: a profile
// photo goes in as base64 well over boundedread.Request, and a request carrying
// one, signed with the earlier key, is still told its key state is stale.
func TestAStaleRequestIsReadUnderItsRoutesBound(t *testing.T) {
	w0 := anOwnerWhoRotatedWorld(t)
	r := w0.s.buildRouter()
	photo := `{"photo":"` + strings.Repeat("A", int(boundedread.Request)+(256<<10)) + `"}`
	resetSeenSignatures(t)
	req := signed(t, "PUT", "/api/profile", photo, w0.earlier, time.Now())
	req.Header.Set(headerOwnerKeyState, w0.earlierState)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "stale_key_state") {
		t.Fatalf("a photo-sized request signed under the earlier key was answered %d %.200s", w.Code, w.Body.String())
	}
}
