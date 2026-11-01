package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A request signed with the owner's earlier key, naming the key state that key
// was in force at, is told its key state is stale, so the app reads it again.
// Signed by any other key it is refused as an unproved request is, whatever
// key state it names, so nobody who cannot sign as the owner learns anything
// about the owner's key state.
func TestAStaleOwnerSignatureIsSaidToBeStale(t *testing.T) {
	s := appHeldCore(t)
	seedNow, aid := sealTestOwner(t, s)
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
	var a, b map[string]interface{}
	_ = json.Unmarshal(icp, &a)
	_ = json.Unmarshal(rot, &b)
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: aid, KEL: []map[string]interface{}{a, b},
		KelVerified: true, CurrentPublicKey: k1}); err != nil {
		t.Fatal(err)
	}
	r := s.buildRouter("")
	ask := func(seed []byte, state string) *httptest.ResponseRecorder {
		resetSeenSignatures(t)
		req := signed(t, "GET", "/api/profile", "", seed, time.Now())
		req.Header.Set(headerOwnerKeyState, state)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	earlierState := "0." + icpEv.SAID
	if w := ask(earlier, earlierState); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "stale_key_state") {
		t.Fatalf("the owner's earlier key, naming its key state, was answered %d %s", w.Code, w.Body.String())
	}
	if w := ask(stranger, earlierState); w.Code != http.StatusForbidden {
		t.Fatalf("a stranger naming the owner's earlier key state was answered %d %s", w.Code, w.Body.String())
	}
	if w := ask(stranger, "1."+rotEv.SAID); w.Code != http.StatusForbidden {
		t.Fatalf("a stranger naming the key state in force was answered %d", w.Code)
	}
}
