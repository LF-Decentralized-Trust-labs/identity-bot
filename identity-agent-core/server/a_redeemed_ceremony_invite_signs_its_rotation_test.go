package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// The device that accepted an invitation into an ownership ceremony makes the
// signature its key owes over a rotation, and nothing else: only a rotation of
// the organisation that invited it, only one that reveals the key being used,
// and only the key in force or the one it committed to.
func TestADeviceSignsOnlyACeremonyRotationThatRevealsItsKey(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)

	rel, ok := s.loginHandler.Store.Get("EORGAID")
	if !ok {
		t.Fatal("no relationship was made for the organisation")
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	pub := func(gen int) ed25519.PublicKey {
		sd, err := backup.DerivePairwiseSeed(root, rel.RelationshipIndex, gen)
		if err != nil {
			t.Fatal(err)
		}
		return ed25519.NewKeyFromSeed(sd).Public().(ed25519.PublicKey)
	}
	rotation := func(prefix string, keys ...ed25519.PublicKey) []byte {
		var ks, ns []string
		for _, k := range keys {
			ks = append(ks, iacrypto.VerkeyQB64(k))
			d, _ := keri.NextDigest(iacrypto.VerkeyQB64(k))
			ns = append(ns, d)
		}
		raw, err := keri.BuildRotation(keri.RotationInput{Prefix: prefix, Keys: ks, PriorSAID: prefix, SN: 1, NextDigests: ns})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	r := chi.NewRouter()
	s.mountCeremonySigningRoutes(r)
	ask := func(token string, gen int, raw []byte) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]any{"invite_token": token, "generation": gen, "raw_b64": base64.StdEncoding.EncodeToString(raw)})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/redeemed-invites/ceremony-signature", strings.NewReader(string(b))))
		return w
	}

	raw := rotation("EORGAID", pub(0), pub(7))
	w := ask("tok", 0, raw)
	var got struct {
		Sig string `json:"signature_b64"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	sig, _ := base64.StdEncoding.DecodeString(got.Sig)
	if w.Code != http.StatusOK || !ed25519.Verify(pub(0), raw, sig) {
		t.Fatalf("the device did not sign the rotation with its key: %d %s", w.Code, w.Body)
	}
	// The key it committed to signs a rotation that reveals it, as a hand-over's second does.
	raw2 := rotation("EORGAID", pub(1))
	w = ask("tok", 1, raw2)
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	sig, _ = base64.StdEncoding.DecodeString(got.Sig)
	if w.Code != http.StatusOK || !ed25519.Verify(pub(1), raw2, sig) {
		t.Fatalf("the committed key did not sign the second rotation: %d %s", w.Code, w.Body)
	}

	for name, c := range map[string]struct {
		w    *httptest.ResponseRecorder
		want int
	}{
		"a rotation that does not reveal the key":  {ask("tok", 0, rotation("EORGAID", pub(5))), http.StatusConflict},
		"a rotation of some other identity":        {ask("tok", 0, rotation("EOTHERAID", pub(0))), http.StatusBadRequest},
		"a key beyond the one committed to":        {ask("tok", 2, rotation("EORGAID", pub(2))), http.StatusBadRequest},
		"an invitation this device never accepted": {ask("other", 0, raw), http.StatusNotFound},
		"bytes that are not an event":              {ask("tok", 0, []byte("sign me")), http.StatusBadRequest},
	} {
		if c.w.Code != c.want {
			t.Errorf("%s: answered %d (%s), want %d", name, c.w.Code, c.w.Body, c.want)
		}
	}
}

// An invitation the organisation did not take into a ceremony is not one this
// device signs rotations for.
func TestAnInviteThatIsNotACeremonyIsNotSignedFor(t *testing.T) {
	app := newInvitingApp(t)
	s := redeemedAgent(t, app)
	s.redeemedInvites.remember("plain", redeemedInvite{base: app.URL, siteAID: "EORGAID"})
	r := chi.NewRouter()
	s.mountCeremonySigningRoutes(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/redeemed-invites/ceremony-signature",
		strings.NewReader(`{"invite_token":"plain","generation":0,"raw_b64":"AAAA"}`)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("a plain invite was signed for: %d", w.Code)
	}
}
