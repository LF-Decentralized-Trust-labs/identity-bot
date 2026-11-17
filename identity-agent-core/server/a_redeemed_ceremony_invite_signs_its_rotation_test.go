package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// aCeremonyDevice is a phone's Identity Agent that accepted an invitation into
// an ownership ceremony of a real organisation identity: one whose key history
// the organisation serves at its address and a real witness holds.
type aCeremonyDevice struct {
	s       *CoreServer
	org     *rotatingController
	witness *peerAgent
	served  []map[string]interface{} // what the organisation's address serves
	r       chi.Router
	root    []byte
	relIdx  int
}

func aCeremonyDeviceOf(t *testing.T) *aCeremonyDevice {
	t.Helper()
	app := newInvitingApp(t)
	d := &aCeremonyDevice{s: redeemedAgent(t, app)}
	d.witness, d.org = witnessedController(t)
	pointTheBootstrapPoolAt(t, d.witness.witnessKey, servedThroughTheRealRouter(t, d.witness))
	d.served = presentedInception(t, d.org)
	orgSite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/oobi/"+d.org.aid {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kel": d.served})
	}))
	t.Cleanup(orgSite.Close)
	in := redeemedInvite{base: app.URL, siteAID: d.org.aid, siteOOBI: orgSite.URL + "/public/oobi/" + d.org.aid, ceremony: true}
	d.s.redeemedInvites.remember("tok", in)
	if err := d.s.keepCeremonyInvite("tok", in); err != nil {
		t.Fatal(err)
	}
	rel, err := d.s.loginHandler.GetOrCreateRelationship(in.siteAID, &login.ChallengeBundle{SiteAID: in.siteAID, SiteOOBI: in.siteOOBI})
	if err != nil {
		t.Fatal(err)
	}
	d.relIdx = rel.RelationshipIndex
	if d.root, err = secureenclave.LoadRootSeed(d.s.DataDir); err != nil {
		t.Fatal(err)
	}
	d.r = chi.NewRouter()
	d.s.mountCeremonySigningRoutes(d.r)
	return d
}

func (d *aCeremonyDevice) pub(t *testing.T, gen int) ed25519.PublicKey {
	t.Helper()
	sd, err := backup.DerivePairwiseSeed(d.root, d.relIdx, gen)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(sd).Public().(ed25519.PublicKey)
}

func (d *aCeremonyDevice) ask(token string, gen int, raw []byte) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"invite_token": token, "generation": gen, "raw_b64": base64.StdEncoding.EncodeToString(raw)})
	w := httptest.NewRecorder()
	d.r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/redeemed-invites/ceremony-signature", strings.NewReader(string(b))))
	return w
}

// commits is what this device derives to commit to at [gen]: the classical
// digest of that generation's key and its post-quantum partner.
func (d *aCeremonyDevice) commits(t *testing.T, gen int) ownerCommitment {
	t.Helper()
	c, err := ownerCommitmentAt(d.root, d.relIdx, gen)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// rotation is a rotation of [prefix] at place [sn] after [prior], revealing
// [keys], and its digest. It commits to the keys' digests and, as an
// organisation that kept this device's commitments would, to this device's
// commitment for each of the two generations after its own.
func (d *aCeremonyDevice) rotation(t *testing.T, prefix string, sn uint64, prior string, keys ...ed25519.PublicKey) ([]byte, string) {
	t.Helper()
	var next []string
	for _, k := range keys {
		dg, _ := keri.NextDigest(iacrypto.VerkeyQB64(k))
		next = append(next, dg)
	}
	for g := 1; g <= 2; g++ {
		c := d.commits(t, g)
		for _, dg := range []string{c.Classical, c.PostQuantum} {
			if !slices.Contains(next, dg) {
				next = append(next, dg)
			}
		}
	}
	return ceremonyRotationCommitting(t, prefix, sn, prior, keys, next)
}

// ceremonyRotationCommitting is a rotation revealing [keys] and committing to
// exactly [next].
func ceremonyRotationCommitting(t *testing.T, prefix string, sn uint64, prior string, keys []ed25519.PublicKey, next []string) ([]byte, string) {
	t.Helper()
	var ks []string
	for _, k := range keys {
		ks = append(ks, iacrypto.VerkeyQB64(k))
	}
	raw, err := keri.BuildRotation(keri.RotationInput{Prefix: prefix, Keys: ks, PriorSAID: prior, SN: int(sn), NextDigests: next})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ev.SAID
}

func signedBy(w *httptest.ResponseRecorder, pub ed25519.PublicKey, raw []byte) bool {
	var got struct {
		Sig string `json:"signature_b64"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	sig, _ := base64.StdEncoding.DecodeString(got.Sig)
	return w.Code == http.StatusOK && ed25519.Verify(pub, raw, sig)
}

// The device that accepted an invitation into an ownership ceremony makes the
// signature its key owes over a rotation, and nothing else: only a rotation of
// the organisation that invited it, only one that reveals the key being used,
// and only the key in force or the one it committed to.
func TestADeviceSignsOnlyACeremonyRotationThatRevealsItsKey(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	aid := d.org.aid

	raw, said := d.rotation(t, aid, 1, d.org.icpSAID, d.pub(t, 0), d.pub(t, 7))
	if w := d.ask("tok", 0, raw); !signedBy(w, d.pub(t, 0), raw) {
		t.Fatalf("the device did not sign the rotation with its key: %d %s", w.Code, w.Body)
	}
	// The key it committed to signs a rotation that reveals it, as a hand-over's
	// second does, placed after the first one it signed.
	raw2, _ := d.rotation(t, aid, 2, said, d.pub(t, 1))
	if w := d.ask("tok", 1, raw2); !signedBy(w, d.pub(t, 1), raw2) {
		t.Fatalf("the committed key did not sign the second rotation: %d %s", w.Code, w.Body)
	}

	notMine, _ := d.rotation(t, aid, 1, d.org.icpSAID, d.pub(t, 5))
	other, _ := d.rotation(t, "EOTHERAID", 1, "EOTHERAID", d.pub(t, 0))
	beyond, _ := d.rotation(t, aid, 3, said, d.pub(t, 2))
	for name, c := range map[string]struct {
		w    *httptest.ResponseRecorder
		want int
	}{
		"a rotation that does not reveal the key":  {d.ask("tok", 0, notMine), http.StatusConflict},
		"a rotation of some other identity":        {d.ask("tok", 0, other), http.StatusBadRequest},
		"a key beyond the one committed to":        {d.ask("tok", 2, beyond), http.StatusBadRequest},
		"an invitation this device never accepted": {d.ask("other", 0, raw), http.StatusNotFound},
		"bytes that are not an event":              {d.ask("tok", 0, []byte("sign me")), http.StatusBadRequest},
	} {
		if c.w.Code != c.want {
			t.Errorf("%s: answered %d (%s), want %d", name, c.w.Code, c.w.Body, c.want)
		}
	}
}

// Once a device has signed an event at a place in the organisation's key
// history, it signs that event again (an answer lost on the way back) and no
// other there: two signed events at one place are two histories.
func TestADeviceSignsOneEventAtEachPlaceOfTheOrganisationsLog(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	raw, _ := d.rotation(t, d.org.aid, 1, d.org.icpSAID, d.pub(t, 0), d.pub(t, 7))
	if w := d.ask("tok", 0, raw); w.Code != http.StatusOK {
		t.Fatalf("the first rotation was not signed: %d %s", w.Code, w.Body)
	}
	if w := d.ask("tok", 0, raw); !signedBy(w, d.pub(t, 0), raw) {
		t.Fatalf("the same rotation, asked again, was not signed again: %d %s", w.Code, w.Body)
	}
	fork, _ := d.rotation(t, d.org.aid, 1, d.org.icpSAID, d.pub(t, 0), d.pub(t, 8))
	if w := d.ask("tok", 0, fork); w.Code != http.StatusConflict {
		t.Fatalf("a second, different rotation at the same place was answered %d (%s), want 409", w.Code, w.Body)
	}
}

// A first rotation goes where the organisation's key history ends, as this
// device reads it and the history's witness holds it, not where the
// organisation says it does.
func TestADeviceSignsOnlyARotationThatFollowsTheOrganisationsLog(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	_, elsewhere := d.rotation(t, d.org.aid, 1, d.org.icpSAID, d.pub(t, 9))
	afterUnheld, _ := d.rotation(t, d.org.aid, 1, elsewhere, d.pub(t, 0))
	pastTheEnd, _ := d.rotation(t, d.org.aid, 2, d.org.icpSAID, d.pub(t, 0))
	for name, raw := range map[string][]byte{
		"after an event the history does not hold": afterUnheld,
		"past the end of the history":              pastTheEnd,
	} {
		if w := d.ask("tok", 0, raw); w.Code != http.StatusConflict {
			t.Errorf("%s: answered %d (%s), want 409", name, w.Code, w.Body)
		}
	}
}

// An organisation that shows its owners a shortened history (an event its
// witness holds, left out) is caught by the witness, and nothing is signed.
func TestADeviceIsNotShownAShortenedHistory(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	p1, _ := d.org.signers[1].PublicKey()
	p2, _ := d.org.signers[2].PublicKey()
	rot, err := d.org.eng.Rotate(drivers.RotationRequest{Name: d.org.name, NewPublicKey: p1, NewNextPublicKey: p2})
	if err != nil {
		t.Fatal(err)
	}
	held, _ := base64.StdEncoding.DecodeString(rot.RawBytesB64)
	if err := d.witness.takes(t, d.org.aid, held, sign(t, d.org.signers[1], held)); err != nil {
		t.Fatal(err)
	}
	// The organisation's address still serves only the inception.
	raw, _ := d.rotation(t, d.org.aid, 1, d.org.icpSAID, d.pub(t, 0))
	if w := d.ask("tok", 0, raw); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "witnesses") {
		t.Fatalf("a rotation on a shortened history was answered %d (%s), want a 409 from the witness", w.Code, w.Body)
	}
}

// An organisation holds its own keys, so it can write a branch of its history
// that cuts every witness and show its owners that instead. A history that
// named witnesses and names none now has nobody to confirm it, and nothing is
// signed onto it.
func TestADeviceSignsNothingOntoAHistoryThatCutItsWitnesses(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	cut, sig := d.org.rotateCutting(t, d.witness.witnessKey)
	ev, err := keri.ParseEvent(cut)
	if err != nil {
		t.Fatal(err)
	}
	d.served = append(d.served, map[string]interface{}{
		"raw_bytes_b64":  base64.StdEncoding.EncodeToString(cut),
		"cesr_signature": sig,
	})
	raw, _ := d.rotation(t, d.org.aid, 2, ev.SAID, d.pub(t, 0))
	if w := d.ask("tok", 0, raw); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "names no witnesses now") {
		t.Fatalf("a rotation onto a history that cut its witnesses was answered %d (%s), want 409", w.Code, w.Body)
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

// A phone's Identity Agent that restarts between the two signatures of a
// hand-over can still make the second: the invitation, and the first rotation
// it signed, were kept on disk. Without that the first rotation would be in the
// log and nothing could sign the next.
func TestAnAgentThatRestartedStillSignsTheSecondRotation(t *testing.T) {
	d := aCeremonyDeviceOf(t)
	raw1, said := d.rotation(t, d.org.aid, 1, d.org.icpSAID, d.pub(t, 0))
	if w := d.ask("tok", 0, raw1); w.Code != http.StatusOK {
		t.Fatalf("the first rotation was not signed: %d %s", w.Code, w.Body)
	}
	raw, _ := d.rotation(t, d.org.aid, 2, said, d.pub(t, 1))

	d.s.redeemedInvites = redeemedInviteBook{} // the Identity Agent was restarted
	if w := d.ask("tok", 1, raw); !signedBy(w, d.pub(t, 1), raw) {
		t.Fatalf("after a restart the second rotation was not signed: %d %s", w.Code, w.Body)
	}

	// An invitation that was never into a ceremony is not kept, so it is not
	// there to be signed for after a restart either.
	d.s.redeemedInvites = redeemedInviteBook{}
	if w := d.ask("never", 1, raw); w.Code != http.StatusNotFound {
		t.Fatalf("an invitation nobody redeemed was signed for: %d", w.Code)
	}
}
