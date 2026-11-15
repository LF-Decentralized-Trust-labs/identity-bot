package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"

	"identity-agent-core/enrolsecret"
	"identity-agent-core/iacrypto"
)

// The owners ceremony against a real engine and real device keys (T-1160).
//
// The box holds its own key. Each device is a test double: an Ed25519 seed that
// signs the bytes the ceremony's route hands it, at the places the event gives
// it, and returns the signature through the route a device's app uses. Nothing
// in the core is faked; what is under test is that the ceremony ends "applied"
// with a log keri-go verifies, where it used to end "failed" with any device
// member (see a_single_key_identity_rotates_to_its_devices_test.go).

func (k aSigner) pub() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(k.seed).Public().(ed25519.PublicKey)
}

const (
	deviceA = "EDeviceAPairwiseAID000000000000000000000000"
	deviceC = "EDeviceCPairwiseAID000000000000000000000000"
)

type aCeremonyWorld struct {
	s    *CoreServer
	r    chi.Router
	a, c []aSigner // the devices' keys: now, next, the one after
	c0   *OwnerCeremony
}

// aCeremonyOfTwoDevices has the box found an identity on keys it derives, and two
// devices accept an ownership ceremony. pq gives each device a post-quantum
// commitment beside its classical next key.
func aCeremonyOfTwoDevices(t *testing.T, handOver, pq bool) *aCeremonyWorld {
	t.Helper()
	s := foundOnDerivedKeys(t, []string{iacrypto.NonTransferableAIDQB64(signerSeeds(1, 90)[0].pub())})
	s.localOwnerSecret = testOwnerSecret
	keys, err := s.ownRotationKeys()
	if err != nil {
		t.Fatal(err)
	}
	w := &aCeremonyWorld{s: s, a: signerSeeds(3, 10), c: signerSeeds(3, 20), r: chi.NewRouter()}
	w.r.Get("/api/signer/invites/{token}/ceremony-event", s.handleCeremonyEvent)
	w.r.Post("/api/signer/invites/{token}/ceremony-signature", s.handleCeremonySignature)

	invitee := func(name, aid, token string, k []aSigner, seedBase int) CeremonyInvitee {
		inv := CeremonyInvitee{Name: name, TokenDigest: enrolsecret.Digest(token), PairwiseAID: aid,
			PublicKey: k[0].key(), NextPublicKey: k[1].key()}
		if handOver {
			inv.AfterNextPublicKey = k[2].key()
		}
		if pq {
			inv.NextPostQuantumDigest = digestOfSeed(t, signerSeeds(1, seedBase)[0].seed)
			if handOver {
				inv.AfterNextPostQuantumDigest = digestOfSeed(t, signerSeeds(1, seedBase+1)[0].seed)
			}
		}
		return inv
	}
	c := &OwnerCeremony{ID: "c1", Threshold: 2, Status: ceremonyCollecting, HandOver: handOver,
		OwnPublicKey: keys.Current, OwnNextPublicKey: keys.Next,
		Invited: []CeremonyInvitee{invitee("C", deviceC, "tok-c", w.c, 40), invitee("A", deviceA, "tok-a", w.a, 30)}}
	ceremonyMu.Lock()
	if err := s.saveCeremony(c); err != nil {
		t.Fatal(err)
	}
	ceremonyMu.Unlock()
	s.completeCeremonyIfReady(c)
	return w
}

func (w *aCeremonyWorld) ceremony(t *testing.T) *OwnerCeremony {
	t.Helper()
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()
	c, err := w.s.loadCeremony()
	if err != nil || c == nil {
		t.Fatal(err)
	}
	return c
}

// fetch is a device asking for the event it is to sign.
func (w *aCeremonyWorld) fetch(t *testing.T, token string) (raw []byte, d string, code int) {
	t.Helper()
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/signer/invites/"+token+"/ceremony-event", nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK {
		return nil, "", rec.Code
	}
	raw, _ = base64.StdEncoding.DecodeString(out["raw_b64"].(string))
	return raw, out["d"].(string), rec.Code
}

// sign is a device returning its signature.
func (w *aCeremonyWorld) sign(t *testing.T, token, d string, sigs ...string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"d": d, "sigs": sigs})
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/signer/invites/"+token+"/ceremony-signature", bytes.NewReader(b)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// indexOf is where a digest sits in the event's next list.
func placeOfDigest(t *testing.T, raw []byte, digest string) int {
	t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range ev.NextDigest {
		if d == digest {
			return i
		}
	}
	t.Fatalf("%s is not among the next digests %v", digest, ev.NextDigest)
	return -1
}

// The ceremony ends "applied" with real device members, and the box's key is in
// neither the signing nor the next set of the log it leaves.
func TestAHandOverCeremonyWithRealDevicesIsAppliedAndDropsTheBox(t *testing.T) {
	w := aCeremonyOfTwoDevices(t, true, false)
	if c := w.ceremony(t); c.Status != ceremonySigning || c.Stage != stageFirst {
		t.Fatalf("after the last acceptance the ceremony is %q at %q (%s): it should be waiting for the devices to sign the first rotation", c.Status, c.Stage, c.Detail)
	}
	own, _ := w.s.DataStore.GetIdentity()
	box0 := own.PublicKey

	// The first rotation: the box has signed; each device checks and signs. The keys
	// are the box's committed key first, then the devices by identifier.
	raw1, d1, code := w.fetch(t, "tok-a")
	if code != http.StatusOK {
		t.Fatalf("the first rotation was not offered to a device: %d", code)
	}
	ev1, _ := keri.ParseEvent(raw1)
	if len(ev1.Keys) != 3 || ev1.Keys[1] != w.a[0].key() || ev1.Keys[2] != w.c[0].key() || len(ev1.NextDigest) != 2 {
		t.Fatalf("the first rotation's keys %v and next digests %v are not the box, then both devices, committing to the devices alone", ev1.Keys, ev1.NextDigest)
	}
	if code, out := w.sign(t, "tok-a", d1, w.a[0].at(t, raw1, 1, -1)); code != http.StatusAccepted {
		t.Fatalf("one device of two signed and the rotation was not held: %d %v", code, out)
	}
	code, out := w.sign(t, "tok-c", d1, w.c[0].at(t, raw1, 2, -1))
	if code != http.StatusCreated || out["next_stage"] != stageSecond {
		t.Fatalf("the second device signed and the hand-over did not go on to its second rotation: %d %v", code, out)
	}

	// The second: the devices' next keys, alone.
	raw2, d2, code := w.fetch(t, "tok-c")
	if code != http.StatusOK || d2 == d1 {
		t.Fatalf("the second rotation was not offered: %d", code)
	}
	ev2, _ := keri.ParseEvent(raw2)
	if len(ev2.Keys) != 2 || ev2.Keys[0] != w.a[1].key() || ev2.Keys[1] != w.c[1].key() {
		t.Fatalf("the second rotation's keys are %v, want the devices' next keys", ev2.Keys)
	}
	pa, pc := placeOfDigest(t, raw1, digestOfSeed(t, w.a[1].seed)), placeOfDigest(t, raw1, digestOfSeed(t, w.c[1].seed))
	if code, _ := w.sign(t, "tok-a", d2, w.a[1].at(t, raw2, 0, pa)); code != http.StatusAccepted {
		t.Fatalf("one device's signature over the second rotation: %d", code)
	}
	if code, out := w.sign(t, "tok-c", d2, w.c[1].at(t, raw2, 1, pc)); code != http.StatusCreated || out["applied"] != true {
		t.Fatalf("both devices signed the second rotation and the ceremony is not applied: %d %v", code, out)
	}
	c := w.ceremony(t)
	if c.Status != ceremonyApplied || c.RotationSAID == "" || c.PendingRawB64 != "" {
		t.Fatalf("the ceremony is %q (%s), rotation %q", c.Status, c.Detail, c.RotationSAID)
	}

	// The log is one keri-go verifies, and no box key is anywhere in what the last event
	// commits to or is signed by.
	m, _ := storedLog(t, w.s, own.AID)
	_ = m
	events, _ := w.s.DataStore.GetEvents(own.AID)
	if len(events) != 3 {
		t.Fatalf("the log holds %d events, want the founding and two rotations", len(events))
	}
	boxDigest, _ := keri.NextDigest(ev1.Keys[0])
	for _, d := range ev2.NextDigest {
		if d == boxDigest {
			t.Error("the second rotation still commits to the box's key")
		}
	}

	// After the hand-over this Identity Agent holds, and derives, no key of it.
	after, _ := w.s.DataStore.GetIdentity()
	if after.PublicKey == box0 || after.PublicKey != w.a[1].key() {
		t.Errorf("the identity's current key is %q, want the first device's next key", after.PublicKey)
	}
	if !w.s.keyIsElsewhere() {
		t.Error("the box still reads the identity's key as its own")
	}
	if _, err := w.s.ownRotationKeys(); err == nil {
		t.Error("the box still derives a rotation key for the identity")
	}
	if _, err := w.s.signEventFor(own.AID, box0, []byte("anything")); err == nil {
		t.Error("the box still signs for the identity with the key it derived")
	}
	if _, ok := w.s.eventSigners.Load(own.AID); ok {
		t.Error("the box still holds a signer for the identity")
	}
	if err := w.s.mayRotateHere(own.AID); err == nil {
		t.Error("the box would still rotate the identity")
	}
}

// With a post-quantum commitment beside each classical one the next-keys
// threshold is weighted, each owner worth one share however many digests it
// committed, and two devices each signing at their classical digest meet it.
func TestAHandOverWithPostQuantumCommitmentsUsesWeightedThresholds(t *testing.T) {
	w := aCeremonyOfTwoDevices(t, true, true)
	raw1, d1, _ := w.fetch(t, "tok-a")
	ev1, _ := keri.ParseEvent(raw1)
	var body struct {
		Nt json.RawMessage `json:"nt"`
	}
	_ = json.Unmarshal(raw1, &body)
	if len(ev1.NextDigest) != 4 || string(body.Nt) != `[{"1/2":["1","1"]},{"1/2":["1","1"]}]` {
		t.Fatalf("next digests %d, nt %s: want four digests under one weighted share per owner", len(ev1.NextDigest), body.Nt)
	}
	w.sign(t, "tok-a", d1, w.a[0].at(t, raw1, 1, -1))
	if code, out := w.sign(t, "tok-c", d1, w.c[0].at(t, raw1, 2, -1)); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	raw2, d2, _ := w.fetch(t, "tok-a")
	pa, pc := placeOfDigest(t, raw1, digestOfSeed(t, w.a[1].seed)), placeOfDigest(t, raw1, digestOfSeed(t, w.c[1].seed))
	w.sign(t, "tok-a", d2, w.a[1].at(t, raw2, 0, pa))
	if code, out := w.sign(t, "tok-c", d2, w.c[1].at(t, raw2, 1, pc)); code != http.StatusCreated || out["applied"] != true {
		t.Fatalf("%d %v", code, out)
	}
}

// Bringing devices in alongside the box is one rotation, committing to the
// box's own next key as well, and it too ends "applied".
func TestACeremonyAlongsideTheBoxIsOneRotationAndIsApplied(t *testing.T) {
	w := aCeremonyOfTwoDevices(t, false, false)
	raw, d, code := w.fetch(t, "tok-a")
	if code != http.StatusOK {
		t.Fatalf("%d", code)
	}
	ev, _ := keri.ParseEvent(raw)
	if len(ev.NextDigest) != 3 {
		t.Fatalf("next digests %v: the box's own next key and each device's", ev.NextDigest)
	}
	w.sign(t, "tok-a", d, w.a[0].at(t, raw, 1, -1))
	if code, out := w.sign(t, "tok-c", d, w.c[0].at(t, raw, 2, -1)); code != http.StatusCreated || out["applied"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if c := w.ceremony(t); c.Status != ceremonyApplied {
		t.Fatalf("%q %s", c.Status, c.Detail)
	}
}

// A signature that is not the device's, over bytes that are not the event, or
// from somebody who holds no invite code, changes nothing.
func TestACeremonyTakesNoSignatureItCannotCheck(t *testing.T) {
	w := aCeremonyOfTwoDevices(t, true, false)
	raw, d, _ := w.fetch(t, "tok-a")
	if _, _, code := w.fetch(t, "no-such-code"); code != http.StatusNotFound {
		t.Errorf("an unknown code was offered the event: %d", code)
	}
	if code, _ := w.sign(t, "tok-a", "EWrongDigest", w.a[0].at(t, raw, 1, -1)); code != http.StatusConflict {
		t.Errorf("a signature naming another event: %d", code)
	}
	if code, _ := w.sign(t, "tok-a", d, w.c[0].at(t, raw, 1, -1)); code == http.StatusAccepted || code == http.StatusCreated {
		t.Errorf("a signature by a key that is not in the event at that place was taken: %d", code)
	}
	if c := w.ceremony(t); c.Status != ceremonySigning {
		t.Errorf("the ceremony moved to %q", c.Status)
	}
}
