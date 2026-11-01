package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A witnessed identity whose events are signed after they are added: by a
// device that holds the key, or late, after a device lost its connection
// between the two steps. A witness takes only signed events, so each event
// signed after the fact must reach the identity's designated witnesses when
// its signature is recorded, in order and with nothing skipped, interactions
// as well as rotations, and only once.
type lateSignedWorld struct {
	s        *CoreServer
	aid      string
	mu       sync.Mutex
	received []map[string]any // what the witness took, in order
	held     []store.EventRecord
	unsigned int // events sent to the witness with no signature
}

func newLateSignedWorld(t *testing.T) *lateSignedWorld {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	name := iacrypto.NonTransferableAIDQB64(pub)
	s := foundOnDerivedKeys(t, []string{name})
	if _, ok := s.KeriDriver.(drivers.KELKeeper); !ok {
		t.Fatal("the engine does not keep key logs")
	}
	s.localOwnerSecret = testOwnerSecret
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "active", IsWitness: true})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: name, IsCommercial: true})
	id, _ := s.DataStore.GetIdentity()
	w := &lateSignedWorld{s: s, aid: id.AID}
	// The witness answers its tip from what it holds, and takes an event only
	// if it is signed and is the next one.
	s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		return witnessTip(url, w.held, priv, name), nil
	}
	s.WitnessService.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		var req map[string]any
		json.Unmarshal(body, &req)
		raw, _ := base64.StdEncoding.DecodeString(req["event_b64"].(string))
		var ev map[string]any
		json.Unmarshal(raw, &ev)
		w.mu.Lock()
		defer w.mu.Unlock()
		sig, _ := req["cesr_signature"].(string)
		if sig == "" {
			w.unsigned++
		}
		if sig == "" || ev["s"] != fmt.Sprintf("%x", len(w.held)) {
			return nil, fmt.Errorf("refused")
		}
		w.received = append(w.received, ev)
		w.held = append(w.held, store.EventRecord{RawBytesB64: req["event_b64"].(string), SequenceNumber: len(w.held)})
		return nil, nil
	}
	s.router = s.buildRouter("")
	return w
}

// foundOnDerivedKeys founds an identity whose keys all come from the agent's
// root seed, committing to the next one on the same branch, so a rotation can
// be built and signed here: key 0 founds it, key 1 is what it commits to.
func foundOnDerivedKeys(t *testing.T, witnesses []string) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t)
	e := keriengine.New()
	s.KeriDriver = e
	s.engineSigns()
	root, err := ensureRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	key := func(n int) ([]byte, string) {
		seed, _ := backup.DerivePairwiseSeed(root, 0, n)
		return seed, iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	seed0, pub0 := key(0)
	_, pub1 := key(1)
	founding := keriengine.New()
	icp, err := founding.Incept(drivers.InceptionRequest{PublicKey: pub0, NextPublicKey: pub1, Name: "owner", Witnesses: witnesses, Toad: 1})
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := founding.GetKel("owner")
	raw, _ := base64.StdEncoding.DecodeString(icp.RawBytesB64)
	sig, err := signEventBytes(raw, seed0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(kel.KEL[0])
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: icp.AID, PublicKey: pub0, NextKeyDigest: icp.NextKeyDigest}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(store.EventRecord{AID: icp.AID, SequenceNumber: 0, EventType: "icp",
		EventJSON: string(body), PublicKey: pub0, RawBytesB64: icp.RawBytesB64, CesrSignature: sig}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: icp.AID, PublicKey: pub0,
		NextKeyDigest: icp.NextKeyDigest, KEL: kel.KEL, RawEventsB64: kel.RawEventsB64}); err != nil {
		t.Fatal(err)
	}
	return s
}

// strand stores an event without its signature, as an event added by a
// device that has not yet signed it, and returns the signature it should have.
func (w *lateSignedWorld) strand(t *testing.T, sn int) string {
	t.Helper()
	events, _ := w.s.DataStore.GetEvents(w.aid)
	for _, ev := range events {
		if ev.SequenceNumber == sn {
			sq := w.s.DataStore.(*store.SQLiteStore)
			if _, err := sq.DB().Exec(`UPDATE kel SET cesr_signature = '' WHERE aid = ? AND seq_num = ?`, w.aid, sn); err != nil {
				t.Fatal(err)
			}
			return ev.CesrSignature
		}
	}
	t.Fatalf("no event %d", sn)
	return ""
}

func (w *lateSignedWorld) attach(t *testing.T, sn int, sig string) {
	t.Helper()
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, local("POST", "/api/events/signature",
		fmt.Sprintf(`{"aid":%q,"sequence_number":%d,"cesr_signature":%q}`, w.aid, sn, sig)))
	if rec.Code != http.StatusOK {
		t.Fatalf("recording the signature over event %d was answered %d %s", sn, rec.Code, rec.Body.String())
	}
}

func (w *lateSignedWorld) waitFor(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < 300; i++ {
		w.mu.Lock()
		got := len(w.received)
		w.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	t.Fatalf("the witness took %d events, not %d: %v", len(w.received), n, w.received)
}

func (w *lateSignedWorld) signedFlags(t *testing.T) []bool {
	t.Helper()
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, local("GET", "/api/kel?name="+w.aid, ""))
	var out struct {
		Signed []bool `json:"signed"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Signed
}

// interact appends an interaction, stored as the core stores its own, and
// returns its sequence number.
func (w *lateSignedWorld) interact(t *testing.T) int {
	t.Helper()
	res, err := w.s.KeriDriver.Interact(w.aid, []interface{}{map[string]interface{}{"d": "Eanchor"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.s.saveOwnInteraction(w.aid, res.IxnEvent, res.RawBytesB64, res.SequenceNumber, ""); err != nil {
		t.Fatal(err)
	}
	return res.SequenceNumber
}

// rotate appends a rotation to the key founding committed to and stores it
// unsigned, as a device's rotation is stored; it returns the sequence number
// and the signature the new key makes over it.
func (w *lateSignedWorld) rotate(t *testing.T) (int, string) {
	t.Helper()
	keys, err := w.s.ownRotationKeys()
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.s.KeriDriver.RotateAid(w.aid, keys.Current, keys.Next)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := w.s.DataStore.GetIdentity()
	root, _ := ensureRootSeed(w.s.DataDir)
	seed, _ := backup.DerivePairwiseSeed(root, id.DerivationIndex, id.KeyGeneration+1)
	raw, _ := base64.StdEncoding.DecodeString(res.RawBytesB64)
	sig, err := signEventBytes(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(res.RotationEvent)
	if err := w.s.DataStore.SaveEvent(store.EventRecord{
		AID: w.aid, SequenceNumber: res.SequenceNumber, EventType: "rot", EventJSON: string(body),
		PublicKey: res.NewPublicKey, NextKeyDigest: res.NewNextKeyDigest, RawBytesB64: res.RawBytesB64,
	}); err != nil {
		t.Fatal(err)
	}
	return res.SequenceNumber, sig
}

func TestEventsSignedLaterReachTheWitnessesInOrder(t *testing.T) {
	w := newLateSignedWorld(t)
	before, _ := w.s.DataStore.GetEvents(w.aid)

	ixn := w.interact(t)
	ixnSig := w.strand(t, ixn)
	if got := w.signedFlags(t); len(got) <= ixn || got[ixn] {
		t.Fatalf("the key log does not say the stranded interaction is unsigned: %v", got)
	}
	rot, rotSig := w.rotate(t)

	w.attach(t, ixn, ixnSig)
	w.waitFor(t, len(before)+1)
	w.attach(t, rot, rotSig)
	w.waitFor(t, len(before)+2)

	w.mu.Lock()
	got := append([]map[string]any{}, w.received...)
	w.mu.Unlock()
	if got[ixn]["t"] != "ixn" || got[rot]["t"] != "rot" {
		t.Fatalf("the witness did not take the interaction and then the rotation: %v", got)
	}
	if flags := w.signedFlags(t); !flags[ixn] || !flags[rot] {
		t.Fatalf("the key log does not say both are now signed: %v", flags)
	}

	// No event was ever sent without its signature: a witness refuses one,
	// and sending it only turns a gap here into a refusal there.
	w.mu.Lock()
	if w.unsigned != 0 {
		w.mu.Unlock()
		t.Fatalf("%d events were sent to the witness unsigned", w.unsigned)
	}
	// The same signature again changes nothing, so it sends nothing, even to
	// a witness that has since fallen behind and would take the rotation.
	w.held = w.held[:len(w.held)-1]
	w.received = nil
	w.mu.Unlock()
	w.attach(t, rot, rotSig)
	time.Sleep(300 * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.received) != 0 {
		t.Fatalf("recording a signature already held sent %d events again", len(w.received))
	}
}

// An event the key log lists and the store does not hold is not reported as
// unsigned: a device would try to sign it, be refused because there is
// nothing to attach the signature to, and stop signing anything.
func TestAnEventNotStoredIsNotReportedUnsigned(t *testing.T) {
	w := newLateSignedWorld(t)
	rot, _ := w.rotate(t)
	sq := w.s.DataStore.(*store.SQLiteStore)
	if _, err := sq.DB().Exec(`DELETE FROM kel WHERE aid = ? AND seq_num = ?`, w.aid, rot); err != nil {
		t.Fatal(err)
	}
	flags := w.signedFlags(t)
	if len(flags) <= rot {
		t.Fatalf("the key log has no flag for event %d: %v", rot, flags)
	}
	if !flags[rot] {
		t.Fatalf("an event the store does not hold was reported unsigned: %v", flags)
	}
}
