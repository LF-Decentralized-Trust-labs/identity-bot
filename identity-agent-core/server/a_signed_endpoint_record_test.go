package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/endpointrecord"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// An identity this witness holds a key log for: an inception, and optionally a
// rotation to the next key. seeds[0] signs the inception and seeds[1] the
// rotation.
type heldIdentity struct {
	aid   string
	seeds [][]byte
	pubs  []string
}

func holdAnIdentity(t *testing.T, ws witness.Store, rotated bool) heldIdentity {
	t.Helper()
	return holdAnIdentityNaming(t, ws, rotated, nil)
}

// aWitnessName is a real non-transferable witness identifier.
func aWitnessName() string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return iacrypto.NonTransferableAIDQB64(pub)
}

// holdAnIdentityNaming is holdAnIdentity whose inception names the given
// witnesses, as a contact's does.
func holdAnIdentityNaming(t *testing.T, ws witness.Store, rotated bool, witnesses []string) heldIdentity {
	t.Helper()
	h := heldIdentity{}
	for i := 0; i < 3; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		h.seeds = append(h.seeds, priv.Seed())
		h.pubs = append(h.pubs, iacrypto.VerkeyQB64(priv.Public().(ed25519.PublicKey)))
	}
	d1, _ := keri.NextDigest(h.pubs[1])
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{h.pubs[0]}, NextDigests: []string{d1}, Witnesses: witnesses, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(icp)
	h.aid = ev.Identifier
	save := func(sn int, said string, raw []byte, seed []byte) {
		sig, err := login.SignString(string(raw), seed)
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.StoreKelEvent(witness.KelEvent{
			SignerAID: h.aid, SequenceNum: sn, EventJSON: string(raw), EventSAID: said,
			StoredAt:    time.Now().UTC().Format(time.RFC3339),
			RawBytesB64: base64.StdEncoding.EncodeToString(raw), CesrSignature: sig,
		}); err != nil {
			t.Fatal(err)
		}
	}
	save(0, ev.SAID, icp, h.seeds[0])
	if rotated {
		d2, _ := keri.NextDigest(h.pubs[2])
		rot, err := keri.BuildRotation(keri.RotationInput{
			Prefix: ev.Identifier, Keys: []string{h.pubs[1]}, PriorSAID: ev.SAID, SN: 1, NextDigests: []string{d2}, PriorWitnesses: witnesses,
		})
		if err != nil {
			t.Fatal(err)
		}
		rev, _ := keri.ParseEvent(rot)
		save(1, rev.SAID, rot, h.seeds[1])
	}
	return h
}

// A witness reachable over HTTP through the router a running agent really has,
// by a caller who is nobody's owner.
type endpointWitness struct {
	core *CoreServer
	url  string
}

func anEndpointWitness(t *testing.T) endpointWitness {
	t.Helper()
	s := witnessWithStore(t)
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, nil, witness.BackendDesktop)
	srv := httptest.NewServer(s.buildRouter())
	t.Cleanup(srv.Close)
	return endpointWitness{core: s, url: srv.URL}
}

func (w endpointWitness) publish(t *testing.T, aid string, record any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"aid": aid, "record": record})
	resp, err := http.Post(w.url+"/api/witness/endpoint", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (w endpointWitness) lookup(t *testing.T, aid string) (int, endpointrecord.Record) {
	t.Helper()
	resp, err := http.Get(w.url + "/api/witness/endpoint/" + aid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Record endpointrecord.Record `json:"record"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Record
}

func signedRecord(t *testing.T, aid, origin string, ago time.Duration, seed []byte) endpointrecord.Record {
	t.Helper()
	r, err := endpointrecord.Sign(aid, origin, time.Now().Add(-ago), seed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The route a counterparty with a dead address has to use is open, and
// answers with the record exactly as its controller signed it, which the asker
// can check for itself.
func TestAWitnessKeepsAndServesAControllersOwnSignedRecord(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)

	if code, _ := w.lookup(t, id.aid); code != http.StatusNotFound {
		t.Fatalf("a lookup before any record was answered %d, want 404", code)
	}
	rec := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[0])
	if code, out := w.publish(t, id.aid, rec); code != http.StatusOK {
		t.Fatalf("the controller's own record was refused: %d %v", code, out)
	}
	code, got := w.lookup(t, id.aid)
	if code != http.StatusOK || got != rec {
		t.Fatalf("lookup gave %d %+v, want the record as signed: %+v", code, got, rec)
	}
	key, _, _ := iacrypto.DecodeEd25519Key(id.pubs[0], false)
	if err := got.Verify(key, time.Now()); err != nil {
		t.Fatalf("the record the witness served does not verify for the asker: %v", err)
	}
}

// Nothing stores on who sent it. Each of these was accepted before: the route
// kept whatever it was handed.
func TestAWitnessKeepsNothingThatIsNotTheControllersOwnStatement(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	stranger := holdAnIdentity(t, w.core.WitnessService.Store, false)
	good := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[0])

	forged := signedRecord(t, id.aid, "https://proxy.example.net:443", time.Minute, stranger.seeds[0])
	tampered := good
	tampered.Origin = "https://proxy.example.net:443"
	unsigned := good
	unsigned.Signature = ""
	future := signedRecord(t, id.aid, "https://org.example.com:443", -time.Hour, id.seeds[0])
	badOrigin := endpointrecord.Record{Type: endpointrecord.Type, AID: id.aid, Origin: "https://org.example.com",
		Issued: good.Issued}
	msg, _ := badOrigin.SignedBytes()
	badOrigin.Signature, _ = iacrypto.MatterFixedQB64("0B", ed25519.Sign(ed25519.NewKeyFromSeed(id.seeds[0]), msg))

	for name, c := range map[string]struct {
		aid    string
		record any
		want   int
	}{
		"a record signed by somebody else's key":    {id.aid, forged, 403},
		"a record changed after it was signed":      {id.aid, tampered, 403},
		"a record with no signature":                {id.aid, unsigned, 403},
		"a record issued in the future":             {id.aid, future, 403},
		"an origin not in its one spelling":         {id.aid, badOrigin, 403},
		"a record filed under another identifier":   {stranger.aid, good, 400},
		"a record for an identifier not witnessed":  {"ENobodyHeldHere", endpointrecord.Record{Type: endpointrecord.Type, AID: "ENobodyHeldHere", Origin: "https://x.example:443", Issued: good.Issued, Signature: good.Signature}, 403},
		"the unsigned form this route used to keep": {id.aid, map[string]any{"v": "KERI10JSON0000e4_", "t": "rpy", "d": "ESaid", "r": "/loc/scheme", "a": map[string]any{"eid": id.aid, "scheme": "https", "url": "https://proxy.example.net"}}, 400},
		"a key event": {id.aid, map[string]any{"v": "KERI10JSON000159_", "t": "icp", "d": "EInceptionSaid", "r": "/icp", "s": "0"}, 400},
		"a record with a field beside the signed ones": {id.aid, map[string]any{"type": good.Type, "aid": good.AID, "origin": good.Origin,
			"issued": good.Issued, "signature": good.Signature, "note": "unsigned"}, 400},
	} {
		if code, out := w.publish(t, c.aid, c.record); code != c.want {
			t.Errorf("%s: answered %d %v, want %d", name, code, out, c.want)
		}
	}
	if code, _ := w.lookup(t, id.aid); code != http.StatusNotFound {
		t.Errorf("after only refusals the witness holds a record (lookup %d)", code)
	}
}

// A newer record replaces an older one, an older one is refused whenever it
// arrives, and the same one again changes nothing.
func TestANewerRecordReplacesAndAnOlderOneIsRefused(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	old := signedRecord(t, id.aid, "https://old.example.com:443", 2*time.Hour, id.seeds[0])
	mid := signedRecord(t, id.aid, "https://new.example.com:443", time.Hour, id.seeds[0])
	newest := signedRecord(t, id.aid, "https://newest.example.com:8443", time.Minute, id.seeds[0])

	if code, out := w.publish(t, id.aid, mid); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := w.publish(t, id.aid, mid); code != 200 || out["unchanged"] != true {
		t.Fatalf("the same record again: %d %v", code, out)
	}
	if code, out := w.publish(t, id.aid, old); code != http.StatusConflict {
		t.Fatalf("an older record was answered %d %v, want 409", code, out)
	}
	if _, got := w.lookup(t, id.aid); got != mid {
		t.Fatalf("an older record displaced the held one: %+v", got)
	}
	if code, out := w.publish(t, id.aid, newest); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if _, got := w.lookup(t, id.aid); got != newest {
		t.Fatalf("lookup gave %+v, want the newest", got)
	}
	// Replayed after the newer one: refused, and the newer one still stands.
	if code, _ := w.publish(t, id.aid, mid); code != http.StatusConflict {
		t.Fatalf("a replayed record was answered %d, want 409", code)
	}
	if _, got := w.lookup(t, id.aid); got != newest {
		t.Fatalf("a replay displaced the newest record: %+v", got)
	}
}

// The key that signs is the one the key log names now. After a rotation the old
// key's records are refused, and a record from the new key is accepted.
func TestRotationsAreHonouredWhenCheckingARecord(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, true)

	byOld := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[0])
	if code, out := w.publish(t, id.aid, byOld); code != 403 {
		t.Fatalf("a record signed by the replaced key was answered %d %v", code, out)
	}
	byNew := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[1])
	if code, out := w.publish(t, id.aid, byNew); code != 200 {
		t.Fatalf("a record signed by the key in force was refused: %d %v", code, out)
	}
	byNext := signedRecord(t, id.aid, "https://org.example.com:9", 0, id.seeds[2])
	if code, _ := w.publish(t, id.aid, byNext); code != 403 {
		t.Fatalf("a record signed by a key not yet in force was accepted: %d", code)
	}
}

// A key log with an event nobody signed names no key, so nothing is accepted
// under it.
func TestALogWithAnUnsignedEventNamesNoKey(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	db := w.core.DataStore.(*store.SQLiteStore).DB()
	if _, err := db.Exec(`UPDATE witness_kel_events SET cesr_signature = '' WHERE signer_aid = ?`, id.aid); err != nil {
		t.Fatal(err)
	}
	rec := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[0])
	if code, _ := w.publish(t, id.aid, rec); code != http.StatusForbidden {
		t.Fatalf("a record under an unverifiable log was answered %d, want 403", code)
	}
}

// Whatever the reason a record is not kept that depends on the key log, the
// answer is the same, so the route cannot be used to learn which identities this
// witness holds a log for.
func TestTheRouteDoesNotSayWhichIdentitiesAreWitnessed(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	stranger := holdAnIdentity(t, w.core.WitnessService.Store, false)

	bad := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, stranger.seeds[0])
	codeHeld, outHeld := w.publish(t, id.aid, bad)
	unheld := signedRecord(t, "ENotHeldHere", "https://org.example.com:443", time.Minute, stranger.seeds[0])
	codeUnheld, outUnheld := w.publish(t, "ENotHeldHere", unheld)
	if codeHeld != codeUnheld || codeHeld != http.StatusForbidden {
		t.Fatalf("a held identity with a bad record: %d, an unheld one: %d", codeHeld, codeUnheld)
	}
	a, _ := json.Marshal(outHeld)
	b, _ := json.Marshal(outUnheld)
	if string(a) != string(b) {
		t.Fatalf("the two answers differ:\n%s\n%s", a, b)
	}
	// The read says the same of an identity that is witnessed and has no record
	// as of one that is not witnessed at all.
	if c1, _ := w.lookup(t, id.aid); c1 != http.StatusNotFound {
		t.Fatalf("lookup of a witnessed identity with no record: %d", c1)
	}
	if c2, _ := w.lookup(t, "ENotHeldHere"); c2 != http.StatusNotFound {
		t.Fatalf("lookup of an identity not witnessed: %d", c2)
	}
}

// A route open to anybody keeps one record per identifier, not one for every
// record ever sent.
func TestOnlyTheNewestRecordIsKept(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	for i := 5; i >= 1; i-- {
		rec := signedRecord(t, id.aid, "https://org.example.com:443", time.Duration(i)*time.Minute, id.seeds[0])
		// 5, 4, ... minutes ago: each is newer than the last.
		if code, out := w.publish(t, id.aid, rec); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	held, err := w.core.DataStore.GetEndpointRecords(id.aid)
	if err != nil || len(held) != 1 {
		t.Fatalf("%d rows held after five records (%v), want 1", len(held), err)
	}
}

// A record left by a key the identifier has since replaced is not ranked, so it
// cannot keep the legitimate newer one out.
func TestARecordOfAReplacedKeyCannotKeepTheCurrentOneOut(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, true)
	// Left behind before the rotation, issued as far ahead as is allowed.
	stale, err := endpointrecord.Sign(id.aid, "https://old.example.com:443", time.Now().Add(9*time.Minute), id.seeds[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := w.core.keepEndpointRecord(store.EndpointRecordHeld, stale, map[string]any{
		"type": stale.Type, "aid": stale.AID, "origin": stale.Origin, "issued": stale.Issued, "signature": stale.Signature}); err != nil {
		t.Fatal(err)
	}
	fresh := signedRecord(t, id.aid, "https://org.example.com:443", time.Minute, id.seeds[1])
	if code, out := w.publish(t, id.aid, fresh); code != 200 {
		t.Fatalf("the current key's record was kept out by a replaced key's: %d %v", code, out)
	}
	if _, got := w.lookup(t, id.aid); got != fresh {
		t.Fatalf("lookup gave %+v", got)
	}
}

// Two records for the same moment cannot both be kept.
func TestTwoRecordsArrivingTogetherAreNotBothKept(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	at := time.Now().Add(-time.Minute)
	a, _ := endpointrecord.Sign(id.aid, "https://a.example.com:443", at, id.seeds[0])
	b, _ := endpointrecord.Sign(id.aid, "https://b.example.com:443", at, id.seeds[0])
	codes := make(chan int, 16)
	for i := 0; i < 16; i++ {
		go func(i int) {
			rec := a
			if i%2 == 1 {
				rec = b
			}
			code, _ := w.publish(t, id.aid, rec)
			codes <- code
		}(i)
	}
	ok := 0
	for i := 0; i < 16; i++ {
		if c := <-codes; c == 200 {
			ok++
		}
	}
	held, _ := w.core.DataStore.GetEndpointRecords(id.aid)
	if len(held) != 1 {
		t.Fatalf("%d rows held", len(held))
	}
	_ = ok
}

// A counterparty that has to find an organisation that moved trusts the
// organisation's own signature and nothing a witness, or something in front of
// one, says; asks every witness and takes the newest; and is never taken back to
// an older address.
type contactWithWitnesses struct {
	core    *CoreServer
	contact heldIdentity
	serves  []func(contact heldIdentity) map[string]any
	// names are the witnesses the contact's inception names, in the order of serves.
	names []string
}

func aContactWithWitnesses(t *testing.T, verified bool, serves ...func(c heldIdentity) map[string]any) *contactWithWitnesses {
	t.Helper()
	s := witnessWithStore(t)
	other := anEndpointWitness(t)
	c := &contactWithWitnesses{core: s, serves: serves}
	var names []string
	for range serves {
		names = append(names, aWitnessName())
	}
	c.names = names
	c.contact = holdAnIdentityNaming(t, other.core.WitnessService.Store, false, names)
	for i := range serves {
		i := i
		wit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := c.serves[i](c.contact)
			if r.URL.Path != "/api/witness/endpoint/"+c.contact.aid || rec == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"controller_aid": c.contact.aid, "record": rec})
		}))
		t.Cleanup(wit.Close)
		name := names[i]
		if err := s.DataStore.SaveContact(store.ContactRecord{AID: name, OobiURL: wit.URL + "/public/oobi/" + name}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: c.contact.aid, KelVerified: verified, CurrentPublicKey: c.contact.pubs[0],
		KEL: heldAsStored(t, other.core.WitnessService.Store, c.contact.aid),
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// heldAsStored is the first n events of aid's log as a contact's log is kept
// once resolved: each entry the bytes it was published as, its signature and
// its text, and nothing else.
func heldAsStored(t *testing.T, ws witness.Store, aid string, n ...int) []map[string]interface{} {
	t.Helper()
	held, err := ws.GetKelEvents(aid)
	if err != nil {
		t.Fatal(err)
	}
	if len(n) > 0 {
		held = held[:n[0]]
	}
	var out []map[string]interface{}
	for _, e := range held {
		out = append(out, map[string]interface{}{
			"raw_bytes_b64": e.RawBytesB64, "cesr_signature": e.CesrSignature, "event_json": e.EventJSON,
		})
	}
	return out
}

func recordObject(r endpointrecord.Record) map[string]any {
	return map[string]any{"type": r.Type, "aid": r.AID, "origin": r.Origin, "issued": r.Issued, "signature": r.Signature}
}

func TestRecoveryBelievesOnlyWhatTheContactSigned(t *testing.T) {
	signed := func(origin string, ago time.Duration) func(heldIdentity) map[string]any {
		return func(c heldIdentity) map[string]any {
			return recordObject(signedRecord(t, c.aid, origin, ago, c.seeds[0]))
		}
	}
	t.Run("the contact's own record is the answer", func(t *testing.T) {
		c := aContactWithWitnesses(t, true, signed("https://moved.example.com:443", time.Minute))
		found, err := c.core.RecoverContactEndpoint(c.contact.aid)
		if err != nil {
			t.Fatal(err)
		}
		if found.Origin != "https://moved.example.com:443" || found.FoundVia != c.names[0] {
			t.Fatalf("got %+v", found)
		}
	})
	t.Run("an address a reverse proxy made up is refused", func(t *testing.T) {
		attacker := make([]byte, 32)
		_, _ = rand.Read(attacker)
		c := aContactWithWitnesses(t, true, func(c heldIdentity) map[string]any {
			return recordObject(signedRecord(t, c.aid, "https://proxy.example.net:443", time.Minute, attacker))
		})
		if found, err := c.core.RecoverContactEndpoint(c.contact.aid); err == nil {
			t.Fatalf("an address not signed by the contact was taken: %+v", found)
		}
	})
	t.Run("a record for somebody else is refused", func(t *testing.T) {
		c := aContactWithWitnesses(t, true, func(c heldIdentity) map[string]any {
			return recordObject(signedRecord(t, "ESomebodyElse", "https://moved.example.com:443", time.Minute, c.seeds[0]))
		})
		if found, err := c.core.RecoverContactEndpoint(c.contact.aid); err == nil {
			t.Fatalf("%+v", found)
		}
	})
	t.Run("a log that was never verified checks nothing", func(t *testing.T) {
		c := aContactWithWitnesses(t, false, signed("https://moved.example.com:443", time.Minute))
		_, err := c.core.RecoverContactEndpoint(c.contact.aid)
		if err == nil || !strings.Contains(err.Error(), "not verified") {
			t.Fatalf("a record was checked against an unverified log: %v", err)
		}
	})
	t.Run("a withdrawal is not an address", func(t *testing.T) {
		c := aContactWithWitnesses(t, true, signed("", time.Minute))
		if found, err := c.core.RecoverContactEndpoint(c.contact.aid); err == nil {
			t.Fatalf("%+v", found)
		}
	})
	t.Run("a withdrawal outranks an older address another witness still holds", func(t *testing.T) {
		c := aContactWithWitnesses(t, true,
			signed("", time.Minute),                          // the contact's newest word
			signed("https://old.example.com:443", time.Hour)) // a stale witness
		if found, err := c.core.RecoverContactEndpoint(c.contact.aid); err == nil {
			t.Fatalf("an older address stood in for a withdrawal: %+v", found)
		}
	})
	t.Run("the newest of several witnesses wins, in any order", func(t *testing.T) {
		for _, order := range [][]time.Duration{{time.Hour, time.Minute}, {time.Minute, time.Hour}} {
			c := aContactWithWitnesses(t, true,
				signed("https://a.example.com:443", order[0]), signed("https://b.example.com:443", order[1]))
			found, err := c.core.RecoverContactEndpoint(c.contact.aid)
			if err != nil {
				t.Fatal(err)
			}
			want := "https://a.example.com:443"
			if order[1] < order[0] {
				want = "https://b.example.com:443"
			}
			if found.Origin != want {
				t.Fatalf("order %v: got %s, want %s", order, found.Origin, want)
			}
		}
	})
	t.Run("an older record is not taken once a newer one has been seen", func(t *testing.T) {
		newest := true
		c := aContactWithWitnesses(t, true, func(c heldIdentity) map[string]any {
			if newest {
				return recordObject(signedRecord(t, c.aid, "https://new.example.com:443", time.Minute, c.seeds[0]))
			}
			// The same witness, later, or a stale one, offering what the contact
			// really did sign before.
			return recordObject(signedRecord(t, c.aid, "https://lapsed.example.com:443", time.Hour, c.seeds[0]))
		})
		first, err := c.core.RecoverContactEndpoint(c.contact.aid)
		if err != nil || first.Origin != "https://new.example.com:443" {
			t.Fatalf("%+v %v", first, err)
		}
		newest = false
		again, err := c.core.RecoverContactEndpoint(c.contact.aid)
		if err != nil || again.Origin != "https://new.example.com:443" || again.FoundVia != "remembered" {
			t.Fatalf("a rollback to an older signed address was taken: %+v %v", again, err)
		}
	})
}

// A contact that has rotated since it was last resolved: the log on file ends at
// the inception, the witnesses hold the rotation.
func aContactThatRotated(t *testing.T, oldKeyAlsoSigns bool) (*CoreServer, heldIdentity) {
	t.Helper()
	w := anEndpointWitness(t)
	witnessName := aWitnessName()
	id := holdAnIdentityNaming(t, w.core.WitnessService.Store, true, []string{witnessName})
	if code, out := w.publish(t, id.aid, signedRecord(t, id.aid, "https://moved.example.com:443", time.Minute, id.seeds[1])); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	front := httputil.NewSingleHostReverseProxy(mustParse(t, w.url))
	witnessFront := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if oldKeyAlsoSigns && strings.HasPrefix(r.URL.Path, "/api/witness/endpoint/") {
			// What a stale or hostile witness still holds: the record the replaced
			// key signed, issued after the rotation was made.
			_ = json.NewEncoder(rw).Encode(map[string]any{"record": recordObject(
				signedRecord(t, id.aid, "https://compromised.example.net:443", 0, id.seeds[0]))})
			return
		}
		front.ServeHTTP(rw, r)
	}))
	t.Cleanup(witnessFront.Close)

	held, err := w.core.WitnessService.Store.GetKelEvents(id.aid)
	if err != nil || len(held) != 2 {
		t.Fatalf("%d events, %v", len(held), err)
	}
	s := witnessWithStore(t)
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: witnessName, OobiURL: witnessFront.URL + "/public/oobi/" + witnessName}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: id.aid, KelVerified: true, CurrentPublicKey: id.pubs[0], KEL: heldAsStored(t, w.core.WitnessService.Store, id.aid, 1),
	}); err != nil {
		t.Fatal(err)
	}
	return s, id
}

func TestRecoveryFollowsARotationTheContactMadeSinceItWasLastResolved(t *testing.T) {
	t.Run("the record the new key signed is the answer", func(t *testing.T) {
		s, id := aContactThatRotated(t, false)
		found, err := s.RecoverContactEndpoint(id.aid)
		if err != nil || found.Origin != "https://moved.example.com:443" {
			t.Fatalf("a record signed by the key the contact rotated to was not taken: %+v %v", found, err)
		}
		kept, _ := s.DataStore.GetContactKEL(id.aid)
		if kept == nil || len(kept.KEL) != 2 || kept.CurrentPublicKey != id.pubs[1] {
			t.Fatalf("the newer key log was not kept: %+v", kept)
		}
	})
	t.Run("a record the replaced key signed is refused", func(t *testing.T) {
		s, id := aContactThatRotated(t, true)
		// The only witness asked still serves the record the replaced key signed.
		found, err := s.RecoverContactEndpoint(id.aid)
		if err == nil {
			t.Fatalf("a record signed by a key the contact had rotated away from was taken: %+v", found)
		}
	})
	t.Run("a log that does not continue the one on file is not an update", func(t *testing.T) {
		s, id := aContactThatRotated(t, false)
		kept, _ := s.DataStore.GetContactKEL(id.aid)
		kept.KEL[0]["raw_bytes_b64"] = "AAAA" // not the inception the witnesses hold
		_ = s.DataStore.SaveContactKEL(*kept)
		if _, err := s.RecoverContactEndpoint(id.aid); err == nil {
			// The witness will not answer for a log whose inception it does not
			// hold, so nothing is refreshed and the old key stays; the new record
			// then fails against it.
			t.Fatal("a record signed by the new key was believed against a log it does not extend")
		}
	})
}

// A witness that has checked a log does not take its cached verdict for a log
// that has since gained an event: the cache is by the log, not by the identifier.
func TestAWitnessFollowsARotationAfterItHasCheckedTheLog(t *testing.T) {
	w := anEndpointWitness(t)
	id := holdAnIdentity(t, w.core.WitnessService.Store, false)
	key, err := w.core.WitnessService.CurrentVerifiedKey(id.aid)
	if err != nil || iacrypto.VerkeyQB64(key) != id.pubs[0] {
		t.Fatalf("%v %v", key, err)
	}
	if again, err := w.core.WitnessService.CurrentVerifiedKey(id.aid); err != nil || !key.Equal(again) {
		t.Fatalf("the same log asked again: %v", err)
	}

	held, _ := w.core.WitnessService.Store.GetKelEvents(id.aid)
	d2, _ := keri.NextDigest(id.pubs[2])
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: id.aid, Keys: []string{id.pubs[1]}, PriorSAID: held[0].EventSAID, SN: 1, NextDigests: []string{d2},
	})
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := keri.ParseEvent(rot)
	sig, _ := login.SignString(string(rot), id.seeds[1])
	if err := w.core.WitnessService.Store.StoreKelEvent(witness.KelEvent{
		SignerAID: id.aid, SequenceNum: 1, EventJSON: string(rot), EventSAID: rev.SAID,
		StoredAt:    time.Now().UTC().Format(time.RFC3339),
		RawBytesB64: base64.StdEncoding.EncodeToString(rot), CesrSignature: sig,
	}); err != nil {
		t.Fatal(err)
	}
	key, err = w.core.WitnessService.CurrentVerifiedKey(id.aid)
	if err != nil || iacrypto.VerkeyQB64(key) != id.pubs[1] {
		t.Fatalf("after the rotation the witness still named the old key: %v %v", key, err)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
