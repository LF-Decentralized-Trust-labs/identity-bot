package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	keri "github.com/grapeid/keri-go"
	"identity-agent-core/iacrypto"
	"identity-agent-core/recovery"
	"identity-agent-core/sandbox"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// twoCores is the device that holds the identity's key, with its own core and
// store, and an Identity Agent that does not hold it: a copy of the device's
// record, with no way to derive the key.
type twoCores struct {
	device    *CoreServer
	requester *elsewhere
	dir       string
	// noWitnesses leaves the requester nowhere to find what the device
	// signed but the device's own answers.
	noWitnesses bool
}

func newTwoCores(t *testing.T) *twoCores {
	t.Helper()
	w := newTalkWorld(t)
	resetSeenSignatures(t)
	device := w.s
	device.localOwnerSecret = testOwnerSecret
	// The requester holds a copy of everything the device holds, except the
	// root seed the key is derived from: its own is another.
	dir := t.TempDir()
	if _, err := device.DataStore.(*store.SQLiteStore).DB().Exec(`VACUUM INTO ?`, filepath.Join(dir, "identity.db")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent_bodies.json", "assets.json", "controller_grants.json", "didcomm_keys.json", "employees.json", "owner_authority.json", "certs/ca.crt", "certs/ca.key"} {
		b, err := os.ReadFile(filepath.Join(device.DataDir, name))
		if err != nil {
			continue
		}
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &twoCores{device: device, dir: dir}
	c.requester = &elsewhere{s: c.openRequester(t)}
	if err := device.keyCanSign(); err != nil {
		t.Fatalf("the device cannot sign: %v", err)
	}
	return c
}

// openRequester starts the requester's core over its data directory, as it
// starts after a restart. The identity's witnesses, which hold what the device
// signed, are stood in for by the device's own key log unless noWitnesses.
func (c *twoCores) openRequester(t *testing.T) *CoreServer {
	t.Helper()
	rds, err := store.NewSQLiteStore(c.dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: c.dir, DataStore: rds, EventHub: NewEventHub()}
	r.KeriDriver = keriengine.New()
	r.engineSigns()
	r.reloadIdentityIntoDriver()
	if err := r.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: c.dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	r.SandboxManager = mgr
	r.router = r.buildRouter("")
	r.fetchSignedEvent = func(aid string, sn int) []heldEvent {
		if c.noWitnesses {
			return nil
		}
		events, _ := c.device.DataStore.GetEvents(aid)
		for _, ev := range events {
			if ev.SequenceNumber == sn {
				return []heldEvent{{RawB64: ev.RawBytesB64, Signature: ev.CesrSignature}}
			}
		}
		return nil
	}
	if !r.keyIsElsewhere() {
		t.Fatalf("the requester can sign as the identity: %v", r.keyCanSign())
	}
	return r
}

// sign is the device signing, on its own core, what the requester queued.
func (c *twoCores) sign(t *testing.T, id string) (string, error) {
	t.Helper()
	all, _ := c.requester.s.DataStore.GetPendingSigningRequests()
	for _, req := range all {
		if req.ID != id {
			continue
		}
		parts := c.requester.s.queuedParts(id)
		return c.device.signForAnother(req.PayloadB64, parts)
	}
	t.Fatalf("no request %s", id)
	return "", nil
}

func (c *twoCores) logsAgree(t *testing.T) {
	t.Helper()
	owner, _ := c.device.DataStore.GetIdentity()
	d, _ := c.device.DataStore.GetEvents(owner.AID)
	r, _ := c.requester.s.DataStore.GetEvents(owner.AID)
	if len(d) != len(r) {
		t.Fatalf("the device holds %d events and the requester %d", len(d), len(r))
	}
	for i := range d {
		if d[i].RawBytesB64 != r[i].RawBytesB64 || d[i].CesrSignature != r[i].CesrSignature {
			t.Fatalf("the logs differ at %d", i)
		}
	}
}

// Grants asked for one after another are each signed by the device, which
// records each in its own key log; both logs hold the same events.
func TestGrantsAreSignedOneAfterAnother(t *testing.T) {
	c := newTwoCores(t)
	a, b := grantFor(5, GradeEnrolled), grantFor(6, GradeEnrolled)
	if rec := c.requester.pairMachine(t, a); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	if rec := c.requester.pairMachine(t, b); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	for i, g := range []ControllerGrant{a, b} {
		reqs := waiting(t, c.requester.s)
		if len(reqs) != 1 {
			t.Fatalf("step %d: %d interactions wait for the device, where one may", i, len(reqs))
		}
		sig, err := c.sign(t, reqs[0].ID)
		if err != nil {
			t.Fatalf("step %d: the device would not sign: %v", i, err)
		}
		if rec := fulfilWith(t, c.requester.s, reqs[0].ID, sig); rec.Code != http.StatusOK {
			t.Fatalf("step %d: %d %s", i, rec.Code, rec.Body.String())
		}
		if got, _, _ := c.requester.s.controllers().Get(g.ControllerAID); got.CredentialSAID == "" {
			t.Fatalf("machine %d was not granted", i)
		}
		c.logsAgree(t)
	}
}

// Two interactions built at one place: the device signs the first, records
// it, and refuses the second. The same one asked for again is answered with
// the signature it was given.
func TestTheDeviceSignsOneEventAtAPlace(t *testing.T) {
	c := newTwoCores(t)
	owner, _ := c.requester.s.DataStore.GetIdentity()
	reg, _ := c.requester.s.DataStore.GetRegistryByIssuer(owner.AID)
	preparer := c.requester.s.KeriDriver.(drivers.PreparedIssuer)
	build := func(g ControllerGrant) *drivers.PreparedIssuance {
		claims := map[string]interface{}{"name": g.Label, "label": g.Label, "public_key": g.PublicKey, "grade": string(g.Grade),
			"i": g.ControllerAID, "asset_type": schemas.ControllerGrant.AssetType}
		p, err := preparer.PrepareCredentialInRegistry(owner.AID, claims, schemas.ControllerGrant.Schema.SAID, g.ControllerAID, nil, reg.RegistrySAID)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	one, two := build(grantFor(5, GradeEnrolled)), build(grantFor(6, GradeEnrolled))
	if one.SN != two.SN {
		t.Fatal("the two were not built at one place")
	}
	b64 := base64.StdEncoding.EncodeToString
	before, _ := c.device.DataStore.GetEvents(owner.AID)
	if _, err := c.device.signForAnother(b64(one.IxnRaw), map[string]string{"credential_b64": b64(two.AcdcRaw), "issuance_b64": b64(two.IssRaw)}); err == nil {
		t.Fatal("the device signed an interaction shown with another credential")
	}
	if now, _ := c.device.DataStore.GetEvents(owner.AID); len(now) != len(before) {
		t.Fatal("the device recorded what it refused to sign")
	}
	sig, err := c.device.signForAnother(b64(one.IxnRaw), map[string]string{"credential_b64": b64(one.AcdcRaw), "issuance_b64": b64(one.IssRaw)})
	if err != nil {
		t.Fatalf("the first: %v", err)
	}
	if _, err := c.device.signForAnother(b64(two.IxnRaw), map[string]string{"credential_b64": b64(two.AcdcRaw), "issuance_b64": b64(two.IssRaw)}); err == nil || !strings.Contains(err.Error(), "already signed another event") {
		t.Fatal("the device signed a second event at a place it had filled")
	}
	again, err := c.device.signForAnother(b64(one.IxnRaw), map[string]string{"credential_b64": b64(one.AcdcRaw), "issuance_b64": b64(one.IssRaw)})
	if err != nil || again != sig {
		t.Fatalf("the same event asked for again: %v", err)
	}
	events, _ := c.device.DataStore.GetEvents(owner.AID)
	last, _ := base64.StdEncoding.DecodeString(events[len(events)-1].RawBytesB64)
	if !bytes.Equal(last, one.IxnRaw) {
		t.Fatal("the device did not record what it signed")
	}
}

// The reviewer's case: two grants asked for at once. Only one waits for the
// device; the other is built once the first lands, on the new tip, and both
// are signed in turn.
func TestTwoGrantsAskedAtOnceAreNotBuiltAtOnePlace(t *testing.T) {
	c := newTwoCores(t)
	g1, g2 := grantFor(11, GradeEnrolled), grantFor(12, GradeEnrolled)
	g1.Label, g2.Label = "one", "two"
	c.requester.pairMachine(t, g1)
	c.requester.pairMachine(t, g2)
	if n := len(waiting(t, c.requester.s)); n != 1 {
		t.Fatalf("%d interactions wait for the device at one tip", n)
	}
	for i := 0; i < 2; i++ {
		req := waiting(t, c.requester.s)[0]
		sig, err := c.sign(t, req.ID)
		if err != nil {
			t.Fatalf("grant %d: the device would not sign: %v", i, err)
		}
		if rec := fulfilWith(t, c.requester.s, req.ID, sig); rec.Code != http.StatusOK {
			t.Fatalf("grant %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	for _, g := range []ControllerGrant{g1, g2} {
		if got, _, _ := c.requester.s.controllers().Get(g.ControllerAID); got.CredentialSAID == "" {
			t.Fatalf("%s was not granted", g.Label)
		}
	}
	c.logsAgree(t)
}

// A grant kept behind one the device refused is built and asked for.
func TestAGrantBehindARefusedOneIsAskedFor(t *testing.T) {
	c := newTwoCores(t)
	c.requester.pairMachine(t, grantFor(5, GradeEnrolled))
	c.requester.pairMachine(t, grantFor(6, GradeEnrolled))
	first := waiting(t, c.requester.s)[0]
	rec := httptestRefuse(t, c.requester.s, first.ID)
	if rec != http.StatusOK {
		t.Fatalf("refusing: %d", rec)
	}
	next := waiting(t, c.requester.s)
	if len(next) != 1 || next[0].ID == first.ID {
		t.Fatalf("the grant behind the refused one was not asked for: %+v", next)
	}
}

func httptestRefuse(t *testing.T, s *CoreServer, id string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRefuseSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+id+"/refuse", strings.NewReader(`{}`), s), id))
	return rec.Code
}

// lostReply signs on the device, and the reply never reaches the requester.
func (c *twoCores) lostReply(t *testing.T) (store.SigningRequest, string) {
	t.Helper()
	reqs := waiting(t, c.requester.s)
	if len(reqs) != 1 {
		t.Fatalf("%d wait for the device", len(reqs))
	}
	sig, err := c.sign(t, reqs[0].ID)
	if err != nil {
		t.Fatalf("the device would not sign: %v", err)
	}
	return reqs[0], sig
}

// signAll has the device sign whatever waits, one at a time, until nothing
// does.
func (c *twoCores) signAll(t *testing.T) {
	t.Helper()
	for i := 0; i < 8; i++ {
		reqs := waiting(t, c.requester.s)
		if len(reqs) == 0 {
			return
		}
		sig, err := c.sign(t, reqs[0].ID)
		if err != nil {
			t.Fatalf("the device would not sign %s: %v", reqs[0].Kind, err)
		}
		if rec := fulfilWith(t, c.requester.s, reqs[0].ID, sig); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", reqs[0].Kind, rec.Code, rec.Body.String())
		}
	}
	t.Fatal("something still waits after eight signatures")
}

func (c *twoCores) machineGranted(t *testing.T, g ControllerGrant) bool {
	t.Helper()
	got, had, _ := c.requester.s.controllers().Get(g.ControllerAID)
	return had && got.CredentialSAID != ""
}

// signedAndWithdrawn checks a grant to holder is in the key log, revoked, and
// not in force.
func (c *twoCores) signedAndWithdrawn(t *testing.T, holder string) {
	t.Helper()
	creds, _ := c.requester.s.DataStore.GetCredentials()
	for _, cr := range creds {
		if cr.HolderAID == holder {
			if cr.Status != "revoked" {
				t.Fatalf("the grant to %s the device signed is %q, not revoked", holder, cr.Status)
			}
			return
		}
	}
	t.Fatalf("the grant to %s the device signed was not taken up", holder)
}

// The reviewer's sequence: the device signs machine a's grant and the reply is
// lost; the owner removes a and pairs b. The requester takes up a's grant
// from the witnesses, withdraws it, and grants b; both logs agree.
func TestReviewLostReplyThenRemoval(t *testing.T) {
	c := newTwoCores(t)
	a, b := grantFor(5, GradeEnrolled), grantFor(6, GradeEnrolled)
	if rec := c.requester.pairMachine(t, a); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	c.lostReply(t)
	if err := c.requester.s.revokeController(a.ControllerAID); err != nil {
		t.Fatal(err)
	}
	if rec := c.requester.pairMachine(t, b); rec.Code != http.StatusOK {
		t.Fatalf("pairing b: %d %s", rec.Code, rec.Body.String())
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	if !c.machineGranted(t, b) {
		t.Fatal("b was not granted")
	}
	if c.machineGranted(t, a) {
		t.Fatal("a removed machine is granted")
	}
}

// The same, with no witness holding what the device signed: the device
// answers the next request with the event it holds there, and the requester
// takes it up from that.
func TestAFilledPlaceIsAnsweredWithWhatIsHeld(t *testing.T) {
	c := newTwoCores(t)
	c.noWitnesses = true
	a, b := grantFor(5, GradeEnrolled), grantFor(6, GradeEnrolled)
	c.requester.pairMachine(t, a)
	c.lostReply(t)
	c.requester.s.revokeController(a.ControllerAID)
	c.requester.pairMachine(t, b)
	req := waiting(t, c.requester.s)[0]
	parts := c.requester.s.queuedParts(req.ID)
	parts["payload_b64"] = req.PayloadB64
	body, _ := json.Marshal(parts)
	rec := httptest.NewRecorder()
	c.device.router.ServeHTTP(rec, local("POST", "/api/signing-requests/sign-for-another", string(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("a second event at a filled place was answered %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Held heldEvent `json:"held"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Held.Signature == "" || out.Held.Parts["credential_b64"] == "" {
		t.Fatalf("the device did not say what it holds: %s", rec.Body.String())
	}
	held, _ := json.Marshal(out.Held)
	rec = httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(rec, local("POST", "/api/signing-requests/adopt", string(held)))
	if rec.Code != http.StatusOK {
		t.Fatalf("taking up what the device holds: %d %s", rec.Code, rec.Body.String())
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	if !c.machineGranted(t, b) {
		t.Fatal("b was not granted")
	}
}

// Signed on the device, then expired here before the reply came: taken up,
// never in force, withdrawn.
func TestAGrantSignedThenExpiredHereIsWithdrawn(t *testing.T) {
	c := newTwoCores(t)
	a := grantFor(5, GradeEnrolled)
	c.requester.pairMachine(t, a)
	req, _ := c.lostReply(t)
	recordDB(t, c.requester.s).Exec(`UPDATE signing_requests SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), req.ID)
	c.requester.s.tick()
	if c.machineGranted(t, a) {
		t.Fatal("a grant expired here is in force")
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
}

// Signed on the device, then refused here before the reply came: the reply,
// when it does come, is taken up and the grant withdrawn.
func TestAGrantSignedThenRefusedHereIsWithdrawn(t *testing.T) {
	c := newTwoCores(t)
	c.noWitnesses = true
	a := grantFor(5, GradeEnrolled)
	c.requester.pairMachine(t, a)
	req, sig := c.lostReply(t)
	if code := httptestRefuse(t, c.requester.s, req.ID); code != http.StatusOK {
		t.Fatalf("refusing: %d", code)
	}
	if rec := fulfilWith(t, c.requester.s, req.ID, sig); !strings.Contains(rec.Body.String(), `"in_force":false`) {
		t.Fatalf("the late reply: %d %s", rec.Code, rec.Body.String())
	}
	if c.machineGranted(t, a) {
		t.Fatal("a grant refused here is in force")
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
}

// The requester stops after the device signed and before the reply: started
// again, it takes the grant up on its tick, in force, since it is still asked
// for.
func TestARequesterRestartedAfterTheDeviceSignedTakesItUp(t *testing.T) {
	c := newTwoCores(t)
	a := grantFor(5, GradeEnrolled)
	c.requester.pairMachine(t, a)
	c.lostReply(t)
	c.requester.s.DataStore.Close()
	c.requester.s = c.openRequester(t)
	c.requester.s.tick()
	if !c.machineGranted(t, a) {
		t.Fatal("the grant the device signed is not in force after a restart")
	}
	if len(waiting(t, c.requester.s)) != 0 {
		t.Fatal("something still waits")
	}
	c.logsAgree(t)
}

// An event not signed by the identity's key, or not extending the key log
// here, is not taken up.
func TestOnlyWhatTheKeySignedAtTheNextPlaceIsTakenUp(t *testing.T) {
	c := newTwoCores(t)
	c.noWitnesses = true
	c.requester.pairMachine(t, grantFor(5, GradeEnrolled))
	req := waiting(t, c.requester.s)[0]
	other := make([]byte, 32)
	other[0] = 9
	forged, _ := signEventBytes(mustB64(t, req.PayloadB64), other)
	if n, _ := c.requester.s.adoptWhatTheDeviceSigned(&heldEvent{RawB64: req.PayloadB64, Signature: forged}); n != 0 {
		t.Fatal("an event signed by another key was taken up")
	}
	// Signed by the key, at the next place, but after another event: not
	// this key log's next event, and passed over without harm.
	owner, _ := c.requester.s.DataStore.GetIdentity()
	tipSN, _, _ := c.requester.s.ownTip(owner.AID)
	elsewhereRaw, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: "Eanother-prior", SN: tipSN + 1,
		Data: []json.RawMessage{json.RawMessage(`{"d":"Esomething"}`)}})
	seed, _ := c.device.identitySigningSeed()
	elsewhereSig, _ := signEventBytes(elsewhereRaw, seed)
	if n, err := c.requester.s.adoptWhatTheDeviceSigned(&heldEvent{RawB64: base64.StdEncoding.EncodeToString(elsewhereRaw), Signature: elsewhereSig}); n != 0 || err != nil {
		t.Fatalf("an event after another prior was taken up: %d %v", n, err)
	}
	sig, _ := c.sign(t, req.ID)
	c.requester.s.adoptWhatTheDeviceSigned(&heldEvent{RawB64: req.PayloadB64, Signature: sig})
	if n, _ := c.requester.s.adoptWhatTheDeviceSigned(&heldEvent{RawB64: req.PayloadB64, Signature: sig}); n != 0 {
		t.Fatal("an event at a place already filled here was taken up again")
	}
	c.logsAgree(t)
}

func mustB64(t *testing.T, v string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An Identity Agent upgraded with events the device never signed says so in
// the waiting list and the log check, and asks the device for nothing.
func TestUnsignedEventsHereAreReportedNotSentToTheDevice(t *testing.T) {
	e := keyElsewhere(t)
	owner, _ := e.s.DataStore.GetIdentity()
	events, _ := e.s.DataStore.GetEvents(owner.AID)
	last := events[len(events)-1].SequenceNumber
	recordDB(t, e.s).Exec(`UPDATE kel SET cesr_signature = '' WHERE aid = ? AND seq_num = ?`, owner.AID, last)
	rec := e.pairMachine(t, grantFor(5, GradeEnrolled))
	if rec.Code < 400 || !strings.Contains(rec.Body.String(), "never had") {
		t.Fatalf("a grant was asked for over an unsigned key log: %d %s", rec.Code, rec.Body.String())
	}
	if len(waiting(t, e.s)) != 0 {
		t.Fatal("the device was asked to extend a key log it never had")
	}
	for _, path := range []string{"/api/grants/awaiting-approval", "/api/activity/chain"} {
		rec := httptest.NewRecorder()
		e.s.router.ServeHTTP(rec, local("GET", path, ""))
		if !strings.Contains(rec.Body.String(), `"key_log_unsigned_events":[`+strconv.Itoa(last)+`]`) {
			t.Fatalf("%s does not report the unsigned event: %s", path, rec.Body.String())
		}
	}
}

// The device withdraws only a grant its own key log issued.
func TestTheDeviceWithdrawsOnlyWhatItIssued(t *testing.T) {
	c := newTwoCores(t)
	owner, _ := c.device.DataStore.GetIdentity()
	reg, _ := c.device.DataStore.GetRegistryByIssuer(owner.AID)
	g := grantFor(5, GradeEnrolled)
	never, err := c.device.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(owner.AID, map[string]interface{}{
		"name": g.Label, "label": g.Label, "public_key": g.PublicKey, "grade": string(g.Grade), "i": g.ControllerAID,
		"asset_type": schemas.ControllerGrant.AssetType}, schemas.ControllerGrant.Schema.SAID, g.ControllerAID, nil, reg.RegistrySAID)
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: never.AcdcSAID, Registry: reg.RegistrySAID, PriorISSSAID: never.IssSAID, DT: "2026-10-23T00:00:00.000000+00:00"})
	revEvent, _ := keri.VerifyTELEvent(rev)
	tipSN, tipSAID, _ := c.device.ownTip(owner.AID)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: tipSAID, SN: tipSN + 1,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + never.AcdcSAID + `","s":"1","d":"` + revEvent.SAID + `"}`)}})
	b64 := base64.StdEncoding.EncodeToString
	_, err = c.device.signForAnother(b64(ixn), map[string]string{"credential_b64": b64(never.AcdcRaw), "revocation_b64": b64(rev)})
	if err == nil || !strings.Contains(err.Error(), "never issued") {
		t.Fatalf("the device withdrew a grant it never issued: %v", err)
	}
}

// withdrawalAsked brings the requester to a grant signed on the device, not
// wanted here, whose withdrawal waits for the device.
func (c *twoCores) withdrawalAsked(t *testing.T) (ControllerGrant, store.SigningRequest) {
	t.Helper()
	a := grantFor(5, GradeEnrolled)
	c.requester.pairMachine(t, a)
	c.lostReply(t)
	c.requester.s.revokeController(a.ControllerAID)
	c.requester.s.tick()
	reqs := waiting(t, c.requester.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindRevocation {
		t.Fatalf("no withdrawal waits: %+v", reqs)
	}
	return a, reqs[0]
}

func withdrawingListed(t *testing.T, s *CoreServer, holder, state string) {
	t.Helper()
	for _, path := range []string{"/api/grants/awaiting-approval", "/api/activity/chain"} {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, local("GET", path, ""))
		var out struct {
			Withdrawing []map[string]string `json:"grants_withdrawing"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		found := false
		for _, g := range out.Withdrawing {
			if g["holder"] == holder && g["withdrawal"] == state && strings.Contains(g["detail"], "still authorised in the published record") {
				found = state != "refused" || strings.Contains(g["detail"], "/api/grants/withdrawing/"+g["credential"]+"/ask")
			}
		}
		if state == "" && len(out.Withdrawing) != 0 {
			t.Fatalf("%s still lists %v", path, out.Withdrawing)
		}
		if state != "" && !found {
			t.Fatalf("%s does not list %s as %s: %s", path, holder, state, rec.Body.String())
		}
	}
}

// A withdrawal that expired is asked for again on the tick, and ends revoked.
func TestAnExpiredWithdrawalIsAskedAgain(t *testing.T) {
	c := newTwoCores(t)
	a, req := c.withdrawalAsked(t)
	withdrawingListed(t, c.requester.s, a.ControllerAID, "waiting")
	recordDB(t, c.requester.s).Exec(`UPDATE signing_requests SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), req.ID)
	c.requester.s.tick()
	again := waiting(t, c.requester.s)
	if len(again) != 1 || again[0].Kind != signingKindRevocation || again[0].ID == req.ID {
		t.Fatalf("the expired withdrawal was not asked again: %+v", again)
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	withdrawingListed(t, c.requester.s, a.ControllerAID, "")
}

// A withdrawal the device refused is not asked again on its own, is listed
// as still authorised in the published record, and can be asked again.
func TestARefusedWithdrawalIsListedAndCanBeAskedAgain(t *testing.T) {
	c := newTwoCores(t)
	a, req := c.withdrawalAsked(t)
	if code := httptestRefuse(t, c.requester.s, req.ID); code != http.StatusOK {
		t.Fatalf("refusing: %d", code)
	}
	c.requester.s.tick()
	if n := len(waiting(t, c.requester.s)); n != 0 {
		t.Fatalf("a refused withdrawal was asked again on its own: %d waiting", n)
	}
	withdrawingListed(t, c.requester.s, a.ControllerAID, "refused")
	creds, _ := c.requester.s.DataStore.GetCredentials()
	var said string
	for _, cr := range creds {
		if cr.HolderAID == a.ControllerAID {
			said = cr.SAID
		}
	}
	rec := httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(rec, local("POST", "/api/grants/withdrawing/"+said+"/ask", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("asking again: %d %s", rec.Code, rec.Body.String())
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	withdrawingListed(t, c.requester.s, a.ControllerAID, "")
}

func withdrawingSAID(t *testing.T, s *CoreServer, holder string) string {
	t.Helper()
	creds, _ := s.DataStore.GetCredentials()
	for _, cr := range creds {
		if cr.HolderAID == holder {
			return cr.SAID
		}
	}
	t.Fatalf("no grant to %s", holder)
	return ""
}

func askAgain(t *testing.T, s *CoreServer, said string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, local("POST", "/api/grants/withdrawing/"+said+"/ask", ""))
	if rec.Code == http.StatusConflict && !strings.Contains(rec.Body.String(), "already waiting") && !strings.Contains(rec.Body.String(), "not waiting to be withdrawn") {
		t.Fatalf("refused without saying why: %s", rec.Body.String())
	}
	return rec.Code
}

// The reviewer's probe: asking again three times while a withdrawal waits
// asks the device for nothing more. The device signs the one withdrawal, the
// logs agree, and nothing is left waiting; asking again after it is done is
// refused too.
func TestAskingAgainWhileAWithdrawalWaitsAsksNothingMore(t *testing.T) {
	c := newTwoCores(t)
	a, _ := c.withdrawalAsked(t)
	said := withdrawingSAID(t, c.requester.s, a.ControllerAID)
	for i := 0; i < 3; i++ {
		if code := askAgain(t, c.requester.s, said); code != http.StatusConflict {
			t.Fatalf("asking again while it waits was answered %d", code)
		}
	}
	if n := len(waiting(t, c.requester.s)); n != 1 {
		t.Fatalf("%d wait for the device after asking again", n)
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	if code := askAgain(t, c.requester.s, said); code != http.StatusConflict {
		t.Fatalf("asking again once revoked was answered %d", code)
	}
	if n := len(waiting(t, c.requester.s)); n != 0 {
		t.Fatalf("%d left waiting", n)
	}
	// And a grant asked for after it is issued: the queue is not jammed.
	b := grantFor(6, GradeEnrolled)
	c.requester.pairMachine(t, b)
	c.signAll(t)
	c.logsAgree(t)
	if !c.machineGranted(t, b) {
		t.Fatal("a grant after the withdrawal was not issued")
	}
}

// A revoked grant is not revoked again: the engine refuses to build it, and
// the device refuses to sign one its own key log has already made.
func TestARevokedGrantIsNotRevokedAgain(t *testing.T) {
	c := newTwoCores(t)
	a, _ := c.withdrawalAsked(t)
	said := withdrawingSAID(t, c.requester.s, a.ControllerAID)
	rec, _ := c.requester.s.DataStore.GetCredential(said)
	revoker := c.requester.s.KeriDriver.(drivers.PreparedRevoker)
	second, err := revoker.PrepareRevocation(rec.IssuerAID, said, rec.RegistrySAID) // built before the first lands
	if err != nil {
		t.Fatal(err)
	}
	c.signAll(t)
	if _, err := revoker.PrepareRevocation(rec.IssuerAID, said, rec.RegistrySAID); err == nil {
		t.Fatal("the engine built a second revocation of a revoked grant")
	}
	// The second, rebuilt on the device's tip, is refused by the device.
	owner, _ := c.device.DataStore.GetIdentity()
	tipSN, tipSAID, _ := c.device.ownTip(owner.AID)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: tipSAID, SN: tipSN + 1,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"1","d":"` + second.RevSAID + `"}`)}})
	b64 := base64.StdEncoding.EncodeToString
	acdc, _ := base64.StdEncoding.DecodeString(rec.AcdcJson)
	_, err = c.device.signForAnother(b64(ixn), map[string]string{"credential_b64": b64(acdc), "revocation_b64": b64(second.RevRaw)})
	if err == nil || !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("the device signed a second withdrawal: %v", err)
	}
}

// An event the device signed whose anchored event the credential log here
// refuses is still taken up, so the key logs never diverge; what it anchors
// is reported.
func TestAnEventIsTakenUpEvenWhenWhatItAnchorsIsRefused(t *testing.T) {
	c := newTwoCores(t)
	a, _ := c.withdrawalAsked(t)
	c.noWitnesses = true
	said := withdrawingSAID(t, c.requester.s, a.ControllerAID)
	rec, _ := c.requester.s.DataStore.GetCredential(said)
	second, _ := c.requester.s.KeriDriver.(drivers.PreparedRevoker).PrepareRevocation(rec.IssuerAID, said, rec.RegistrySAID)
	c.signAll(t)
	// As a device without the check above would have: a second revocation,
	// signed with the key at the next place.
	owner, _ := c.requester.s.DataStore.GetIdentity()
	tipSN, tipSAID, _ := c.requester.s.ownTip(owner.AID)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: tipSAID, SN: tipSN + 1,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"1","d":"` + second.RevSAID + `"}`)}})
	seed, _ := c.device.identitySigningSeed()
	sig, _ := signEventBytes(ixn, seed)
	acdc, _ := base64.StdEncoding.DecodeString(rec.AcdcJson)
	b64 := base64.StdEncoding.EncodeToString
	n, err := c.requester.s.adoptWhatTheDeviceSigned(&heldEvent{RawB64: b64(ixn), Signature: sig,
		Parts: map[string]string{"credential_b64": b64(acdc), "revocation_b64": b64(second.RevRaw)}})
	if err != nil || n != 1 {
		t.Fatalf("took up %d: %v", n, err)
	}
	if now, _, _ := c.requester.s.ownTip(owner.AID); now != tipSN+1 {
		t.Fatal("the key-log event was not taken up")
	}
	notHeld := c.requester.s.anchoredNotHeld()
	if len(notHeld) != 1 || notHeld[0].Interaction != saidOf(ixn) || len(notHeld[0].Anchors) != 1 ||
		!strings.Contains(string(notHeld[0].Anchors[0]), said) || !strings.Contains(string(notHeld[0].Anchors[0]), second.RevSAID) {
		t.Fatalf("what it anchors is not named: %+v", notHeld)
	}
}

// Nothing already waiting for the device is asked of it again, whatever asks.
func TestTheSameThingIsNeverQueuedTwice(t *testing.T) {
	c := newTwoCores(t)
	a, req := c.withdrawalAsked(t)
	said := withdrawingSAID(t, c.requester.s, a.ControllerAID)
	body, _, _ := c.requester.s.DataStore.GetPendingIssuance(req.ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	if _, err := c.requester.s.queueForTheKey(signingKindRevocation, p, p.Revocation.IxnRaw, "again"); !errors.Is(err, errAlreadyAsked) {
		t.Fatalf("the same withdrawal was queued twice: %v", err)
	}
	_ = said
}

// grantedOnBoth grants a machine through the device that holds the key.
func (c *twoCores) grantedOnBoth(t *testing.T, g ControllerGrant) string {
	t.Helper()
	if rec := c.requester.pairMachine(t, g); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	c.signAll(t)
	got, _, _ := c.requester.s.controllers().Get(g.ControllerAID)
	if got.CredentialSAID == "" {
		t.Fatal("not granted")
	}
	return got.CredentialSAID
}

// The reviewer's case: a granted machine removed where the key is on another
// device. Nothing is written into the key log here; the grant stops being in
// force and its revocation is asked of the device, which signs it; both logs
// agree and the grant is revoked in the published record.
func TestZZRemoveGrantedMachineKeyElsewhere(t *testing.T) {
	c := newTwoCores(t)
	a := grantFor(5, GradeEnrolled)
	said := c.grantedOnBoth(t, a)
	owner, _ := c.requester.s.DataStore.GetIdentity()
	before, _ := c.requester.s.DataStore.GetEvents(owner.AID)
	if err := c.requester.s.revokeController(a.ControllerAID); err != nil {
		t.Fatal(err)
	}
	if after, _ := c.requester.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("removing a machine wrote into the key log here")
	}
	if rec, _ := c.requester.s.DataStore.GetCredential(said); rec.Status != credentialStatusWithdrawing {
		t.Fatalf("the removed machine's grant is %q", rec.Status)
	}
	if unsigned := c.requester.s.unsignedOwnEvents(); len(unsigned) != 0 {
		t.Fatalf("unsigned events here: %v", unsigned)
	}
	reqs := waiting(t, c.requester.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindRevocation {
		t.Fatalf("the withdrawal was not asked of the device: %+v", reqs)
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
	// Published: the device's key log anchors the revocation.
	events, _ := c.device.DataStore.GetEvents(owner.AID)
	if !anchorsSealOf(events, said, "1") {
		t.Fatal("the revocation is not in the published key log")
	}
}

// Every way a grant is revoked goes through the device where the key is
// elsewhere: the grant API, re-granting, and removing an AI agent's body all
// leave nothing unsigned here.
func TestEveryRevocationWaitsForTheDevice(t *testing.T) {
	c := newTwoCores(t)
	a := grantFor(5, GradeEnrolled)
	said := c.grantedOnBoth(t, a)
	rec := httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(rec, local("POST", "/api/credentials/"+said+"/revoke", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), credentialStatusWithdrawing) {
		t.Fatalf("revoking through the API: %d %s", rec.Code, rec.Body.String())
	}
	if unsigned := c.requester.s.unsignedOwnEvents(); len(unsigned) != 0 {
		t.Fatalf("unsigned events here: %v", unsigned)
	}
	c.signAll(t)
	c.logsAgree(t)
	c.signedAndWithdrawn(t, a.ControllerAID)
}

// A granted machine re-granted where the key is on another device, with a
// new label, grade and end: the old grant's withdrawal and the new grant are
// both asked of the device, in that order, and both land.
func TestAMachineIsReGrantedWhereTheKeyIsElsewhere(t *testing.T) {
	c := newTwoCores(t)
	a := grantFor(5, GradeEnrolled)
	old := c.grantedOnBoth(t, a)
	a.Label = "renamed"
	if rec := c.requester.pairMachine(t, a); rec.Code != http.StatusOK {
		t.Fatalf("re-granting: %d %s", rec.Code, rec.Body.String())
	}
	if r, _ := c.requester.s.DataStore.GetCredential(old); r.Status != credentialStatusWithdrawing {
		t.Fatalf("the replaced grant is %q", r.Status)
	}
	c.signAll(t)
	c.logsAgree(t)
	if r, _ := c.requester.s.DataStore.GetCredential(old); r.Status != "revoked" {
		t.Fatalf("the replaced grant ends %q", r.Status)
	}
	got, _, _ := c.requester.s.controllers().Get(a.ControllerAID)
	if got.CredentialSAID == "" || got.CredentialSAID == old || got.Label != "renamed" {
		t.Fatalf("the machine was not re-granted: %+v", got)
	}
}

// A withdrawal the device signed whose revocation event did not reach here
// with it: the key log here already withdraws the grant, so it is recorded
// revoked and not asked for again; and the device's own answer, asked again,
// hands back the revocation, which is kept.
func TestAWithdrawalAlreadyInTheKeyLogIsNotAskedAgain(t *testing.T) {
	c := newTwoCores(t)
	a, req := c.withdrawalAsked(t)
	said := withdrawingSAID(t, c.requester.s, a.ControllerAID)
	parts := c.requester.s.queuedParts(req.ID)
	if _, err := c.sign(t, req.ID); err != nil {
		t.Fatal(err)
	}
	// The request is lost here with what it kept; the event comes from the
	// witnesses alone, so only the key-log event is taken up.
	c.requester.s.DataStore.DeletePendingIssuance(req.ID)
	recordDB(t, c.requester.s).Exec(`UPDATE signing_requests SET status = 'expired' WHERE id = ?`, req.ID)
	c.requester.s.tick()
	c.logsAgree(t)
	if n := len(waiting(t, c.requester.s)); n != 0 {
		t.Fatalf("a grant the key log already withdraws was asked for again: %d waiting", n)
	}
	if r, _ := c.requester.s.DataStore.GetCredential(said); r.Status != "revoked" {
		t.Fatalf("a grant the key log withdraws is %q", r.Status)
	}
	// The device, asked to withdraw it again, says so and hands back what
	// it holds; taken up, the revocation is kept here.
	owner, _ := c.device.DataStore.GetIdentity()
	tipSN, tipSAID, _ := c.device.ownTip(owner.AID)
	rec, _ := c.requester.s.DataStore.GetCredential(said)
	rev, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: said, Registry: rec.RegistrySAID, PriorISSSAID: rec.IssSAID, DT: "2026-10-23T00:00:00.000000+00:00"})
	revEvent, _ := keri.VerifyTELEvent(rev)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: owner.AID, PriorSAID: tipSAID, SN: tipSN + 1,
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + said + `","s":"1","d":"` + revEvent.SAID + `"}`)}})
	body, _ := json.Marshal(map[string]string{"payload_b64": base64.StdEncoding.EncodeToString(ixn), "credential_b64": parts["credential_b64"],
		"revocation_b64": base64.StdEncoding.EncodeToString(rev)})
	w := httptest.NewRecorder()
	c.device.router.ServeHTTP(w, local("POST", "/api/signing-requests/sign-for-another", string(body)))
	var out struct {
		Detail string    `json:"detail"`
		Held   heldEvent `json:"held"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusConflict || !strings.Contains(out.Detail, "already withdrawn") || out.Held.Parts["revocation_b64"] == "" {
		t.Fatalf("the device asked to withdraw it again answered %d %s", w.Code, w.Body.String())
	}
	held, _ := json.Marshal(out.Held)
	w = httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(w, local("POST", "/api/signing-requests/adopt", string(held)))
	if w.Code != http.StatusOK {
		t.Fatalf("taking up the revocation: %d %s", w.Code, w.Body.String())
	}
	tel, _ := c.requester.s.DataStore.GetCredentialTEL(rec.RegistrySAID, said)
	if len(tel) != 2 {
		t.Fatalf("the credential's log here holds %d events, not its issuance and revocation", len(tel))
	}
}

// A grant whose withdrawal cannot even be asked of the device stays
// withdrawing here, never in force and never read as revoked.
func TestAGrantWhoseWithdrawalCannotBeAskedStaysWithdrawing(t *testing.T) {
	c := newTwoCores(t)
	owner, _ := c.requester.s.DataStore.GetIdentity()
	c.requester.s.DataStore.SaveCredential(store.CredentialRecord{SAID: "Egrant-in-no-registry-here", IssuerAID: owner.AID, HolderAID: "Bmachine",
		SchemaSAID: schemas.ControllerGrant.Schema.SAID, Status: "issued", RegistrySAID: "Eno-such-registry", IssSAID: "Eiss", Format: "acdc"})
	c.requester.s.withdrawOrSay("Egrant-in-no-registry-here")
	if r, _ := c.requester.s.DataStore.GetCredential("Egrant-in-no-registry-here"); r.Status != credentialStatusWithdrawing {
		t.Fatalf("a grant still in the published record reads %q here", r.Status)
	}
}

// Issuing a credential outside a registry where the key is on another device
// writes nothing: not through the API, not unsigned.
func TestIssuingOutsideARegistryWhereTheKeyIsElsewhereWritesNothing(t *testing.T) {
	c := newTwoCores(t)
	owner, _ := c.requester.s.DataStore.GetIdentity()
	before, _ := c.requester.s.DataStore.GetEvents(owner.AID)
	rec := httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(rec, local("POST", "/api/credential/issue",
		`{"claims":{"role":"engineer"},"schema_said":"EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM"}`))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "can't be extended here") {
		t.Fatalf("an issuance where the key is elsewhere was answered %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	c.requester.s.router.ServeHTTP(rec, local("POST", "/api/interact", `{"name":"`+owner.AID+`","data":[{"d":"Eanything"}]}`))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "can't be extended here") {
		t.Fatalf("an interaction where the key is elsewhere was answered %d %s", rec.Code, rec.Body.String())
	}
	if after, _ := c.requester.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an issuance where the key is elsewhere wrote into the key log")
	}
	if _, err := c.requester.s.KeriDriver.IssueCredential(owner.AID, map[string]interface{}{"role": "engineer"},
		"EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM", "", nil); err == nil {
		t.Fatal("the engine issued outside a registry where the key is elsewhere")
	}
	if kel, _ := c.requester.s.KeriDriver.GetKel(owner.AID); kel.EventCount != len(before) {
		t.Fatalf("the engine's key log holds %d events, not %d", kel.EventCount, len(before))
	}
	if unsigned := c.requester.s.unsignedOwnEvents(); len(unsigned) != 0 {
		t.Fatalf("unsigned events here: %v", unsigned)
	}
}

// Every rotation of this identity where its key is on another device is
// refused, and writes nothing: the rotation route, a recovery's rotation,
// and changing who owns it.
func TestNoRotationIsMadeWhereTheKeyIsElsewhere(t *testing.T) {
	c := newTwoCores(t)
	owner, _ := c.requester.s.DataStore.GetIdentity()
	before, _ := c.requester.s.DataStore.GetEvents(owner.AID)
	k1, k2 := testRotationKeys(t)
	for _, call := range []struct{ path, body string }{
		{"/api/rotation", `{"name":"` + owner.AID + `","new_public_key":"` + k1 + `","new_next_public_key":"` + k2 + `"}`},
		{"/api/owners/ceremony", `{"invite":["Sam"],"own_public_key":"` + k1 + `","own_next_public_key":"` + k2 + `"}`},
		{"/api/recovery/sessions/any/rotation", `{"name":"` + owner.AID + `","new_public_key":"` + k1 + `","new_next_public_key":"` + k2 + `"}`},
	} {
		rec := httptest.NewRecorder()
		c.requester.s.router.ServeHTTP(rec, local("POST", call.path, call.body))
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "can't be extended here") {
			t.Fatalf("%s was answered %d %s", call.path, rec.Code, rec.Body.String())
		}
	}
	if _, err := c.requester.s.rotateCarryingTheCommitment(owner.AID, k1, k2); !errors.Is(err, errKeyElsewhere) {
		t.Fatalf("a rotation carrying the commitment: %v", err)
	}
	if err := c.requester.s.mayRotateHere(owner.AID); err == nil {
		t.Fatal("a recovery rotation would be made here")
	}
	if after, _ := c.requester.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("a refused rotation wrote into the key log")
	}
	// Where the key is held, the same check lets a rotation through.
	if err := c.device.mayRotateHere(owner.AID); err != nil {
		t.Fatalf("a rotation where the key is held: %v", err)
	}
}

func testRotationKeys(t *testing.T) (string, string) {
	t.Helper()
	a, _ := signingPair(t, 81)
	b, _ := signingPair(t, 82)
	return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(a).Public().(ed25519.PublicKey)),
		iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey))
}

// Break-glass root rotation, switched on, is refused whole and plainly before
// anything is made, since its events are not yet signed by their keys.
func TestBreakGlassRootRotationIsRefusedPlainly(t *testing.T) {
	aMachineThatMayFound(t)
	prior := recovery.RootAIDRotationEnabled
	recovery.RootAIDRotationEnabled = true
	t.Cleanup(func() { recovery.RootAIDRotationEnabled = prior })
	s := agentWithDerivedIdentity(t)
	s.KeriDriver = keriengine.New()
	s.engineSigns()
	rec := httptest.NewRecorder()
	s.handleRecoveryRootAIDRotation(rec, local("POST", "/api/recovery/root-aid-rotation", `{}`))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "neither is yet signed by its key") {
		t.Fatalf("break-glass root rotation was answered %d %s", rec.Code, rec.Body.String())
	}
}
