package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	rds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: rds, EventHub: NewEventHub()}
	r.KeriDriver = keriengine.New()
	r.reloadIdentityIntoDriver()
	if err := r.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	r.router = r.buildRouter("")
	if !r.keyIsElsewhere() {
		t.Fatalf("the requester can sign as the identity: %v", r.keyCanSign())
	}
	if err := device.keyCanSign(); err != nil {
		t.Fatalf("the device cannot sign: %v", err)
	}
	return &twoCores{device: device, requester: &elsewhere{s: r}}
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
		return c.device.signForAnother(req.PayloadB64, parts["credential_b64"], parts["issuance_b64"], parts["registry_b64"])
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
	if _, err := c.device.signForAnother(b64(one.IxnRaw), b64(two.AcdcRaw), b64(two.IssRaw), ""); err == nil {
		t.Fatal("the device signed an interaction shown with another credential")
	}
	if now, _ := c.device.DataStore.GetEvents(owner.AID); len(now) != len(before) {
		t.Fatal("the device recorded what it refused to sign")
	}
	sig, err := c.device.signForAnother(b64(one.IxnRaw), b64(one.AcdcRaw), b64(one.IssRaw), "")
	if err != nil {
		t.Fatalf("the first: %v", err)
	}
	if _, err := c.device.signForAnother(b64(two.IxnRaw), b64(two.AcdcRaw), b64(two.IssRaw), ""); err == nil || !strings.Contains(err.Error(), "already signed another event") {
		t.Fatal("the device signed a second event at a place it had filled")
	}
	again, err := c.device.signForAnother(b64(one.IxnRaw), b64(one.AcdcRaw), b64(one.IssRaw), "")
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
