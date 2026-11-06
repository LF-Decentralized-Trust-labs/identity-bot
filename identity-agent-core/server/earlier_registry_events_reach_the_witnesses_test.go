package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// pairwiseIssuer founds a second identity this agent holds the key of, naming
// bob as its witness, the way a pairwise identity is held: its own key log in
// the store, its signer known to the agent, and bob willing to witness for it.
func (w *pushWorld) pairwiseIssuer() string {
	w.t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	pub := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	next, _ := keri.GenerateSigner(true)
	nextPub, _ := next.PublicKey()
	founding := keriengine.New()
	icp, err := founding.Incept(drivers.InceptionRequest{
		PublicKey: pub, NextPublicKey: nextPub, Name: "pairwise", Witnesses: []string{w.bob.witnessKey}, Toad: 1,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	kel, _ := founding.GetKel("pairwise")
	raw, _ := base64.StdEncoding.DecodeString(icp.RawBytesB64)
	sig, err := signEventBytes(raw, seed)
	if err != nil {
		w.t.Fatal(err)
	}
	ev, _ := json.Marshal(kel.KEL[0])
	if err := w.s.DataStore.SaveEvent(store.EventRecord{
		AID: icp.AID, SequenceNumber: 0, EventType: "icp", EventJSON: string(ev),
		PublicKey: pub, RawBytesB64: icp.RawBytesB64, CesrSignature: sig,
	}); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.eng.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID: icp.AID, PublicKey: icp.PublicKey, NextKeyDigest: icp.NextKeyDigest,
		KEL: kel.KEL, RawEventsB64: kel.RawEventsB64,
	}); err != nil {
		w.t.Fatal(err)
	}
	w.s.eventSigners.Store(icp.AID, seed)
	// A pairwise identity takes commercial witnesses only (witness/eligibility.go),
	// so bob is a service witness for it, asked at the root, where his routes
	// are under /api.
	was := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness {
		return []witness.BootstrapWitness{{AID: "EBOBSERVICE", WitnessKey: w.bob.witnessKey, URL: w.bob.base + "/api", Operator: "test"}}
	}
	w.t.Cleanup(func() { witness.BootstrapWitnesses = was })
	w.bob.willWitnessFor(w.t, icp.AID)
	return icp.AID
}

func (w *pushWorld) issueAs(aid string) {
	w.t.Helper()
	reg, err := w.eng.InceptRegistry(aid)
	if err != nil {
		w.t.Fatal(err)
	}
	schema, _ := keri.Blake3SAID([]byte("a test schema"))
	if _, err := w.eng.IssueCredentialInRegistry(aid, map[string]interface{}{"role": "engineer"},
		schema, "EHolder000000000000000000000000000000000000", nil, reg.RegistrySaid); err != nil {
		w.t.Fatalf("the issuance failed: %v", err)
	}
}

func (w *pushWorld) bobServesFor(aid string) (int, int) {
	ans, err := w.bob.svc.ServeTEL(aid, -1)
	if err != nil {
		return 0, 0
	}
	return len(ans.Events), ans.AnchoredSN
}

// Events kept before the outbox existed are queued once at start, and the
// witnesses then serve them.
func TestRegistryEventsMadeBeforeTheOutboxAreSentOnce(t *testing.T) {
	w := newPushWorld(t)
	w.issue()
	// As it was before the outbox: kept, never queued.
	for _, p := range w.pending() {
		_ = w.s.DataStore.FinishTELPushes(p.IssuerAID, []string{p.SAID})
	}
	w.eventually(func() bool { return len(w.pending()) == 0 }, "the outbox should be empty")

	w.s.backfillRegistryEvents()
	p := w.pending()
	if len(p) < 2 || p[0].Kind != "vcp" {
		t.Fatalf("the registry's inception and the issuance should be queued, inception first: %+v", p)
	}
	// (The witnessing worker brings bob the key log itself, then the events.)
	w.eventually(func() bool { n, anchored := w.bobServes(); return n == 2 && anchored == 2 && len(w.pending()) == 0 },
		"the witness should serve what was made before the outbox")

	// Once: a second start queues nothing, however much was sent.
	w.s.backfillRegistryEvents()
	if p := w.pending(); len(p) != 0 {
		t.Fatalf("the earlier events were queued again at the next start: %+v", p)
	}
}

// A pairwise identity's registry events reach that identity's witnesses, and
// the witnessing pass brings that identity's key log to them first, with no
// help from the owner's.
func TestAPairwiseIssuersEventsReachItsWitnessesWithItsKeyLog(t *testing.T) {
	w := newPushWorld(t)
	pw := w.pairwiseIssuer()
	w.issueAs(pw)
	// Earlier events of the pairwise identity too.
	for _, p := range w.pending() {
		_ = w.s.DataStore.FinishTELPushes(p.IssuerAID, []string{p.SAID})
	}
	w.s.backfillRegistryEvents()
	if n, _ := w.bobServesFor(pw); n != 0 {
		t.Fatalf("bob cannot hold events before its key log; it serves %d", n)
	}
	// Bob has been given no key log of the pairwise identity: the pass must.
	w.eventually(func() bool {
		n, anchored := w.bobServesFor(pw)
		return n == 2 && anchored == 2 && len(w.pending()) == 0
	},
		"the pairwise identity's witness should serve its registry events")
}
