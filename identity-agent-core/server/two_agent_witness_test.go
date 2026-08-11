package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// Two agents witnessing for each other, over real HTTP.
//
// The individual pieces are covered by unit tests, which is not the same thing.
// The wire between them is where this has actually been wrong twice: once
// because the path an agent builds did not exist on the other side, and once
// because the controller's signature never travelled at all — and both times
// every unit test passed. So this runs two independent witness services, each
// with its own store and its own key, and makes one receipt the other through
// the handler an agent really serves.

type peerAgent struct {
	svc        *witness.Service
	witnessKey string
	base       string
}

// startPeer brings up one agent's witness surface on its own address.
func startPeer(t *testing.T, name string) *peerAgent {
	t.Helper()
	dir := t.TempDir()

	dataStore, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	t.Cleanup(func() { dataStore.Close() })

	svc := witness.NewService(witness.NewSQLiteStore(dataStore.DB()), dataStore, nil, witness.BackendDesktop)
	svc.OurEntityType = func() witness.EntityType { return witness.EntityIndividual }

	// The witnessing key belongs to the agent, not to the witness package, so
	// the host supplies both signing and the identifier. Each agent gets its
	// own, which is what makes them two observers rather than one.
	signer, err := keri.GenerateSigner(false) // non-transferable, as a witness must be
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	svc.OurWitnessAID = func() (string, error) { return key, nil }
	svc.SignReceipt = func(said string) (string, string, error) {
		raw, err := signer.Sign([]byte(said))
		if err != nil {
			return "", "", err
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return key, sig, err
	}
	_ = dir

	// The route an agent actually serves, on the handler it actually uses.
	core := &CoreServer{WitnessService: svc}
	r := chi.NewRouter()
	r.Post("/api/witness/event", core.handleWitnessEvent)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	return &peerAgent{svc: svc, witnessKey: key, base: srv.URL}
}

// willWitnessFor makes this agent willing to witness for an identity.
func (p *peerAgent) willWitnessFor(t *testing.T, aid string) {
	t.Helper()
	if err := p.svc.Contacts.SaveContact(store.ContactRecord{
		AID: aid, Status: "accepted", ContactCategory: "general",
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.svc.Store.SaveContactMeta(witness.ContactMeta{
		ContactAID: aid, BackendType: witness.BackendDesktop, EntityType: "individual",
		WitnessingFor: true, WitnessStatus: witness.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
}

// signedInception founds an identity designating the given witness.
func signedInception(t *testing.T, witnessKey string) (aid, said string, raw []byte, sig string) {
	t.Helper()
	e := keriengine.New()
	a, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := a.PublicKey()
	nextPub, _ := b.PublicKey()

	req := drivers.InceptionRequest{PublicKey: pub, NextPublicKey: nextPub, Name: "subject"}
	if witnessKey != "" {
		req.Witnesses = []string{witnessKey}
		req.Toad = 1
	}
	icp, err := e.Incept(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(icp.RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := a.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
	if err != nil {
		t.Fatal(err)
	}
	return ev.Identifier, ev.SAID, raw, sig
}

func TestTwoAgentsWitnessForEachOther(t *testing.T) {
	alice := startPeer(t, "alice")
	bob := startPeer(t, "bob")

	// Two agents must not derive the same witness key — that would be one
	// observer wearing two names, and a threshold of two met by one machine.
	if alice.witnessKey == bob.witnessKey {
		t.Fatal("both agents derived the same witness key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Alice's identity, designating Bob. Bob agrees to witness for it.
	aliceAID, aliceSAID, aliceRaw, aliceSig := signedInception(t, bob.witnessKey)
	bob.willWitnessFor(t, aliceAID)

	resp, err := alice.svc.SubmitToWitness(ctx, bob.base+"/api/witness/event",
		aliceAID, aliceRaw, aliceSig)
	if err != nil {
		t.Fatalf("bob would not witness for alice: %v", err)
	}
	issuer, _ := resp["witness_aid"].(string)
	receipt, _ := resp["cesr_signature"].(string)
	if issuer != bob.witnessKey {
		t.Fatalf("the receipt is attributed to %s, not to bob's key %s", issuer, bob.witnessKey)
	}

	// Alice checks it herself, against the key her own event names.
	res, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID: aliceAID, RawEvents: [][]byte{aliceRaw}, CesrSignatures: []string{aliceSig},
		Receipts: map[string][]drivers.WitnessReceipt{
			aliceSAID: {{WitnessAID: issuer, CesrSignature: receipt}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.KelVerified || !res.Witnessed {
		t.Fatalf("alice's log: verified=%v witnessed=%v %v",
			res.KelVerified, res.Witnessed, res.ValidationErrors)
	}

	// And the other direction, so this is mutual rather than one-way.
	bobAID, bobSAID, bobRaw, bobSig := signedInception(t, alice.witnessKey)
	alice.willWitnessFor(t, bobAID)

	resp, err = bob.svc.SubmitToWitness(ctx, alice.base+"/api/witness/event",
		bobAID, bobRaw, bobSig)
	if err != nil {
		t.Fatalf("alice would not witness for bob: %v", err)
	}
	issuer, _ = resp["witness_aid"].(string)
	receipt, _ = resp["cesr_signature"].(string)
	res, err = drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID: bobAID, RawEvents: [][]byte{bobRaw}, CesrSignatures: []string{bobSig},
		Receipts: map[string][]drivers.WitnessReceipt{
			bobSAID: {{WitnessAID: issuer, CesrSignature: receipt}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Witnessed {
		t.Fatalf("bob's log was not witnessed by alice: %+v", res.WitnessDetail)
	}
}

// Over the same wire, a peer must refuse what it cannot verify. This is the
// pair of checks that unit tests passed while the wire was carrying nothing.
func TestAPeerRefusesOverTheWireWhatItCannotVerify(t *testing.T) {
	bob := startPeer(t, "bob")
	alice := startPeer(t, "alice")
	ctx := context.Background()

	aid, _, raw, _ := signedInception(t, bob.witnessKey)
	bob.willWitnessFor(t, aid)

	// No controller signature.
	if _, err := alice.svc.SubmitToWitness(ctx, bob.base+"/api/witness/event", aid, raw, ""); err == nil {
		t.Fatal("a peer receipted an event that arrived unsigned")
	}

	// Signed by somebody else.
	_, _, _, strangerSig := signedInception(t, bob.witnessKey)
	if _, err := alice.svc.SubmitToWitness(ctx, bob.base+"/api/witness/event", aid, raw, strangerSig); err == nil {
		t.Fatal("a peer receipted an event signed by a key it does not declare")
	}

	// An identity it never agreed to witness for.
	other, _, otherRaw, otherSig := signedInception(t, bob.witnessKey)
	if _, err := alice.svc.SubmitToWitness(ctx, bob.base+"/api/witness/event",
		other, otherRaw, otherSig); err == nil {
		t.Fatal("a peer witnessed for an identity it never agreed to")
	}
	_ = http.StatusOK
}
