package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// ownerPeer is a whole agent: its own store, witness service and the routes an
// owner actually uses to add and accept a contact, on a local address.
type ownerPeer struct {
	core       *CoreServer
	svc        *witness.Service
	aid        string
	witnessKey string
	identKey   string
	base       string
}

func startOwnerPeer(t *testing.T, aid string) *ownerPeer {
	t.Helper()
	return startOwnerPeerServing(t, aid, true)
}

// startOwnerPeerServing is startOwnerPeer, with or without a key history at the
// address it publishes.
func startOwnerPeerServing(t *testing.T, aid string, serveKeyHistory bool) *ownerPeer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	t.Cleanup(func() { ds.Close() })
	svc := witness.NewService(witness.NewSQLiteStore(ds.DB()), ds, nil, witness.BackendDesktop)
	svc.OurEntityType = func() witness.EntityType { return witness.EntityIndividual }

	signer, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	wkey, _ := signer.PublicKey()
	svc.OurWitnessAID = func() (string, error) { return wkey, nil }
	svc.SignReceipt = func(said string) (string, string, error) {
		raw, err := signer.Sign([]byte(said))
		if err != nil {
			return "", "", err
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return wkey, sig, err
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()
	svc.SignAsRequester = func(statement string) (string, error) { return login.SignString(statement, seed) }

	// The agent checks a published key history and mints the relationship
	// identifier an added contact gets, so the added contact is verified.
	if err := secureenclave.StoreDeviceLocalSeed(dir, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Skipf("root seed unavailable: %v", err)
	}
	engine := &driverfake.Engine{
		ValidateKELFunc: func(string, []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: true}, nil
		},
		ValidateKELBytesFunc: func(drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: true}, nil
		},
		CreateInceptionNamedFunc: func(_, _, name string) (*drivers.DriverInceptionResponse, error) {
			return &drivers.DriverInceptionResponse{AID: "ERel" + name}, nil
		},
	}

	p := &ownerPeer{core: &CoreServer{
		localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, WitnessService: svc, EventHub: NewEventHub(), KeriDriver: engine,
	}, svc: svc, aid: aid, witnessKey: wkey, identKey: iacrypto.NonTransferableAIDQB64(pub)}

	r := chi.NewRouter()
	// What this agent publishes about itself, for the other's owner to add.
	r.Get("/public/oobi/{aid}", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"aid": aid, "public_key": p.identKey, "alias": "peer-" + aid[len(aid)-1:],
			"backend_type": witness.BackendDesktop, "witness_key": wkey, "entity_type": "individual",
		}
		if serveKeyHistory {
			doc["kel"] = []map[string]any{{"t": "icp", "d": aid, "i": aid, "s": "0"}}
		}
		json.NewEncoder(w).Encode(doc)
	})
	r.Route("/api", func(r chi.Router) {
		r.Post("/contacts", p.core.handleAddContact)
		r.Post("/contacts/{aid}/accept", p.core.handleAcceptContact)
		p.core.mountWitnessRoutes(r)
		r.Post("/witness/request", p.core.handleWitnessRequest)
		r.Post("/witness/accept", p.core.handleWitnessAccept)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	p.base = srv.URL
	svc.OurAID = func() string { return aid }
	svc.OurOOBI = func() string { return p.base + "/public/oobi/" + aid }
	return p
}

func (p *ownerPeer) oobi() string { return p.base + "/public/oobi/" + p.aid }

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Two agents whose owners add each other by address, through the add-contact
// route and no seeded rows, then a witness request and its answer succeed.
func TestOwnersWhoAddEachOtherCanAskAndAnswerAWitnessRequest(t *testing.T) {
	a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
	b := startOwnerPeer(t, "EAgentB0000000000000000000000000000000000002")

	for _, c := range []struct{ owner, other *ownerPeer }{{a, b}, {b, a}} {
		if resp := postJSON(t, c.owner.base+"/api/contacts", map[string]any{"oobi_url": c.other.oobi(), "trusted": true}); resp.StatusCode != http.StatusCreated {
			t.Fatalf("the owner's add-contact was refused: %d", resp.StatusCode)
		}
	}
	rec, _ := a.core.DataStore.GetContact(b.aid)
	if rec == nil || rec.Status != "accepted" {
		t.Fatalf("a contact the owner added is %+v, not accepted", rec)
	}

	if err := a.svc.SendWitnessRequest(context.Background(), b.aid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "B's answer to enrol it as A's witness", func() bool {
		c, _ := a.core.DataStore.GetContact(b.aid)
		return c != nil && c.IsWitness
	})
	if meta, _ := b.svc.Store.GetContactMeta(a.aid); meta == nil || !meta.WitnessingFor {
		t.Fatal("B does not witness for A after accepting")
	}
}

// A local or dev peer that introduced itself keeps its address, is not called
// while the owner has not agreed to it, and is once the owner accepts it
// through the accept route.
func TestALocalPeerIsAnsweredOnceTheOwnerAcceptsIt(t *testing.T) {
	a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
	b := startOwnerPeer(t, "EAgentB0000000000000000000000000000000000002")
	if resp := postJSON(t, b.base+"/api/contacts", map[string]any{"oobi_url": a.oobi(), "trusted": true}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("B's owner could not add A: %d", resp.StatusCode)
	}

	// B introduces itself to A from a local address.
	body, _ := json.Marshal(map[string]string{"oobi_url": b.oobi()})
	if err := a.core.recordConnectionRequest(b.aid, &didcomm.JWM{Type: didcomm.TypeContactRequest, Body: body}); err != nil {
		t.Fatal(err)
	}
	pending, _ := a.core.DataStore.GetContact(b.aid)
	if pending.OobiURL != b.oobi() {
		t.Fatalf("the address was not kept: %q", pending.OobiURL)
	}
	pending.PublicKey = b.identKey // the history the introduction proved
	_ = a.core.DataStore.SaveContact(*pending)

	// Unconfirmed: the address is recorded and unusable, and the request is not acted on.
	err := a.svc.SendAcceptCallback(context.Background(), b.oobi(), witness.AcceptCallback{RequesterAID: b.aid, Decision: "declined", Reason: "x", RequestID: "r"})
	if err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("an answer went toward an address the owner has not confirmed: %v", err)
	}

	if resp := postJSON(t, a.base+"/api/contacts/"+b.aid+"/accept", map[string]any{"contact_category": "trusted"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("accept refused: %d", resp.StatusCode)
	}
	if c, _ := a.core.DataStore.GetContact(b.aid); c.Status != "accepted" || c.ContactSource != witness.ContactSourceInboundConfirmed || c.OobiURL == "" {
		t.Fatalf("after accepting: %+v", c)
	}
	if _, err := a.core.resolveKnownContactAsPeer(b.aid); err != nil && strings.Contains(err.Error(), "no recorded address") {
		t.Fatalf("an accepted local peer has no address: %v", err)
	}

	// Now B asks A to witness, and A's answer reaches B.
	a.svc.RecordContactCapability(b.aid, witness.BackendDesktop, b.witnessKey, "individual")
	b.svc.RecordContactCapability(a.aid, witness.BackendDesktop, a.witnessKey, "individual")
	if err := b.svc.SendWitnessRequest(context.Background(), a.aid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "A's answer to enrol it as B's witness", func() bool {
		c, _ := b.core.DataStore.GetContact(a.aid)
		return c != nil && c.IsWitness
	})
}

// An address that serves no key history gives a contact whose identifier and
// key are only what that host claims: it is recorded as unchecked, is not
// accepted, and gets no witness request.
func TestAContactWhoseKeyWasNeverCheckedIsNotAccepted(t *testing.T) {
	a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
	b := startOwnerPeerServing(t, "EAgentB0000000000000000000000000000000000002", false)

	if resp := postJSON(t, a.base+"/api/contacts", map[string]any{"oobi_url": b.oobi(), "trusted": true}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("the owner's add-contact was refused: %d", resp.StatusCode)
	}
	rec, _ := a.core.DataStore.GetContact(b.aid)
	if rec == nil || rec.Status != "unchecked" || rec.Verified {
		t.Fatalf("a contact whose address served no key history is %+v, want unchecked", rec)
	}
	if err := a.svc.SendWitnessRequest(context.Background(), b.aid); err == nil {
		t.Fatal("a witness request went to a contact whose key was never checked")
	}
	if meta, _ := b.svc.Store.GetContactMeta(a.aid); meta != nil && meta.WitnessingFor {
		t.Fatal("B witnesses for A without ever being asked")
	}
}
