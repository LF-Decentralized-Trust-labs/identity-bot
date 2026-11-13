package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A witness is reached by whoever holds the identity's keys, through the router
// an agent really serves, with no credential of this agent's: the app sending
// its own event, and a peer reading how far the witness holds the log. Each
// was refused with 403 before its handler ran until these routes were
// declared public, and the tests that mounted the witness routes on a bare
// router could not see it.
// aRoutedWitness is a witness behind the router an agent really serves, with a
// signing key of its own.
func aRoutedWitness(t *testing.T) (svc *witness.Service, key string, srv *httptest.Server, peer *peerAgent) {
	t.Helper()
	s := agentWithNoIdentity(t)
	svc = witness.NewService(witness.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()), s.DataStore, nil, witness.BackendDesktop)
	svc.OurEntityType = func() witness.EntityType { return witness.EntityIndividual }
	signer, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	key, _ = signer.PublicKey()
	svc.OurWitnessAID = func() (string, error) { return key, nil }
	svc.SignEventReceipt = receiptSignerFor(signer, key)
	svc.SignReceipt = func(msg string) (string, string, error) {
		raw, err := signer.Sign([]byte(msg))
		if err != nil {
			return "", "", err
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return key, sig, err
	}
	s.WitnessService = svc
	srv = httptest.NewServer(s.buildRouter())
	t.Cleanup(srv.Close)
	peer = &peerAgent{svc: svc, witnessKey: key, base: srv.URL}

	return svc, key, srv, peer
}

func TestAWitnessIsReachedWithoutThisAgentsCredentials(t *testing.T) {
	_, key, srv, peer := aRoutedWitness(t)

	aid, said, raw, sig := signedInception(t, key)
	peer.willWitnessFor(t, aid)

	// No owner secret, no signed request: a stranger to this agent.
	body, _ := json.Marshal(map[string]any{
		"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw),
		"cesr_signatures": []string{sig},
	})
	res, err := http.Post(srv.URL+"/api/witness/event", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		EventSAID  string `json:"event_said"`
		WitnessAID string `json:"witness_aid"`
		Sig        string `json:"cesr_signature"`
	}
	_ = json.NewDecoder(res.Body).Decode(&receipt)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the event was not taken: %d", res.StatusCode)
	}
	if receipt.EventSAID != said || receipt.WitnessAID != key ||
		drivers.VerifyEventReceipt(key, raw, said, receipt.Sig, nil) != nil {
		t.Fatalf("the receipt is not this witness's over this event: %+v", receipt)
	}

	get := func(path string, withInception bool) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if withInception {
			req.Header.Set(witness.HeaderInception, base64.RawURLEncoding.EncodeToString(raw))
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// A stranger is answered as for a log not held: the tip is signed all the
	// same, and says nothing is held, and the event is not found.
	res = get("/api/witness/kel/"+aid+"/tip?nonce=n0nce", false)
	var tip witness.TipAnswer
	_ = json.NewDecoder(res.Body).Decode(&tip)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || tip.SN != -1 || tip.SAID != "" ||
		drivers.VerifyReceipt(key, witness.TipStatement(aid, "n0nce", -1, ""), tip.Signature) != nil {
		t.Fatalf("a stranger was told what the witness holds: %d %+v", res.StatusCode, tip)
	}
	res = get("/api/witness/kel/"+aid+"/event/0", false)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("a stranger was given an event: %d", res.StatusCode)
	}

	// Somebody who holds the log's inception, as a verifier given the log by its
	// controller does, is answered from what is held.
	res = get("/api/witness/kel/"+aid+"/tip?nonce=n0nce", true)
	tip = witness.TipAnswer{}
	_ = json.NewDecoder(res.Body).Decode(&tip)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || tip.SN != 0 || tip.SAID != said ||
		drivers.VerifyReceipt(key, witness.TipStatement(aid, "n0nce", 0, said), tip.Signature) != nil {
		t.Fatalf("the tip was not answered, signed: %d %+v", res.StatusCode, tip)
	}

	res = get("/api/witness/kel/"+aid+"/event/"+strconv.Itoa(0), true)
	var ev witness.SignedEvent
	_ = json.NewDecoder(res.Body).Decode(&ev)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || ev.RawBytesB64 != base64.StdEncoding.EncodeToString(raw) ||
		len(ev.Signatures) != 1 || ev.Signatures[0] != sig {
		t.Fatalf("the event was not answered as signed: %d %+v", res.StatusCode, ev)
	}
}
