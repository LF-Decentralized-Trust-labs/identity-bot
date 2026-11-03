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
func TestAWitnessIsReachedWithoutThisAgentsCredentials(t *testing.T) {
	s := agentWithNoIdentity(t)
	svc := witness.NewService(witness.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()), s.DataStore, nil, witness.BackendDesktop)
	svc.OurEntityType = func() witness.EntityType { return witness.EntityIndividual }
	signer, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := signer.PublicKey()
	svc.OurWitnessAID = func() (string, error) { return key, nil }
	svc.SignReceipt = func(msg string) (string, string, error) {
		raw, err := signer.Sign([]byte(msg))
		if err != nil {
			return "", "", err
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return key, sig, err
	}
	s.WitnessService = svc
	srv := httptest.NewServer(s.buildRouter(""))
	t.Cleanup(srv.Close)
	peer := &peerAgent{svc: svc, witnessKey: key, base: srv.URL}

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
		drivers.VerifyReceipt(key, said, receipt.Sig) != nil {
		t.Fatalf("the receipt is not this witness's over this event: %+v", receipt)
	}

	res, err = http.Get(srv.URL + "/api/witness/kel/" + aid + "/tip?nonce=n0nce")
	if err != nil {
		t.Fatal(err)
	}
	var tip witness.TipAnswer
	_ = json.NewDecoder(res.Body).Decode(&tip)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || tip.SN != 0 || tip.SAID != said ||
		drivers.VerifyReceipt(key, witness.TipStatement(aid, "n0nce", 0, said), tip.Signature) != nil {
		t.Fatalf("the tip was not answered, signed: %d %+v", res.StatusCode, tip)
	}

	res, err = http.Get(srv.URL + "/api/witness/kel/" + aid + "/event/" + strconv.Itoa(0))
	if err != nil {
		t.Fatal(err)
	}
	var ev witness.SignedEvent
	_ = json.NewDecoder(res.Body).Decode(&ev)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || ev.RawBytesB64 != base64.StdEncoding.EncodeToString(raw) ||
		len(ev.Signatures) != 1 || ev.Signatures[0] != sig {
		t.Fatalf("the event was not answered as signed: %d %+v", res.StatusCode, ev)
	}
}
