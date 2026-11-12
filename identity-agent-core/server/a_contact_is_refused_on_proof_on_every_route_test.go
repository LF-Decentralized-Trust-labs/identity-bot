package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
	"identity-agent-core/watcher"
)

// withParsedFields is a log's records as a route holds them: each event's bytes
// and signature, and its own fields beside them.
func withParsedFields(recs []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(recs))
	for _, rec := range recs {
		c := map[string]interface{}{}
		for k, v := range rec {
			c[k] = v
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(rec["event_json"].(string)), &ev); err == nil {
			for k, v := range ev {
				if _, taken := c[k]; !taken {
					c[k] = v
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// aStandingWatcherHolding makes the agent's watcher service ask one trusted
// standing watcher, which answers a signed digest of records and serves them as
// the log it holds, as /public/kel-digest and /witness/kel/{aid} do.
func aStandingWatcherHolding(t *testing.T, s *CoreServer, aid string, records []map[string]interface{}) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) + 9
	}
	signer := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/witness/kel/") {
			json.NewEncoder(w).Encode(map[string]interface{}{"aid": aid, "kel": records, "count": len(records)})
			return
		}
		var seq int
		for _, c := range r.URL.Query().Get("seq") {
			seq = seq*10 + int(c-'0')
		}
		resp := watcher.DigestResponse{AID: r.URL.Query().Get("aid"), SequenceNumber: seq, SignedBy: signer}
		if d, err := witnessproto.KelDigestAtSeq(records, seq); err == nil && seq < len(records) {
			resp.Digest = &d
		}
		stmt, _ := witnessproto.DigestStatement(resp.AID, seq, resp.Digest, nil, nil)
		resp.Signature, _ = login.SignString(stmt, seed)
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	ws := watcher.NewService(watcher.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()))
	ws.L2 = &watcher.L2Client{HTTPClient: http.DefaultClient, TrustedSigners: func() []string { return []string{signer} }}
	if err := ws.Store.SetConfig("default_l2_url", srv.URL); err != nil {
		t.Fatal(err)
	}
	s.WatcherService = ws
}

func twoSignedHistories(t *testing.T) (honest, rival *signedlog.Log) {
	t.Helper()
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("first")
	return base.Fork().Interact("honest"), base.Fork().Interact("rival")
}

func aRecordedPost(h http.HandlerFunc, path string, body map[string]interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rec
}

// A standing watcher that shows a validly signed rival event at a place the
// presented log holds a different event at stops the OOBI resolve and the add
// contact routes: no contact, and no key log kept. With a watcher holding the
// same log both go through, so the refusal below is the proof and nothing else.
//
// Fails when either route goes back to checking the log after it is kept, or to
// ignoring what the watcher proved.
func TestAProvenForkStopsOobiResolveAndAddContact(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	honest, rival := twoSignedHistories(t)
	recs := withParsedFields(honest.Records())
	for _, c := range []struct {
		name   string
		holds  *signedlog.Log
		refuse bool
	}{{"a watcher holding the same log", honest, false}, {"a watcher proving a fork", rival, true}} {
		s := witnessWithSeed(t, 7)
		s.KeriDriver = anEngineThatVerifies(honest.Key(), honest.Len())
		aStandingWatcherHolding(t, s, honest.AID, withParsedFields(c.holds.Records()))
		peer := aPeerServing(t, honest.AID, honest.Key(), recs)
		body := map[string]interface{}{"oobi_url": peer.URL + "/oobi/" + honest.AID, "alias": "x"}

		resolve := aRecordedPost(s.handleResolveOobiContact, "/api/oobi/resolve", body)
		add := aRecordedPost(s.handleAddContact, "/api/contacts", body)
		if c.refuse {
			for name, rec := range map[string]*httptest.ResponseRecorder{"resolve": resolve, "add": add} {
				if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"duplicity"`) {
					t.Fatalf("%s, %s: %d %s", c.name, name, rec.Code, rec.Body.String())
				}
			}
			if k, _ := s.DataStore.GetContactKEL(honest.AID); k != nil {
				t.Fatalf("a refused log was kept: %+v", k)
			}
			if ct, _ := s.DataStore.GetContact(honest.AID); ct != nil {
				t.Fatalf("a refused contact was added: %+v", ct)
			}
		} else if resolve.Code != http.StatusOK || add.Code == http.StatusConflict {
			t.Fatalf("%s: resolve %d %s, add %d %s", c.name, resolve.Code, resolve.Body.String(), add.Code, add.Body.String())
		}
	}
}

// The same, for the two routes that read a credential issuer's key log: the
// credential-verify route and credential sign-in. The issuer's log is the
// world's own real one, and the rival event is an interaction at its last place signed
// by the issuer's one key.
func TestAProvenForkOfAnIssuersLogStopsCredentialVerifyAndSignIn(t *testing.T) {
	for _, forked := range []bool{false, true} {
		w := aGateWorldHolding(t, true, logHeldAsContact)
		held, err := w.s.DataStore.GetContactKEL(w.issuer)
		if err != nil || held == nil || len(held.KEL) < 2 {
			t.Fatalf("the issuer's log: %v %+v", err, held)
		}
		records := withParsedFields(held.KEL)
		// The watcher service sees the log with the fields a route hands it.
		held.KEL = records
		if err := w.s.DataStore.SaveContactKEL(*held); err != nil {
			t.Fatal(err)
		}
		shown := records
		if forked {
			n := len(records)
			shown = append([]map[string]interface{}{}, records[:n-1]...)
			shown = append(shown, aRivalAtThePlaceOfTheLastEvent(t, w, records[n-2], n-1))
		}
		aStandingWatcherHolding(t, w.s, w.issuer, shown)

		rec := aRecordedPost(w.s.handleVerifyCredential, "/api/credentials/verify", map[string]interface{}{"acdc_json": w.acdc})
		ok, _, reason := w.s.verifyPresentedCredentialACDC(context.Background(), w.acdc, w.holder, "", "", "", nil)
		if forked {
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "duplicity") {
				t.Fatalf("credential verify with a proven fork: %d %s", rec.Code, rec.Body.String())
			}
			if ok || !strings.Contains(reason, "duplicity") {
				t.Fatalf("sign-in with a proven fork: ok=%v reason=%q", ok, reason)
			}
		} else if rec.Code != http.StatusOK {
			t.Fatalf("credential verify with an agreeing watcher: %d %s", rec.Code, rec.Body.String())
		}
	}
}

// aRivalAtThePlaceOfTheLastEvent is an interaction event at the last place of the
// issuer's log, signed by the issuer's key, different from the one the log holds.
func aRivalAtThePlaceOfTheLastEvent(t *testing.T, w *aGateWorld, before map[string]interface{}, sn int) map[string]interface{} {
	t.Helper()
	ev, err := keri.ParseEvent(mustDecode(t, before["raw_bytes_b64"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: w.issuer, PriorSAID: ev.SAID, SN: sn, Data: []json.RawMessage{json.RawMessage(`{"d":"a-rival"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signsWithTheKeysMadeHere(w.issuer, w.issuerKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	return withParsedFields([]map[string]interface{}{{
		"event_json": string(raw), "raw_bytes_b64": b64s(raw), "cesr_signature": sig,
	}})[0]
}
