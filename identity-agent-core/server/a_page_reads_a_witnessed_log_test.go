package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A page in a browser reads a key log from a witness the log's inception names.
// It has the inception (the first event of the log it was given) and nothing
// else, so the read must be open to that proof across origins, and the answer
// must carry what the page checks: each event's bytes, and this witness's
// receipt of it. A read without the proof is answered, and seen, exactly as a
// log that is not held.
func TestAPageReadsAWitnessedLogAcrossOrigins(t *testing.T) {
	_, key, srv, peer := aRoutedWitness(t)
	aid, said, raw, sig := signedInception(t, key)
	peer.willWitnessFor(t, aid)
	body, _ := json.Marshal(map[string]any{
		"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw),
		"cesr_signatures": []string{sig},
	})
	res, err := http.Post(srv.URL+"/api/witness/event", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the event was not taken: %d", res.StatusCode)
	}

	read := func(method, aid string, inception []byte) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, srv.URL+"/api/witness/kel/"+aid, nil)
		req.Header.Set("Origin", "https://page.example")
		if method == "OPTIONS" { // a browser's real preflight, which the server's cross-origin policy answers unless a route says it does
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", witness.HeaderInception)
		}
		if inception != nil {
			req.Header.Set(witness.HeaderInception, base64.RawURLEncoding.EncodeToString(inception))
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}

	// The browser asks first whether X-Inception-Event may be sent. The answer
	// is the same for a log held and one that is not.
	held, _ := read("OPTIONS", aid, nil)
	other, _ := read("OPTIONS", "EnotHeldAtAllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", nil)
	for _, r := range []*http.Response{held, other} {
		if r.StatusCode != http.StatusNoContent || r.Header.Get("Access-Control-Allow-Origin") != "*" ||
			r.Header.Get("Access-Control-Allow-Headers") != witness.HeaderInception {
			t.Fatalf("the preflight did not let a page send the inception: %d %v", r.StatusCode, r.Header)
		}
	}

	// With the inception: the log, readable by the page, each event with its
	// bytes and this witness's receipt, which verifies over those bytes.
	res, b := read("GET", aid, raw)
	if res.StatusCode != http.StatusOK || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("a page was not given the log it presented the inception of: %d %v", res.StatusCode, res.Header)
	}
	// What it says depends on the proof presented, so no cache may keep it for another asker.
	if res.Header.Get("Cache-Control") != "no-store" || !strings.Contains(strings.Join(res.Header.Values("Vary"), ","), witness.HeaderInception) {
		t.Fatalf("a read that depends on the inception was not marked so: %v", res.Header)
	}
	var ans struct {
		KEL []struct {
			Raw      string `json:"raw_bytes_b64"`
			Receipts []struct {
				Witness string `json:"witness"`
				Sig     string `json:"cesr_signature"`
			} `json:"witness_receipts"`
		} `json:"kel"`
	}
	if err := json.Unmarshal(b, &ans); err != nil || len(ans.KEL) != 1 {
		t.Fatalf("unreadable answer: %v %s", err, b)
	}
	e := ans.KEL[0]
	got, _ := drivers.DecodeRawBytes(e.Raw)
	if !bytes.Equal(got, raw) || len(e.Receipts) != 1 || e.Receipts[0].Witness != key ||
		drivers.VerifyEventReceipt(key, got, said, e.Receipts[0].Sig, nil) != nil {
		t.Fatalf("the answer does not carry the event's bytes and this witness's receipt of them: %s", b)
	}

	// Without it, or with another log's: the answer for a log not held, and
	// nothing that lets a page read it.
	_, unheld := read("GET", "EnotHeldAtAllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", raw)
	for name, inc := range map[string][]byte{"none": nil, "another log's": []byte(`{"t":"icp","d":"Eother"}`)} {
		res, b := read("GET", aid, inc)
		if res.StatusCode != http.StatusNotFound || res.Header.Get("Access-Control-Allow-Origin") != "" ||
			!bytes.Equal(b, unheld) {
			t.Fatalf("a read with %s inception was told more than a read of a log not held: %d %s", name, res.StatusCode, b)
		}
	}
}

// Pages read through the URL relay, which reaches this agent from its own
// address: each is counted as the visitor the relay names, so one page's reads
// cannot use up the allowance of every page behind the relay.
func TestPagesBehindTheRelayAreCountedApart(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()), s.DataStore, nil, witness.BackendDesktop)
	from := func(visitor string) int {
		r := httptest.NewRequest("GET", "/api/witness/kel/ENotHeldAtAllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", nil)
		r = r.WithContext(relayproto.ContextWithPreamble(r.Context(), relayproto.Preamble{Visitor: visitor}))
		w := httptest.NewRecorder()
		s.witnessReadAllowed(w, r, "ENotHeldAtAllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		return w.Code
	}
	for i := 0; i < 120; i++ {
		if code := from("203.0.113.7:4000"); code != http.StatusNotFound {
			t.Fatalf("read %d of one visitor: %d", i, code)
		}
	}
	if code := from("203.0.113.7:4001"); code != http.StatusTooManyRequests {
		t.Fatalf("a visitor past its allowance was not limited: %d", code)
	}
	if code := from("198.51.100.9:5000"); code != http.StatusNotFound {
		t.Fatalf("another visitor behind the same relay was limited by the first: %d", code)
	}
	// The tip is counted the same way.
	tip := func(visitor string) int {
		r := httptest.NewRequest("GET", "/api/witness/kel/EX/tip?nonce=n", nil)
		r = r.WithContext(relayproto.ContextWithPreamble(r.Context(), relayproto.Preamble{Visitor: visitor}))
		w := httptest.NewRecorder()
		s.handleWitnessKelTip(w, r)
		return w.Code
	}
	if code := tip("203.0.113.7:4002"); code != http.StatusTooManyRequests {
		t.Fatalf("a tip from a visitor past its allowance was not limited: %d", code)
	}
}
