package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"identity-agent-core/drivers"
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
