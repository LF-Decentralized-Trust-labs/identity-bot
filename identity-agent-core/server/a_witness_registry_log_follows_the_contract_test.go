package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// What a witness serves about an issuer's registry logs is the contract's
// shape (SEAM-13 §2, witness/registry-log-vectors.json), not whatever its
// Go types happen to marshal to.

func (w *registryWorld) raw(path string) (int, []byte) {
	w.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, w.base+path, nil)
	proof, _ := witness.InceptionProof(w.kel)
	req.Header.Set(witness.HeaderInception, proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestTheServedRegistryLogHasTheContractsShape(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	rev := w.revoke(reg.RegistrySaid, iss, true)
	if code := w.post(vcpB64(reg), iss.IssRawBytesB64, rev.RevRawBytesB64); code != http.StatusOK {
		t.Fatalf("the issuer's own events were refused: %d", code)
	}
	code, body := w.raw("/api/witness/tel/" + w.c.aid)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if err := witness.CheckRegistryLogAnswerShape(body); err != nil {
		t.Fatalf("the answer is not the contract's shape: %v\n%s", err, body)
	}
	var ans struct {
		AID            string            `json:"aid"`
		RegistryPrefix string            `json:"registry_prefix"`
		Events         []json.RawMessage `json:"events"`
		AnchoredSN     int               `json:"anchored_sn"`
		LatestKelSN    int               `json:"latest_kel_sn"`
	}
	_ = json.Unmarshal(body, &ans)
	if ans.AID != w.c.aid || ans.RegistryPrefix != reg.RegistrySaid || len(ans.Events) != 3 || ans.AnchoredSN != 3 || ans.LatestKelSN != 3 {
		t.Fatalf("wrong content: %+v", ans)
	}
	// Each event is what the issuer published, to the byte, so it verifies
	// under the reader's own KERI library.
	want := []string{vcpB64(reg), iss.IssRawBytesB64, rev.RevRawBytesB64}
	for i, ev := range ans.Events {
		published, _ := base64.StdEncoding.DecodeString(want[i])
		if string(ev) != string(published) {
			t.Errorf("event %d is not as published:\n got %s\nwant %s", i, ev, published)
		}
		if _, err := keri.VerifyTELEvent(ev); err != nil {
			t.Errorf("event %d does not verify: %v", i, err)
		}
	}
	// Nothing in the old record form is left.
	if strings.Contains(string(body), "raw_b64") || strings.Contains(string(body), "anchor_sn") {
		t.Errorf("the answer carries the old record form: %s", body)
	}
}

func TestAnIssuerWithTwoRegistriesIsServedBothAndNamedByTheFirst(t *testing.T) {
	w := newRegistryWorld(t)
	first := w.inceptRegistry(true)
	issA := w.issue(first.RegistrySaid, true)
	second := w.inceptRegistry(true)
	issB := w.issue(second.RegistrySaid, true)
	if code := w.post(vcpB64(first), issA.IssRawBytesB64, vcpB64(second), issB.IssRawBytesB64); code != http.StatusOK {
		t.Fatalf("refused: %d", code)
	}
	_, body := w.raw("/api/witness/tel/" + w.c.aid)
	if err := witness.CheckRegistryLogAnswerShape(body); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	var ans struct {
		RegistryPrefix string   `json:"registry_prefix"`
		Registries     []string `json:"registries"`
	}
	_ = json.Unmarshal(body, &ans)
	if ans.RegistryPrefix != first.RegistrySaid || len(ans.Registries) != 2 || ans.Registries[1] != second.RegistrySaid {
		t.Fatalf("the two registries are not carried: %+v", ans)
	}
	// Anchored at 1, 2, 3 and 4: from 3 on, only the second registry's issuance,
	// and a later registry does not change which one names the answer.
	code, only := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=3", true)
	if code != http.StatusOK || len(only.Events) != 1 || only.RegistryPrefix != first.RegistrySaid {
		t.Fatalf("since_sn=3: %d %+v", code, only)
	}
}

func TestAWitnessWithNoRegistryLogSaysNoTEL(t *testing.T) {
	w := newRegistryWorld(t)
	for _, path := range []string{"/api/witness/tel/" + w.c.aid, "/api/witness/tel/" + w.c.aid + "/head"} {
		code, body := w.raw(path)
		if code != http.StatusNotFound || strings.TrimSpace(string(body)) != `{"error":"no_tel"}` {
			t.Errorf("%s: %d %s; want 404 {\"error\":\"no_tel\"}", path, code, body)
		}
	}
}

func TestTheHeadSaysWhereTheLogIsHeldTo(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	w.inceptRegistry(true) // the witness holds the key log one further, with no registry event for it
	code, body := w.raw("/api/witness/tel/" + w.c.aid + "/head")
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if err := witness.CheckRegistryLogHeadShape(body); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	var head witness.TELHead
	_ = json.Unmarshal(body, &head)
	if head.AnchoredSN != 2 || head.LatestKelSN != 3 || head.EventDigest != iss.IssSaid {
		t.Fatalf("head = %+v; the issuance (%s) is the latest event, anchored at 2, with the key log held through 3", head, iss.IssSaid)
	}
	// And it is answered on the log's terms: not to a stranger.
	req, _ := http.NewRequest(http.MethodGet, w.base+"/api/witness/tel/"+w.c.aid+"/head", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a stranger was given the head: %d", resp.StatusCode)
	}
}

// liarServing serves answer on every registry-log route and counts the asks.
func liarServing(t *testing.T, answer witness.TELAnswer, asked *int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/witness/tel/") {
			http.NotFound(rw, r)
			return
		}
		atomic.AddInt32(asked, 1)
		_ = json.NewEncoder(rw).Encode(answer)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// A witness holding the key log no further than the verifier does, and serving
// an event that key log does not seal, is reported as possible duplicity
// (SEAM-13 §5 T-3), the log and that witness are rejected, and it is not asked
// again.
func TestAnEventTheKeyLogDoesNotSealIsReportedAsPossibleDuplicity(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	rev, err := w.c.eng.RevokeCredential(w.c.name, iss.AcdcSaid, reg.RegistrySaid, iss.IssSaid) // never sealed in the key log
	if err != nil {
		t.Fatal(err)
	}
	_, honest := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	revRaw, _ := base64.StdEncoding.DecodeString(rev.RevRawBytesB64)
	honest.Events = append(honest.Events, json.RawMessage(revRaw))
	var asked int32
	real := w.base
	w.base = liarServing(t, honest, &asked)
	res := w.verifyOutside(iss)
	w.base = real
	if res.Verified || res.Checks["possible_duplicity"] != true {
		t.Fatalf("an unsealed event was not reported as possible duplicity: verified=%v %+v %v", res.Verified, res.Checks, res.Errors)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "possible duplicity") || !strings.Contains(strings.Join(res.Errors, " "), w.bob.witnessKey) {
		t.Errorf("the result does not say which witness and why: %v", res.Errors)
	}
	if issuerVerdict(res, true) != issuerDuplicity {
		t.Errorf("the issuer status is not possible duplicity: %q", issuerVerdict(res, true))
	}
	// The witness is rejected: a second check does not ask it.
	before := atomic.LoadInt32(&asked)
	w.base = liarServing(t, honest, &asked)
	w.verifyOutside(iss) // the pool now points at a new server for the same witness key
	if atomic.LoadInt32(&asked) != before {
		t.Errorf("a witness rejected for serving an unsealed event was asked again")
	}
}

func TestAWitnessAheadOfTheVerifiersKeyLogIsBelievedAfterTheVerifierCatchesUp(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	// The verifier's copy stops before the interaction that seals the issuance;
	// the witness holds it, and the verifier extends its copy from the witness.
	w.kel = w.kel[:2]
	res := w.verifyOutside(iss)
	if !res.Verified {
		t.Fatalf("an issuance sealed beyond the verifier's key log was not proved after the log was caught up: %+v %v", res.Checks, res.Errors)
	}
	if res.Checks["possible_duplicity"] == true {
		t.Fatalf("a witness that is ahead was accused of duplicity: %+v %v", res.Checks, res.Errors)
	}
}
