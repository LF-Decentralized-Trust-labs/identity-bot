package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/witness"
)

// A verifier's copy of an issuer's key log is only as new as the last time
// anything refreshed it, and nothing on the path that reads a witness's
// registry log does. So a revocation anchored after the verifier's copy must
// not be missed: the verifier catches its copy up from the witnesses first, and
// when it cannot, the credential is "not checked", never "not revoked".

// notVouchedFor is what every one of these must come to when the witnesses
// cannot show the credential is live: not verified, and not reported as
// checked and not revoked.
func notVouchedFor(t *testing.T, res *drivers.DriverVerifyCredentialResponse, what string) {
	t.Helper()
	if res.Verified || res.Checks["not_revoked"] == true {
		t.Fatalf("%s: the credential was vouched for: verified=%v checks=%+v errors=%v", what, res.Verified, res.Checks, res.Errors)
	}
}

// aWorldWhereTheVerifierIsBehind is an issued credential that was then
// revoked, the witness holding the key log through the revocation's seal. The
// verifier's copy of the key log stops at the issuance. The revocation event
// itself is given to the witness only when withRevocation.
func aWorldWhereTheVerifierIsBehind(t *testing.T, withRevocation bool) (*registryWorld, *drivers.DriverIssueCredentialResponse, *drivers.DriverRegistryInceptResponse, *drivers.DriverRevokeCredentialResponse) {
	t.Helper()
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	atIssuance := len(w.kel)
	rev := w.revoke(reg.RegistrySaid, iss, true)
	if withRevocation {
		w.post(rev.RevRawBytesB64)
	}
	w.kel = w.kel[:atIssuance]
	return w, iss, reg, rev
}

func TestARevocationAnchoredAfterTheVerifiersCopyAndWithheldIsNotMissed(t *testing.T) {
	w, iss, _, _ := aWorldWhereTheVerifierIsBehind(t, false)
	notVouchedFor(t, w.verifyOutside(iss), "a witness that leaves out the revocation")
}

func TestAnHonestWitnessServingTheRevocationIsBelievedAfterTheVerifierCatchesUp(t *testing.T) {
	w, iss, _, _ := aWorldWhereTheVerifierIsBehind(t, true)
	res := w.verifyOutside(iss)
	if res.Verified || res.Checks["not_revoked"] != false {
		t.Fatalf("a revocation an honest witness serves was not reported: verified=%v checks=%+v errors=%v", res.Verified, res.Checks, res.Errors)
	}
	if res.Checks["possible_duplicity"] == true {
		t.Fatalf("the honest witness was accused of duplicity: %v", res.Errors)
	}
}

// front stands in front of a witness: it serves the registry log by the given
// function and passes every other request (the key log) to the real witness.
func front(t *testing.T, real string, tel func(rw http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	target, _ := url.Parse(real)
	proxy := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/witness/tel/") && r.Method == http.MethodGet {
			tel(rw, r)
			return
		}
		proxy.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func serveAnswer(rw http.ResponseWriter, ans witness.TELAnswer) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(ans)
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(buf.Bytes())
}

func TestAReplayedEarlierAnswerClaimingToBeCurrentIsNotTakenForLive(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	_, early := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true) // before the revocation
	atIssuance := len(w.kel)
	w.revoke(reg.RegistrySaid, iss, true)
	early.LatestKelSN = len(w.kel) - 1 // claims to be as far as the key log now is
	w.kel = w.kel[:atIssuance]
	real := w.base
	w.base = front(t, real, func(rw http.ResponseWriter, _ *http.Request) { serveAnswer(rw, early) })
	notVouchedFor(t, w.verifyOutside(iss), "a replayed answer")
}

func TestAWitnessClaimingMoreOfTheKeyLogThanItCanShowIsNotTakenForLive(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	_, honest := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	honest.LatestKelSN += 5 // a key log it will not produce
	w.base = front(t, w.base, func(rw http.ResponseWriter, _ *http.Request) { serveAnswer(rw, honest) })
	notVouchedFor(t, w.verifyOutside(iss), "a witness that cannot show the key log it claims")
}

// aStaleAndACurrentWitness is an issuer witnessed by two: the first holds the
// key log, and the registry log, only to the issuance; the second holds all of
// it, the revocation too. The verifier's copy stops at the issuance.
func aStaleAndACurrentWitness(t *testing.T) (*registryWorld, *drivers.DriverIssueCredentialResponse, []witness.BootstrapWitness) {
	t.Helper()
	stale, current := startPeer(t, "stale"), startPeer(t, "current")
	c := newRotatingControllerWitnessedBy(t, "subject", stale.witnessKey, current.witnessKey)
	for _, p := range []*peerAgent{stale, current} {
		p.willWitnessFor(t, c.aid)
		if err := p.takes(t, c.aid, c.icpRaw, c.icpSig); err != nil {
			t.Fatalf("a witness would not take the inception: %v", err)
		}
	}
	w := registryWorldOf(t, current, c)
	staleBase := servedThroughTheRealRouter(t, stale)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	// The stale witness is given everything up to the issuance, and nothing after.
	for _, rec := range w.kel[1:] {
		raw, _ := b64Decode(rec["raw_bytes_b64"].(string))
		if err := stale.takes(t, c.aid, raw, rec["cesr_signature"].(string)); err != nil {
			t.Fatalf("the stale witness would not take a key-log event: %v", err)
		}
	}
	body, _ := json.Marshal(map[string]interface{}{"events": []string{vcpB64(reg), iss.IssRawBytesB64}})
	resp, err := http.Post(staleBase+"/api/witness/tel/"+c.aid, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	atIssuance := len(w.kel)
	rev := w.revoke(reg.RegistrySaid, iss, true)
	w.post(rev.RevRawBytesB64)
	w.kel = w.kel[:atIssuance]
	return w, iss, []witness.BootstrapWitness{
		{AID: "EStale", WitnessKey: stale.witnessKey, URL: staleBase, Operator: "tests"},
		{AID: "ECurrent", WitnessKey: current.witnessKey, URL: w.base, Operator: "tests"},
	}
}

func TestAStaleWitnessAskedFirstDoesNotHideARevocationAnotherWitnessHolds(t *testing.T) {
	w, iss, pool := aStaleAndACurrentWitness(t)
	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness { return pool }
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })
	res := w.verifyWithThePool(iss)
	if res.Verified || res.Checks["not_revoked"] != false {
		t.Fatalf("a stale witness hid the revocation a current one holds: verified=%v checks=%+v errors=%v", res.Verified, res.Checks, res.Errors)
	}
	if res.Checks["possible_duplicity"] == true {
		t.Fatalf("an honest stale witness was accused of duplicity: %v", res.Errors)
	}
}
