package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// A witness serves the registry log of an identity it witnesses, and a
// verifier that does not hold that log reads it from there. These run a real
// witness behind its real router and a real issuer's engine.

// registryWorld is an issuer witnessed by bob, whose registry events and key
// log events are made by its real engine.
type registryWorld struct {
	t      *testing.T
	bob    *peerAgent
	c      *rotatingController
	base   string
	kel    []map[string]interface{} // the issuer's key log as a verifier holds it
	kelSN  int
	schema string
}

func newRegistryWorld(t *testing.T) *registryWorld {
	t.Helper()
	bob, c := witnessedController(t)
	w := &registryWorld{t: t, bob: bob, c: c, base: servedThroughTheRealRouter(t, bob)}
	c.eng.SetEventSignature(func(_, _ string, raw []byte) (string, error) { return sign(t, c.signers[0], raw), nil })
	w.schema, _ = keri.Blake3SAID([]byte("a test schema"))
	w.addKel(c.icpRaw, c.icpSig)
	return w
}

func (w *registryWorld) addKel(raw []byte, sig string) {
	w.kel = append(w.kel, map[string]interface{}{
		"event_json": string(raw), "raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": sig,
	})
	w.kelSN = len(w.kel) - 1
}

// anchor appends the issuer's interaction event to its key log and, when
// toWitness, hands it to the witness.
func (w *registryWorld) anchor(ixnB64 string, toWitness bool) {
	w.t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(ixnB64)
	sig := sign(w.t, w.c.signers[0], raw)
	w.addKel(raw, sig)
	if toWitness {
		if err := w.bob.takes(w.t, w.c.aid, raw, sig); err != nil {
			w.t.Fatalf("the witness would not take the issuer's interaction: %v", err)
		}
	}
}

func (w *registryWorld) post(events ...string) int {
	w.t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"events": events})
	resp, err := http.Post(w.base+"/api/witness/tel/"+w.c.aid, "application/json", bytes.NewReader(body))
	if err != nil {
		w.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (w *registryWorld) get(path string, withInception bool) (int, witness.TELAnswer) {
	w.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, w.base+path, nil)
	if withInception {
		proof, _ := witness.InceptionProof(w.kel)
		req.Header.Set(witness.HeaderInception, proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	var ans witness.TELAnswer
	_ = json.NewDecoder(resp.Body).Decode(&ans)
	return resp.StatusCode, ans
}

func (w *registryWorld) inceptRegistry(toWitness bool) *drivers.DriverRegistryInceptResponse {
	w.t.Helper()
	reg, err := w.c.eng.InceptRegistry(w.c.name)
	if err != nil {
		w.t.Fatal(err)
	}
	w.anchor(reg.IxnRawBytesB64, toWitness)
	return reg
}

func (w *registryWorld) issue(registry string, toWitness bool) *drivers.DriverIssueCredentialResponse {
	w.t.Helper()
	iss, err := w.c.eng.IssueCredentialInRegistry(w.c.name, map[string]interface{}{"role": "engineer"},
		w.schema, "EHolder000000000000000000000000000000000000", nil, registry)
	if err != nil {
		w.t.Fatal(err)
	}
	w.anchor(iss.IxnRawBytesB64, toWitness)
	return iss
}

func (w *registryWorld) revoke(registry string, iss *drivers.DriverIssueCredentialResponse, toWitness bool) *drivers.DriverRevokeCredentialResponse {
	w.t.Helper()
	rev, err := w.c.eng.RevokeCredential(w.c.name, iss.AcdcSaid, registry, iss.IssSaid)
	if err != nil {
		w.t.Fatal(err)
	}
	w.anchor(rev.IxnRawBytesB64, toWitness)
	return rev
}

func vcpB64(r *drivers.DriverRegistryInceptResponse) string { return r.VcpJsonB64 }

// verifyOutside is a verifier that holds the issuer's key log and nothing of
// the registry, checking the credential with what the witnesses give it.
func (w *registryWorld) verifyOutside(iss *drivers.DriverIssueCredentialResponse) *drivers.DriverVerifyCredentialResponse {
	w.t.Helper()
	pointTheBootstrapPoolAt(w.t, w.bob.witnessKey, w.base)
	s := agentWithNoIdentity(w.t)
	res, err := keriengine.New().VerifyCredential(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:          iss.AcdcJsonB64,
		IssuerKelEvents:   w.kel,
		RegistryEventsB64: s.issuanceLogForVerification(iss.AcdcBody, w.kel),
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

func TestAWitnessServesAnIssuersWholeRegistryLogRangedBySince(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	if code := w.post(vcpB64(reg), iss.IssRawBytesB64); code != http.StatusOK {
		t.Fatalf("the issuer's own events were refused: %d", code)
	}
	code, all := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	if code != http.StatusOK || len(all.Events) != 2 {
		t.Fatalf("the whole log was not served: %d %+v", code, all)
	}
	if all.AnchoredSN != 2 {
		t.Errorf("anchored_sn = %d, but the witness holds the issuer's key log through 2", all.AnchoredSN)
	}
	// vcp is sealed at 1, iss at 2: from 1 on, only the issuance.
	_, part := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=1", true)
	if len(part.Events) != 1 || part.Events[0].Ilk != "iss" {
		t.Fatalf("since_sn=1 did not leave out the registry inception: %+v", part.Events)
	}
	_, none := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=2", true)
	if len(none.Events) != 0 {
		t.Fatalf("since_sn=2 served events anchored at or before it: %+v", none.Events)
	}
}

func TestAWitnessKeepsNoEventTheIssuersKeyLogDoesNotSeal(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, false) // the witness never got the interaction that seals it
	if code := w.post(vcpB64(reg), iss.IssRawBytesB64); code == http.StatusOK {
		t.Fatal("an issuance the witness's key log does not seal was stored")
	}
	_, ans := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	if len(ans.Events) != 0 {
		t.Fatalf("a rejected batch left events behind: %+v", ans.Events)
	}
}

func TestAWitnessKeepsNoRegistryTheIssuerDidNotFound(t *testing.T) {
	w := newRegistryWorld(t)
	other := newRotatingController(t, "other", w.bob.witnessKey)
	other.eng.SetEventSignature(func(_, _ string, raw []byte) (string, error) { return sign(t, other.signers[0], raw), nil })
	reg, err := other.eng.InceptRegistry("other")
	if err != nil {
		t.Fatal(err)
	}
	if code := w.post(reg.VcpJsonB64); code == http.StatusOK {
		t.Fatal("another identity's registry was stored under this issuer")
	}
}

func TestARegistryLogIsAnsweredOnlyToWhoCanShowTheInception(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	w.post(vcpB64(reg))
	if code, _ := w.get("/api/witness/tel/"+w.c.aid, false); code != http.StatusNotFound {
		t.Errorf("a stranger was served the log: %d", code)
	}
	// And it cannot be asked for by credential or by registry.
	if code, _ := w.get("/api/witness/tel/"+w.c.aid+"/"+reg.RegistrySaid, true); code == http.StatusOK {
		t.Errorf("a registry-level read exists: %d", code)
	}
}

func TestAnOutsideCredentialVerifiesFromTheWitnessesLog(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	res := w.verifyOutside(iss)
	if !res.Verified || res.Checks["issuance_proved"] != true || res.Checks["not_revoked"] != true {
		t.Fatalf("a genuine outside credential did not verify: %+v %v", res.Checks, res.Errors)
	}
}

func TestAnOutsideCredentialIsNotProvedWhenNoWitnessHoldsItsLog(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true) // the issuer never gave the witness the events
	res := w.verifyOutside(iss)
	if res.Verified || res.Checks["issuance_proved"] == true {
		t.Fatalf("a credential nothing proved verified: %+v", res.Checks)
	}
}

func TestARevokedOutsideCredentialIsRefused(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	rev := w.revoke(reg.RegistrySaid, iss, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64, rev.RevRawBytesB64)
	res := w.verifyOutside(iss)
	if res.Verified || res.Checks["not_revoked"] != false {
		t.Fatalf("a revoked outside credential was accepted: %+v %v", res.Checks, res.Errors)
	}
}

func TestARevocationKeptBackIsNotMistakenForALiveCredential(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.revoke(reg.RegistrySaid, iss, true) // sealed in the key log, but its event never given
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	res := w.verifyOutside(iss)
	if res.Verified {
		t.Fatalf("a credential whose revocation the key log seals but the witness left out verified: %+v", res.Checks)
	}
}

func TestAnAnswerBehindTheKeyLogIsNotBelieved(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, false) // witness holds the key log only to 1
	w.post(vcpB64(reg))
	res := w.verifyOutside(iss)
	if res.Verified {
		t.Fatalf("an answer from a witness behind the issuer's key log proved an issuance: %+v", res.Checks)
	}
}

func TestAWitnessCannotMakeUpARevocation(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	// A revocation of a live credential, made by the issuer's engine but never
	// sealed in the key log the verifier holds, served by a witness that lies.
	rev, err := w.c.eng.RevokeCredential(w.c.name, iss.AcdcSaid, reg.RegistrySaid, iss.IssSaid)
	if err != nil {
		t.Fatal(err)
	}
	real := w.base
	_, honest := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	honest.Events = append(honest.Events, witness.TELEvent{RawB64: rev.RevRawBytesB64})
	liar := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/witness/tel/") {
			http.NotFound(rw, r)
			return
		}
		_ = json.NewEncoder(rw).Encode(honest)
	}))
	defer liar.Close()
	w.base = liar.URL
	res := w.verifyOutside(iss)
	w.base = real
	if res.Verified || res.Checks["not_revoked"] == false && res.Checks["issuance_proved"] != true {
		t.Logf("checks: %+v", res.Checks)
	}
	// The invented revocation is not sealed, so the whole answer is refused and
	// the credential is not proved from it; it must not be reported revoked.
	if res.Checks["not_revoked"] == false {
		t.Fatalf("a revocation no key log seals was believed: %+v", res.Checks)
	}
}

func TestAnAnswerFromAWitnessBehindTheVerifiersKeyLogIsNotBelieved(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	// The verifier's copy of the key log has moved on (a later event the witness
	// has not been given), so the witness's answer may be missing what came after.
	w.inceptRegistry(false)
	res := w.verifyOutside(iss)
	if res.Verified {
		t.Fatalf("an answer from a witness behind the key log the verifier holds proved an issuance: %+v", res.Checks)
	}
}
