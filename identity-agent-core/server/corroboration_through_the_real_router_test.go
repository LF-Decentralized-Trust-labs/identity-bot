package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/witness"
)

// The withheld-rotation cross-check reads a witness as a verifier that is
// neither the identity nor its delegator. These put a real witness behind its
// real router; a stand-in that answers everyone hid that the read was refused.

func pointTheBootstrapPoolAt(t *testing.T, key, url string) {
	t.Helper()
	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness {
		return []witness.BootstrapWitness{{AID: "EWitness", WitnessKey: key, URL: url, Operator: "tests"}}
	}
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })
}

func presentedInception(t *testing.T, c *rotatingController) []map[string]interface{} {
	t.Helper()
	var icp map[string]interface{}
	if err := json.Unmarshal(c.icpRaw, &icp); err != nil {
		t.Fatal(err)
	}
	return []map[string]interface{}{icp}
}

func TestAVerifierCorroboratesAWholeHistoryThroughARealWitness(t *testing.T) {
	bob, c := witnessedController(t)
	pointTheBootstrapPoolAt(t, bob.witnessKey, servedThroughTheRealRouter(t, bob))
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, presentedInception(t, c))
	if got.Asked != 1 || !got.Corroborated() {
		t.Fatalf("a real witness holding exactly this history did not corroborate it: %+v", got)
	}
}

func TestAWithheldRotationIsCaughtThroughARealWitness(t *testing.T) {
	bob, c := witnessedController(t)
	p1, _ := c.signers[1].PublicKey()
	p2, _ := c.signers[2].PublicKey()
	rot, err := c.eng.Rotate(drivers.RotationRequest{Name: c.name, NewPublicKey: p1, NewNextPublicKey: p2})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(rot.RawBytesB64)
	sig := sign(t, c.signers[1], raw)
	if err := bob.takes(t, c.aid, raw, sig); err != nil {
		t.Fatalf("the witness would not take the controller's rotation: %v", err)
	}
	pointTheBootstrapPoolAt(t, bob.witnessKey, servedThroughTheRealRouter(t, bob))
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, presentedInception(t, c))
	if got.Asked != 1 || !got.Contradicted {
		t.Fatalf("the rotation the claim left out was not caught: %+v", got)
	}
}

func TestAnInceptionThatIsNotTheOneHeldOpensNothing(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)
	other := newRotatingController(t, "other", bob.witnessKey)
	proof, _ := witness.InceptionProof(presentedInception(t, other))
	req, _ := http.NewRequest(http.MethodGet, base+"/api/witness/kel/"+c.aid, nil)
	req.Header.Set(witness.HeaderInception, proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another log's inception opened this one: %d", resp.StatusCode)
	}
}

func TestASignedReadCannotBeReplayedToAnotherWitness(t *testing.T) {
	bob, c := witnessedController(t)
	base := servedThroughTheRealRouter(t, bob)
	target := base + "/api/witness/kel/" + c.aid
	resp := c.signedGet(t, target, c.aid, c.signers[0], time.Now())
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the signed read was refused at the witness it was made for: %d", resp.StatusCode)
	}
	// The same headers, sent under another host name for the same witness.
	srv := httptest.NewServer(bob.core.buildRouter())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/witness/kel/"+c.aid, nil)
	req.Host = "another-witness.example"
	for _, h := range []string{witness.HeaderReader, witness.HeaderReadStamp, witness.HeaderReadSignature} {
		req.Header.Set(h, resp.Request.Header.Get(h))
	}
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Errorf("a read signed for one witness was accepted by another: %d", r2.StatusCode)
	}
}
