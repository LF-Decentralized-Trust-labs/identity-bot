package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// POST /witness/tel/{aid} is open to anybody, so its answer must not depend on
// whether this witness holds a log for that identity, as the read routes do not
// (witness.MayRead).
func TestSubmittingRegistryEventsAnswersTheSameWhetherOrNotTheIdentityIsWitnessed(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, false) // the witness does not hold the interaction that seals it

	submit := func(aid string, events ...string) (int, string) {
		body, _ := json.Marshal(map[string]interface{}{"events": events})
		resp, err := http.Post(w.base+"/api/witness/tel/"+aid, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	other := newRotatingController(t, "other", w.bob.witnessKey) // never taken by this witness
	other.eng.SetEventSignature(func(_, _ string, raw []byte) (string, error) { return sign(t, other.signers[0], raw), nil })
	otherReg, err := other.eng.InceptRegistry("other")
	if err != nil {
		t.Fatal(err)
	}

	heldCode, heldBody := submit(w.c.aid, vcpB64(reg), iss.IssRawBytesB64) // witnessed, events not sealed by what it holds
	unheldCode, unheldBody := submit(other.aid, otherReg.VcpJsonB64)       // not witnessed
	if heldCode != unheldCode || heldBody != unheldBody {
		t.Fatalf("a witnessed identity got %d %q and an unwitnessed one %d %q: the route says who is witnessed", heldCode, heldBody, unheldCode, unheldBody)
	}
	if heldCode == http.StatusOK {
		t.Fatalf("events the key log does not seal were stored: %d", heldCode)
	}
}
