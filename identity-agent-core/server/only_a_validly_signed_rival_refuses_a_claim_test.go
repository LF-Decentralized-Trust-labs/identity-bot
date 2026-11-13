package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// What a registered witness hands back as "conflicting" is not believed as
// served. One broken or hostile witness must not be able to refuse an honest
// claim; only a second event the identity really signed at a place it already
// used does. These run the Identity Agent's own claim path (askTheWitnesses)
// against a witness serving a real, signed log.

func TestOnlyAValidlySignedRivalRefusesAClaimInTheCore(t *testing.T) {
	bob := startPeer(t, "bob")
	c := newRotatingController(t, "subject", bob.witnessKey)
	p1, _ := c.signers[1].PublicKey()
	p2, _ := c.signers[2].PublicKey()
	rot, err := c.eng.Rotate(drivers.RotationRequest{Name: c.name, NewPublicKey: p1, NewNextPublicKey: p2})
	if err != nil {
		t.Fatal(err)
	}
	rotRaw, _ := base64.StdEncoding.DecodeString(rot.RawBytesB64)
	rec := func(raw []byte, sig string) map[string]interface{} {
		return map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": sig}
	}
	icpRec := rec(c.icpRaw, c.icpSig)
	rotRec := rec(rotRaw, sign(t, c.signers[1], rotRaw))
	rotEv, _ := keri.ParseEvent(rotRaw)
	ixnAt := func(sn int, prior, tag string, by keri.Signer) map[string]interface{} {
		raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: prior, SN: sn,
			Data: []json.RawMessage{json.RawMessage(`{"d":"E` + tag + `"}`)}})
		if err != nil {
			t.Fatal(err)
		}
		return rec(raw, sign(t, by, raw))
	}
	heldIxn := ixnAt(2, rotEv.SAID, "held", c.signers[1])
	presented := []map[string]interface{}{icpRec, rotRec, heldIxn}

	cases := []struct {
		name        string
		conflicting []map[string]interface{}
		refused     bool
	}{
		{"the held event itself", []map[string]interface{}{heldIxn}, false},
		{"garbage bytes", []map[string]interface{}{rec([]byte("not an event"), "x")}, false},
		{"an empty object", []map[string]interface{}{{}}, false},
		{"a key already rotated away from", []map[string]interface{}{ixnAt(2, rotEv.SAID, "stale", c.signers[0])}, false},
		{"a validly signed rival", []map[string]interface{}{ixnAt(2, rotEv.SAID, "rival", c.signers[1])}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]interface{}{"kel": presented, "conflicting": tc.conflicting})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
			t.Cleanup(srv.Close)
			pointTheBootstrapPoolAt(t, bob.witnessKey, srv.URL)
			got := agentWithNoIdentity(t).askTheWitnesses(c.aid, presented)
			if got.Contradicted != tc.refused {
				t.Fatalf("contradicted = %v, want %v: %+v", got.Contradicted, tc.refused, got)
			}
			if !tc.refused && !got.Corroborated() {
				t.Fatalf("an honest claim was refused over an invalid entry: %+v", got)
			}
		})
	}
}
