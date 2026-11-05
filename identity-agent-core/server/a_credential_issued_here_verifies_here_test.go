package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A credential this core issues through /credential/issue carries its own proof
// of issuance: the interaction sealing it is in the issuer's key log, so the
// verify route, reading that log, verifies it. Fails if the issuing path does
// not anchor the credential, or the verify route does not accept the anchor.
func TestACredentialIssuedThroughTheIssueRouteVerifiesOnTheVerifyRoute(t *testing.T) {
	c := newTwoCores(t)
	d := c.device
	rec := httptest.NewRecorder()
	d.router.ServeHTTP(rec, local("POST", "/api/credential/issue",
		`{"claims":{"role":"engineer"},"schema_said":"EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issuing answered %d %s", rec.Code, rec.Body.String())
	}
	var issued map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	w := &aGateWorld{s: d, acdc: issued["acdc_json_b64"].(string)}
	out := w.post(t, d.handleVerifyCredential, map[string]interface{}{"acdc_json": w.acdc})
	if out["verified"] != true || out["issuer_status"] != issuerChecked {
		t.Fatalf("a credential this core issued did not verify here: %v", out)
	}
	if !strings.Contains(rec.Body.String(), "ixn_said") {
		t.Fatalf("the issue reply carries no anchor: %s", rec.Body.String())
	}
}
