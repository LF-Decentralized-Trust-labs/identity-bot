package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The credential-verify and chain-verify routes read the issuer's key log the
// way the gate does: whole, with the bytes and signatures it was verified by.
// Each test fails if its route hands the engine the log stripped of them.

func (w *aGateWorld) post(t *testing.T, h http.HandlerFunc, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (w *aGateWorld) verifyRoute(t *testing.T) map[string]interface{} {
	return w.post(t, w.s.handleVerifyCredential, map[string]interface{}{"acdc_json": w.acdc})
}

func (w *aGateWorld) chainRoute(t *testing.T) map[string]interface{} {
	return w.post(t, w.s.handleVerifyCredentialChain, map[string]interface{}{"acdc_json_b64": w.acdc})
}

func TestAGenuineCredentialVerifiesOnTheCredentialVerifyRoute(t *testing.T) {
	out := aGateWorldHolding(t, true, logHeldAsContact).verifyRoute(t)
	if out["verified"] != true || out["issuer_status"] != issuerChecked {
		t.Fatalf("a genuine credential from an issuer whose log is held was not verified: %v", out)
	}
}

func TestAGenuineCredentialVerifiesOnTheChainVerifyRoute(t *testing.T) {
	out := aGateWorldHolding(t, true, logHeldAsContact).chainRoute(t)
	if out["valid"] != true {
		t.Fatalf("a genuine credential from an issuer whose log is held was not valid: %v", out)
	}
}

// The organisation's own log is read the way a contact's is. Fails if the own
// log is given as parsed events, which carry no signature to check.
func TestACredentialFromThisAgentsOwnIssuerVerifiesOnBothRoutes(t *testing.T) {
	w := aGateWorldHolding(t, true, logHeldAsOwn)
	if out := w.verifyRoute(t); out["verified"] != true {
		t.Fatalf("a credential from the agent's own issuer was not verified: %v", out)
	}
	if out := w.chainRoute(t); out["valid"] != true {
		t.Fatalf("a credential from the agent's own issuer was not valid: %v", out)
	}
}

// An issuer nobody here has a log for cannot be checked, so the credential is
// not verified, and the reply says "not checked" rather than failing or passing.
// Fails if a credential with no issuer log is passed on the engine's word.
func TestACredentialWhoseIssuerCannotBeCheckedIsNeverVerified(t *testing.T) {
	w := aGateWorldHolding(t, true, logNotHeld)
	out := w.verifyRoute(t)
	if out["verified"] == true {
		t.Fatalf("a credential from an issuer that could not be checked was verified: %v", out)
	}
	if s, _ := out["issuer_status"].(string); !strings.HasPrefix(s, "not checked: ") {
		t.Fatalf("the reply does not say the issuer was not checked: %v", out)
	}
	chain := w.chainRoute(t)
	if chain["valid"] == true {
		t.Fatalf("a credential from an issuer that could not be checked was valid on the chain route: %v", chain)
	}
	steps, _ := chain["chain"].([]interface{})
	step, _ := steps[0].(map[string]interface{})
	if s, _ := step["issuer_status"].(string); !strings.HasPrefix(s, "not checked: ") {
		t.Fatalf("the chain step does not say the issuer was not checked: %v", step)
	}
}

// A credential is verified only with proof its issuer issued it. Each forgery
// names an issuer whose log this agent holds, so its key log checks out; each
// test fails if the proof of issuance is not required.
var forgeries = map[string]howIssued{
	"no registry":                          forgedWithNoRegistry,
	"a registry the issuer never anchored": forgedInIssuersRegistry,
	"a registry and no log held":           forgedWithNoLogHeld,
}

func TestAForgeryNamingAKnownIssuerIsNotVerifiedOnTheRoutes(t *testing.T) {
	for name, how := range forgeries {
		for _, held := range []issuerLogHeld{logHeldAsContact, logHeldAsOwn} {
			w := aGateWorldWhere(t, true, held, how)
			out := w.verifyRoute(t)
			if out["verified"] == true {
				t.Fatalf("%s: a forgery was verified: %v", name, out)
			}
			if out["issuer_status"] != "not checked: no proof of issuance" {
				t.Fatalf("%s: the reply does not say there is no proof of issuance: %v", name, out)
			}
			chain := w.chainRoute(t)
			if chain["valid"] == true {
				t.Fatalf("%s: a forgery was valid on the chain route: %v", name, chain)
			}
			steps, _ := chain["chain"].([]interface{})
			step, _ := steps[0].(map[string]interface{})
			if step["issuer_status"] != "not checked: no proof of issuance" {
				t.Fatalf("%s: the chain step does not say there is no proof of issuance: %v", name, step)
			}
		}
	}
}
