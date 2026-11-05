package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// presented is what the agent would put in its assertion, as the site reads it.
func (w *aGateWorld) presented(t *testing.T) []interface{} {
	t.Helper()
	held := w.s.loginHandler.HeldCredentials()
	raw, _ := json.Marshal(held)
	var out []interface{}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 1 {
		t.Fatalf("expected the one held credential, got %d (%v)", len(out), err)
	}
	return out
}

func (w *aGateWorld) gate(t *testing.T) (bool, string) {
	t.Helper()
	return w.s.credentialGateSatisfied(context.Background(), w.presented(t), w.holder, w.schema, w.issuer)
}

// A genuine held credential, as the agent presents it, passes the gate. Fails if
// the held body is encoded a second time on its way out.
func TestAGenuineHeldCredentialPassesTheCredentialGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, true)
	if ok, reason := w.gate(t); !ok {
		t.Fatalf("a genuine credential was refused: %s", reason)
	}
}

// The body is sent in one encoding whichever way it was kept.
func TestAHeldBodyIsEncodedOnceWhetherKeptEncodedOrPlain(t *testing.T) {
	const plain = `{"v":"ACDC10JSON"}`
	enc := acdcAsBase64(plain)
	if acdcAsBase64(enc) != enc {
		t.Fatal("an already-encoded body was encoded again")
	}
	if enc == plain || strings.HasPrefix(enc, "{") {
		t.Fatalf("a plain body was not encoded: %q", enc)
	}
}

// The credential's issuee must be the identity signing in.
func TestACredentialIssuedToSomebodyElseIsRefusedAtTheGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, false, true)
	ok, reason := w.gate(t)
	if ok {
		t.Fatal("a credential issued to somebody other than the identity signing in was accepted")
	}
	if !strings.Contains(reason, "subject") {
		t.Fatalf("the refusal does not say the holder is wrong: %q", reason)
	}
}

// The issuer's key log must be one the agent holds.
func TestACredentialWhoseIssuerLogIsNotHeldIsRefusedAtTheGate(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, false)
	ok, reason := w.gate(t)
	if ok {
		t.Fatal("a credential was accepted with no key log for its issuer")
	}
	if !strings.Contains(reason, "issuer KEL not found") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

// A credential issued by the organisation the agent belongs to — its own key
// log, not a contact's — passes the gate. Fails if the own log is read as parsed
// events, which carry no signature, so the engine never reports it verified.
func TestACredentialIssuedByThisAgentsOwnOrganisationPassesTheCredentialGate(t *testing.T) {
	w := aGateWorldHolding(t, true, logHeldAsOwn)
	if ok, reason := w.gate(t); !ok {
		t.Fatalf("a credential issued by the site's own organisation was refused: %s", reason)
	}
}
