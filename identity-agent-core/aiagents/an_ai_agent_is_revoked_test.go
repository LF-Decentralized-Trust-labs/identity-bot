package aiagents

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
)

// Revoking an AI agent withdraws its grant, ends the machine that speaks for
// it, and is final: changing what it may do afterwards is refused, because it
// would issue it a new grant.
func TestARevokedAIAgentStaysRevoked(t *testing.T) {
	w := newTalkWorld(t)
	bodies := of(w.s).bodies().ForAgent(w.b.ID)
	if len(bodies) != 1 || bodies[0].State != agentbody.StateActive {
		t.Fatalf("Build server's machine: %+v", bodies)
	}
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/revoke", "")
	if code != http.StatusOK || out["status"] != "revoked" || out["grants_withdrawn"] != float64(1) || out["machines_ended"] != float64(1) {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	if st := of(w.s).agentStatus(w.b.PairwiseAID); st != "revoked" {
		t.Fatalf("status %s", st)
	}
	if b, _ := of(w.s).bodies().Get(bodies[0].ID); b.State != agentbody.StateRevoked {
		t.Fatalf("its machine is %s", b.State)
	}
	if code, b, _ := w.hostB.Call("GET", "/api/agent-host/agents", nil); code == http.StatusOK {
		t.Fatalf("its machine is still admitted: %s", b)
	}
	// Final: no new grant by changing what it may do.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/capabilities", `{"capabilities":["`+capabilityMessageAgent+`"]}`); code != http.StatusConflict ||
		!strings.Contains(raw, "revoked") {
		t.Fatalf("re-granting a revoked AI agent: %d %s", code, raw)
	}
	if st := of(w.s).agentStatus(w.b.PairwiseAID); st != "revoked" {
		t.Fatalf("after a refused change, status %s", st)
	}
	// Shown as revoked, and revoking again is harmless.
	if _, _, raw := w.asOwner(t, "GET", "/api/mcp/agents", ""); !strings.Contains(raw, `"revoked_at"`) || !strings.Contains(raw, `"revoked_by":"owner"`) {
		t.Fatalf("the list does not say it was revoked: %s", raw)
	}
	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking again: %d %s", code, raw)
	}
	if n := len(governanceRows(t, w, "agent.revoked")); n != 1 {
		t.Fatalf("revocation recorded %d times", n)
	}
	// Nothing that would act for it, configure it or give it a machine works.
	for _, c := range []struct{ method, path, body string }{
		{"PATCH", "/api/mcp/agents/" + w.b.ID, `{"role":"back again"}`},
		{"PUT", "/api/mcp/agents/" + w.b.ID + "/brain-sign-in", `{"kind":"api_key","provider":"anthropic","secret":"sk-ant-x"}`},
		{"POST", "/api/mcp/agents/" + w.b.ID + "/body-enrolment", ""},
	} {
		if code, _, raw := w.asOwner(t, c.method, c.path, c.body); code != http.StatusConflict {
			t.Fatalf("%s %s on a revoked AI agent: %d %s", c.method, c.path, code, raw)
		}
	}
	// It can be asked nothing.
	if code, out := w.personSays(t, w.b, "", "are you there?"); code != http.StatusConflict {
		t.Fatalf("a person asked a revoked AI agent: %d %v", code, out)
	}
	// The other AI agent is untouched.
	if st := of(w.s).agentStatus(w.a.PairwiseAID); st != "active" {
		t.Fatalf("Desk assistant is %s", st)
	}
}

// The mark alone refuses the AI agent everything, even while a grant
// credential is still usable: the scopes it is resolved with are empty.
func TestTheMarkAloneRefusesARevokedAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	if _, _, err := of(w.s).revokedAIAgents().Mark(w.b.ID, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if g := hostOf(w.s).FindCapabilityGrant(w.b.PairwiseAID); g == nil {
		t.Fatal("the grant should still be usable for this test")
	}
	cc, ok := of(w.s).ResolveAgentCaller(w.b.PairwiseAID)
	if !ok || len(cc.Scopes) != 0 || cc.NoScopesBecause != "this AI agent was revoked" {
		t.Fatalf("a marked AI agent resolved as %+v", cc)
	}
	if code, b, _ := w.hostB.Call("POST", "/api/agent-host/brain-sign-in", []byte("{}")); code == http.StatusOK {
		t.Fatalf("a marked AI agent's machine was lent its sign-in: %s", b)
	}
}
