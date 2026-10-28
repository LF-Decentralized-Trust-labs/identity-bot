package server

import (
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/agentbody"
)

// Revoking an AI agent withdraws its grant, ends the machine that speaks for
// it, and is final: changing what it may do afterwards is refused, because it
// would issue it a new grant.
func TestARevokedAIAgentStaysRevoked(t *testing.T) {
	w := newTalkWorld(t)
	bodies := w.s.bodies().ForAgent(w.b.ID)
	if len(bodies) != 1 || bodies[0].State != agentbody.StateActive {
		t.Fatalf("Build server's machine: %+v", bodies)
	}
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/revoke", "")
	if code != http.StatusOK || out["status"] != "revoked" || out["grants_withdrawn"] != float64(1) || out["machines_ended"] != float64(1) {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	if st := w.s.agentStatus(w.b.PairwiseAID); st != "revoked" {
		t.Fatalf("status %s", st)
	}
	if b, _ := w.s.bodies().Get(bodies[0].ID); b.State != agentbody.StateRevoked {
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
	if st := w.s.agentStatus(w.b.PairwiseAID); st != "revoked" {
		t.Fatalf("after a refused change, status %s", st)
	}
	// Shown as revoked, and revoking again is harmless.
	if _, _, raw := w.asOwner(t, "GET", "/api/mcp/agents", ""); !strings.Contains(raw, `"revoked_at"`) {
		t.Fatalf("the list does not say it was revoked: %s", raw)
	}
	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking again: %d %s", code, raw)
	}
	if n := len(governanceRows(t, w, "agent.revoked")); n != 1 {
		t.Fatalf("revocation recorded %d times", n)
	}
	// It can be asked nothing.
	if code, out := w.personSays(t, w.b, "", "are you there?"); code != http.StatusConflict {
		t.Fatalf("a person asked a revoked AI agent: %d %v", code, out)
	}
	// The other AI agent is untouched.
	if st := w.s.agentStatus(w.a.PairwiseAID); st != "active" {
		t.Fatalf("Desk assistant is %s", st)
	}
}
