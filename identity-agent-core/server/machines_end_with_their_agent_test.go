package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmachine"
)

// machineFor has the provider make a machine for an AI agent up to the point
// where it asks to become the body: the request, its binding and the
// enrolment string the provider was given.
func machineFor(t *testing.T, w *talkWorld, provider *agenthost.Host, providerBody, agentID string) (id, bid, enrolment string) {
	t.Helper()
	base := "/api/mcp/agents/" + agentID
	if code, _, raw := w.asOwner(t, "PUT", base+"/machine", `{"provides":["toolchain"]}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	code, out, raw := w.asOwner(t, "POST", base+"/machine-requests", `{"provider":"`+providerBody+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("asking for a machine: %d %s", code, raw)
	}
	id = out["id"].(string)
	body, _ := json.Marshal(map[string]any{"state": agentmachine.StateMaking})
	if code, b, _ := provider.Call("POST", "/api/agent-host/machine-requests/"+id, body); code != http.StatusOK {
		t.Fatalf("making: %d %s", code, b)
	}
	code, b, err := provider.Call("POST", "/api/agent-host/machine-requests/"+id+"/enrolment", []byte("{}"))
	if err != nil || code != http.StatusCreated {
		t.Fatalf("enrolment: %d %s %v", code, b, err)
	}
	var en struct {
		Enrolment string `json:"enrolment"`
	}
	_ = json.Unmarshal(b, &en)
	e, _ := agentbody.ParseEnrolment(en.Enrolment)
	e.URL = w.srv.URL
	enrolment, _ = e.Encode()
	return id, "", enrolment
}

// enrolGuest has a new machine ask with the string, and the provider report
// its words; it returns the binding.
func enrolGuest(t *testing.T, w *talkWorld, provider *agenthost.Host, agentID, id, enrolment string) string {
	t.Helper()
	guest := newTestMachine(t)
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: guest, Hardware: true, PollEvery: 20 * time.Millisecond}
	go func() { _, _ = h.Enrol(enrolment, "vm", 3*time.Second) }()
	host, _, _ := agentbody.Identity(guest)
	var bid string
	waitFor(t, "the machine to ask", func() bool {
		for _, b := range w.s.bodies().ForAgent(agentID) {
			if b.Host == host && b.State == agentbody.StatePending {
				bid = b.ID
			}
		}
		return bid != ""
	})
	body, _ := json.Marshal(map[string]any{"state": agentmachine.StateEnrolling, "words": agentbody.Words(host)})
	if code, b, _ := provider.Call("POST", "/api/agent-host/machine-requests/"+id, body); code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", code, b)
	}
	return bid
}

func providerOf(t *testing.T, w *talkWorld, makerID string, h *agenthost.Host) string {
	t.Helper()
	if _, _, err := h.Call("GET", "/api/agent-host/machine-requests?offers=toolchain", nil); err != nil {
		t.Fatal(err)
	}
	return w.s.bodies().ForAgent(makerID)[0].ID
}

// Revoking an AI agent destroys the machines made for it: its body ends, its
// body credential is withdrawn, and its provider is told to destroy the
// machine, at once rather than at the next sweep.
func TestRevokingAnAIAgentDestroysItsMachines(t *testing.T) {
	w, maker, providerHost := machineWorld(t)
	pb := providerOf(t, w, maker.ID, providerHost)
	id, _, enrolment := machineFor(t, w, providerHost, pb, w.b.ID)
	bid := enrolGuest(t, w, providerHost, w.b.ID, id, enrolment)
	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/bodies/"+bid+"/approve", ""); code != http.StatusOK {
		t.Fatalf("approving: %d %s", code, raw)
	}
	if j, _ := w.s.machines().Get(id); j.State != agentmachine.StateReady {
		t.Fatalf("before revoking, the request is %s", j.State)
	}
	grant := w.s.findCapabilityGrant(w.b.PairwiseAID)
	if grant == nil {
		t.Fatal("no grant")
	}
	if code, _, raw := w.asOwner(t, "POST", "/api/credentials/"+grant.SAID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	if j, _ := w.s.machines().Get(id); j.State != agentmachine.StateRemoving {
		t.Fatalf("after revoking the AI agent, its machine request is %s", j.State)
	}
	b, _ := w.s.bodies().Get(bid)
	if b.State != agentbody.StateRevoked {
		t.Fatalf("after revoking the AI agent, its machine's body is %s", b.State)
	}
	if rec, _ := w.s.DataStore.GetCredential(b.CredentialSAID); rec == nil || rec.Status != "revoked" {
		t.Fatalf("the body credential is %+v", rec)
	}
	// The provider is given it to destroy.
	code, raw, _ := providerHost.Call("GET", "/api/agent-host/machine-requests", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), id) || !strings.Contains(string(raw), agentmachine.StateRemoving) {
		t.Fatalf("the provider's work: %d %s", code, raw)
	}
	if n := len(governanceRows(t, w, "agent.machine.removing")); n != 1 {
		t.Fatalf("%d machines were ended", n)
	}
}

// A machine nobody approved before its enrolment window ran out is destroyed
// by the sweep, and so is one whose enrolment string ran out before it asked.
// Cancelling a request voids the enrolment string it was given, so a machine
// cannot use it afterwards.
func TestAMachineNotApprovedInTimeIsDestroyed(t *testing.T) {
	w, maker, providerHost := machineWorld(t)
	pb := providerOf(t, w, maker.ID, providerHost)

	// Asked, never approved: its window runs out.
	id, _, enrolment := machineFor(t, w, providerHost, pb, w.b.ID)
	bid := enrolGuest(t, w, providerHost, w.b.ID, id, enrolment)
	backdate(t, filepath.Join(w.s.DataDir, "agent_bodies.json"), "bindings", "id", bid, "pending_until", time.Now().Add(-time.Second))
	w.s.endMachinesNoLongerWanted("test")
	if j, _ := w.s.machines().Get(id); j.State != agentmachine.StateRemoving {
		t.Fatalf("a machine nobody approved in time is %s", j.State)
	}
	if b, _ := w.s.bodies().Get(bid); b.State != agentbody.StateExpired {
		t.Fatalf("its body is %s", b.State)
	}

	// Given a string, and never asked: it runs out.
	id2, _, _ := machineFor(t, w, providerHost, pb, w.b.ID)
	backdate(t, filepath.Join(w.s.DataDir, "agent_machines.json"), "jobs", "id", id2, "enrolment_given_at",
		time.Now().Add(-agentbody.EnrolmentWindow-2*time.Minute))
	w.s.endMachinesNoLongerWanted("test")
	if j, _ := w.s.machines().Get(id2); j.State != agentmachine.StateRemoving {
		t.Fatalf("a machine that never asked in time is %s", j.State)
	}

	// Cancelled after the string was given: the string no longer works.
	id3, _, str := machineFor(t, w, providerHost, pb, w.b.ID)
	if code, _, raw := w.asOwner(t, "DELETE", "/api/mcp/agents/"+w.b.ID+"/machine-requests/"+id3, ""); code != http.StatusOK {
		t.Fatalf("cancelling: %d %s", code, raw)
	}
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: newTestMachine(t), Hardware: true, PollEvery: 20 * time.Millisecond}
	if _, err := h.Enrol(str, "vm", time.Second); err == nil {
		t.Fatal("a machine enrolled with the string of a cancelled request")
	}

	if n := len(governanceRows(t, w, "agent.machine.removing")); n != 2 {
		t.Fatalf("%d machines were ended by the sweep, not 2", n)
	}
}

// backdate sets one time field of one entry in a store's JSON file, standing
// in for the clock having moved on.
func backdate(t *testing.T, path, list, key, id, field string, when time.Time) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string][]map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range f[list] {
		if e[key] == id {
			e[field] = when.UTC().Format(time.RFC3339Nano)
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s %s in %s", list, id, path)
	}
	out, _ := json.Marshal(f)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
