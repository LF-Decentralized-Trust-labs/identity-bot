package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmachine"
	"identity-agent-core/asset"
)

// machineWorld is a talkWorld with a third AI agent, "Machine maker", whose
// grant lets it make machines, enrolled with a body of its own.
func machineWorld(t *testing.T) (*talkWorld, *asset.Asset, *agenthost.Host) {
	t.Helper()
	w := newTalkWorld(t)
	maker := w.provision(t, "Machine maker", []string{capabilityProvideMachines})
	h, _ := w.enrolBody(t, maker)
	return w, maker, h
}

// fakeMaker is a stand-in for the program a provider makes machines with. It
// writes down every call; "enrol" hands the enrolment string to the test and
// waits for it to say which six words the new machine shows.
func fakeMaker(t *testing.T) (path, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	dir = t.TempDir()
	path = filepath.Join(dir, "make-machines")
	script := "#!/bin/sh\necho \"$@ for=$AGENT_MACHINE_FOR\" >> " + dir + "/calls\n" +
		"if [ \"$1\" = enrol ]; then\n" +
		"  cat > " + dir + "/enrolment.tmp && mv " + dir + "/enrolment.tmp " + dir + "/enrolment\n" +
		"  i=0; while [ ! -f " + dir + "/words ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done\n" +
		"  echo \"words: $(cat " + dir + "/words)\"\n" +
		"fi\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, dir
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (w *talkWorld) machineRequest(t *testing.T, agentID string) agentmachine.Job {
	t.Helper()
	js := w.s.machines().ForAgent(agentID)
	if len(js) == 0 {
		t.Fatal("no machine request")
	}
	return js[0]
}

// The whole path: a person says what an AI agent's machine must provide, sees
// which providers fit, asks one for a machine; the provider makes it, gets it
// a one-time enrolment string, and reports its six words; the person approves
// them, and the machine is the AI agent's body. Removing that machine ends the
// body and has its provider destroy it.
func TestANewMachineIsMadeEnrolledApprovedAndDestroyed(t *testing.T) {
	w, _, providerHost := machineWorld(t)
	program, dir := fakeMaker(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = providerHost.Provide(ctx, agenthost.ProvideOptions{Program: program, Offers: []string{"toolchain", "screen"}})
	}()
	t.Cleanup(func() { cancel(); <-done })

	designer := w.provision(t, "Designer", []string{capabilityMessageAgent})
	base := "/api/mcp/agents/" + designer.ID
	if code, _, raw := w.asOwner(t, "PUT", base+"/machine", `{"provides":["screen","Screen"]}`); code != http.StatusOK ||
		!strings.Contains(raw, `"provides":["screen"]`) {
		t.Fatalf("setting what its machine provides: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PUT", base+"/machine", `{"provides":["a fast car"]}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown need was taken: %d %s", code, raw)
	}

	// The provider appears once it has collected work, and fits.
	var fit struct {
		Needs     []string              `json:"needs"`
		Providers []machineProviderView `json:"providers"`
		Yourself  string                `json:"set_up_yourself"`
	}
	waitFor(t, "the provider to offer", func() bool {
		_, _, raw := w.asOwner(t, "GET", base+"/machines-that-fit", "")
		_ = json.Unmarshal([]byte(raw), &fit)
		return len(fit.Providers) == 1
	})
	p := fit.Providers[0]
	if !p.Fits || !p.Online || p.Name != "Machine maker" || strings.Join(p.Offers, ",") != "screen,toolchain" {
		t.Fatalf("the provider as offered: %+v", p)
	}

	code, _, raw := w.asOwner(t, "POST", base+"/machine-requests", `{"provider":"`+p.Body+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("asking for a machine: %d %s", code, raw)
	}
	if code, _, _ := w.asOwner(t, "POST", base+"/machine-requests", `{"provider":"`+p.Body+`"}`); code != http.StatusConflict {
		t.Fatalf("a second machine while the first is being made: %d", code)
	}

	// The provider makes it and hands it the enrolment string; the machine
	// enrols with it, as agent-host on the new machine would.
	waitFor(t, "the enrolment string", func() bool { _, err := os.Stat(filepath.Join(dir, "enrolment")); return err == nil })
	str, _ := os.ReadFile(filepath.Join(dir, "enrolment"))
	// The test server has no endpoint of its own, so the string names the
	// test's address, as enrolmentVia does.
	e, err := agentbody.ParseEnrolment(strings.TrimSpace(string(str)))
	if err != nil || e.Agent != designer.PairwiseAID {
		t.Fatalf("the enrolment string: %v %+v", err, e)
	}
	e.URL = w.srv.URL
	enrolment, _ := e.Encode()
	guest := newTestMachine(t)
	guestHost, _, _ := agentbody.Identity(guest)
	words := strings.Join(agentbody.Words(guestHost), " ")
	gh := &agenthost.Host{DataDir: t.TempDir(), Signer: guest, Hardware: true, PollEvery: 20 * time.Millisecond}
	enrolled := make(chan error, 1)
	go func() { _, err := gh.Enrol(enrolment, "vm", 20*time.Second); enrolled <- err }()
	waitFor(t, "the new machine to ask", func() bool {
		select {
		case err := <-enrolled:
			t.Fatalf("the new machine's enrolment ended: %v", err)
		default:
		}
		for _, b := range w.s.bodies().ForAgent(designer.ID) {
			if b.State == agentbody.StatePending {
				return true
			}
		}
		return false
	})
	if err := os.WriteFile(filepath.Join(dir, "words"), []byte(words), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the provider to report the words", func() bool { return w.machineRequest(t, designer.ID).State == agentmachine.StateEnrolling })
	j := w.machineRequest(t, designer.ID)
	if strings.Join(j.Words, " ") != words || j.Body == "" || strings.Join(j.Needs, ",") != "screen" {
		t.Fatalf("the request as reported: %+v", j)
	}

	// Nothing about the provider approves it: a person does.
	if b, _ := w.s.bodies().Get(j.Body); b.State != agentbody.StatePending {
		t.Fatalf("the new machine is %s before anybody approved it", b.State)
	}
	if code, _, raw := w.asOwner(t, "POST", base+"/bodies/"+j.Body+"/approve", ""); code != http.StatusOK {
		t.Fatalf("approving: %d %s", code, raw)
	}
	if err := <-enrolled; err != nil {
		t.Fatalf("the new machine's enrolment: %v", err)
	}
	if j = w.machineRequest(t, designer.ID); j.State != agentmachine.StateReady {
		t.Fatalf("after approval the request is %s", j.State)
	}

	// Removing the machine ends the body, and its provider destroys it.
	if code, _, raw := w.asOwner(t, "DELETE", base+"/bodies/"+j.Body, ""); code != http.StatusOK {
		t.Fatalf("removing: %d %s", code, raw)
	}
	waitFor(t, "the machine to be destroyed", func() bool { return w.machineRequest(t, designer.ID).State == agentmachine.StateRemoved })
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	want := "make " + j.MachineName + " screen for=Designer\nenrol " + j.MachineName + " for=Designer\nremove " + j.MachineName + " for=Designer\n"
	if string(calls) != want {
		t.Fatalf("the program was called:\n%s\nwant:\n%s", calls, want)
	}
	for _, e := range []string{"agent.machine.requested", "agent.machine.enrolment", "agent.machine.enrolling", "agent.machine.removing", "agent.machine.removed"} {
		if len(governanceRows(t, w, e)) != 1 {
			t.Fatalf("%s was not recorded once", e)
		}
	}
}

// Only a live body whose AI agent's grant lets it make machines collects that
// work or is given an enrolment string.
func TestOnlyABodyGrantedItMakesMachines(t *testing.T) {
	w, maker, providerHost := machineWorld(t)
	// Desk assistant's body may message, not make machines.
	if code, b, err := w.hostA.Call("GET", "/api/agent-host/machine-requests?offers=screen", nil); err != nil || code != http.StatusForbidden ||
		!strings.Contains(string(b), "agent.machine.provide") {
		t.Fatalf("a body without the grant collected work: %d %s %v", code, b, err)
	}
	if n := len(governanceRows(t, w, "agent.machine.provide")); n != 1 {
		t.Fatalf("the refusal was recorded %d times", n)
	}
	// Unsealed and unsigned, nothing is admitted.
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agent-host/machine-requests", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("work was given to a request that is not a body's")
	}
	// The provider is offered, and asked for no more than it provides.
	if code, b, err := providerHost.Call("GET", "/api/agent-host/machine-requests?offers=toolchain", nil); err != nil || code != http.StatusOK {
		t.Fatalf("the provider collecting: %d %s %v", code, b, err)
	}
	if code, b, _ := providerHost.Call("GET", "/api/agent-host/machine-requests?offers=a+fast+car", nil); code != http.StatusBadRequest {
		t.Fatalf("offering an unknown thing: %d %s", code, b)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/machine", `{"provides":["screen"]}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	pb := w.s.bodies().ForAgent(maker.ID)[0].ID
	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/machine-requests", `{"provider":"`+pb+`"}`); code != http.StatusConflict ||
		!strings.Contains(raw, "screen") {
		t.Fatalf("asking a provider for what it does not provide: %d %s", code, raw)
	}
	// Words no waiting machine shows are not taken.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.b.ID+"/machine", `{"provides":["toolchain"]}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents/"+w.b.ID+"/machine-requests", `{"provider":"`+pb+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, raw)
	}
	id := out["id"].(string)
	report := func(h *agenthost.Host, state string, words ...string) int {
		body, _ := json.Marshal(map[string]any{"state": state, "words": words})
		code, _, _ := h.Call("POST", "/api/agent-host/machine-requests/"+id, body)
		return code
	}
	if c := report(w.hostA, agentmachine.StateMaking); c != http.StatusForbidden {
		t.Fatalf("another body reported on the request: %d", c)
	}
	if c := report(providerHost, agentmachine.StateReady); c != http.StatusConflict {
		t.Fatalf("a provider said a machine was ready: %d", c)
	}
	if c := report(providerHost, agentmachine.StateMaking); c != http.StatusOK {
		t.Fatalf("making: %d", c)
	}
	if code, b, _ := w.hostA.Call("POST", "/api/agent-host/machine-requests/"+id+"/enrolment", []byte("{}")); code != http.StatusForbidden {
		t.Fatalf("another body was given the enrolment string: %d %s", code, b)
	}
	if c := report(providerHost, agentmachine.StateEnrolling, "a", "b", "c", "d", "e", "f"); c != http.StatusConflict {
		t.Fatalf("words no machine shows were taken: %d", c)
	}
	// Cancelling a machine being made asks its provider to destroy it.
	if code, out, raw := w.asOwner(t, "DELETE", "/api/mcp/agents/"+w.b.ID+"/machine-requests/"+id, ""); code != http.StatusOK ||
		out["state"] != agentmachine.StateRemoving {
		t.Fatalf("cancelling: %d %s", code, raw)
	}
}

// What an AI agent's machine must provide is set when it is made, kept when
// its configuration changes without mentioning it, and shown with it.
func TestWhatAMachineMustProvideIsKeptOnTheAIAgent(t *testing.T) {
	w := signInWorld(t)
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents",
		`{"name":"Researcher","capabilities":["agent.message.send"],"machine":{"provides":["toolchain","screen"]}}`)
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, raw)
	}
	id := out["asset_id"].(string)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+id, `{"role":"reads the web"}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "GET", "/api/mcp/agents/"+id+"/machine", ""); code != http.StatusOK ||
		!strings.Contains(raw, `"provides":["screen","toolchain"]`) {
		t.Fatalf("after a change that did not mention it: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "POST", "/api/mcp/agents",
		`{"name":"Racer","capabilities":["agent.message.send"],"machine":{"provides":["a fast car"]}}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown need was taken: %d %s", code, raw)
	}
}

// A person may approve the new machine from its own request before its
// provider's report arrives: the report is still matched, and the request is
// ready rather than the machine destroyed. A machine whose words a person
// rejects is destroyed.
func TestAMachineApprovedEarlyIsKeptAndOneRejectedIsDestroyed(t *testing.T) {
	w, maker, providerHost := machineWorld(t)
	pb := w.s.bodies().ForAgent(maker.ID)[0].ID
	if _, _, err := providerHost.Call("GET", "/api/agent-host/machine-requests?offers=toolchain", nil); err != nil {
		t.Fatal(err)
	}
	base := "/api/mcp/agents/" + w.b.ID
	if code, _, raw := w.asOwner(t, "PUT", base+"/machine", `{"provides":["toolchain"]}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, raw)
	}
	// One machine made and enrolled; returns its request id, binding and words.
	makeOne := func() (string, string, []string) {
		t.Helper()
		code, out, raw := w.asOwner(t, "POST", base+"/machine-requests", `{"provider":"`+pb+`"}`)
		if code != http.StatusCreated {
			t.Fatalf("%d %s", code, raw)
		}
		id := out["id"].(string)
		body, _ := json.Marshal(map[string]any{"state": agentmachine.StateMaking})
		if code, b, _ := providerHost.Call("POST", "/api/agent-host/machine-requests/"+id, body); code != http.StatusOK {
			t.Fatalf("making: %d %s", code, b)
		}
		code, b, err := providerHost.Call("POST", "/api/agent-host/machine-requests/"+id+"/enrolment", []byte("{}"))
		if err != nil || code != http.StatusCreated {
			t.Fatalf("enrolment: %d %s %v", code, b, err)
		}
		var en struct {
			Enrolment string `json:"enrolment"`
		}
		_ = json.Unmarshal(b, &en)
		e, _ := agentbody.ParseEnrolment(en.Enrolment)
		e.URL = w.srv.URL
		str, _ := e.Encode()
		guest := newTestMachine(t)
		h := &agenthost.Host{DataDir: t.TempDir(), Signer: guest, Hardware: true, PollEvery: 20 * time.Millisecond}
		go func() { _, _ = h.Enrol(str, "vm", 5*time.Second) }()
		host, _, _ := agentbody.Identity(guest)
		words := agentbody.Words(host)
		var bid string
		waitFor(t, "the machine to ask", func() bool {
			for _, b := range w.s.bodies().ForAgent(w.b.ID) {
				if b.State == agentbody.StatePending && strings.Join(b.Words, " ") == strings.Join(words, " ") {
					bid = b.ID
				}
			}
			return bid != ""
		})
		return id, bid, words
	}
	enrolling := func(id string, words []string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"state": agentmachine.StateEnrolling, "words": words})
		code, b, _ := providerHost.Call("POST", "/api/agent-host/machine-requests/"+id, body)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		if code != http.StatusOK {
			t.Fatalf("enrolling: %d %s", code, b)
		}
		return out
	}

	id, bid, words := makeOne()
	if code, _, raw := w.asOwner(t, "POST", base+"/bodies/"+bid+"/approve", ""); code != http.StatusOK {
		t.Fatalf("approving early: %d %s", code, raw)
	}
	if out := enrolling(id, words); out["state"] != agentmachine.StateReady || out["body"] != bid {
		t.Fatalf("a machine approved before its provider reported: %v", out)
	}

	id, bid, words = makeOne()
	enrolling(id, words)
	if code, _, raw := w.asOwner(t, "POST", base+"/bodies/"+bid+"/reject", ""); code != http.StatusOK {
		t.Fatalf("rejecting: %d %s", code, raw)
	}
	if j, _ := w.s.machines().Get(id); j.State != agentmachine.StateRemoving {
		t.Fatalf("a rejected machine is %s, not being destroyed", j.State)
	}
}
