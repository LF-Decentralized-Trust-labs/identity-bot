package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
)

// approveWhenAsked approves the machine's pending body as soon as it appears,
// standing in for the owner comparing the words — after checking the words the
// owner would see are the machine's.
func approveWhenAsked(t *testing.T, s *CoreServer, agentID string, words string, done chan<- error) {
	go func() {
		for i := 0; i < 100; i++ {
			for _, b := range s.bodies().ForAgent(agentID) {
				if b.State == agentbody.StatePending {
					if strings.Join(b.Words, " ") != words {
						done <- nil
						return
					}
					rec := httptest.NewRecorder()
					s.handleApproveBody(rec, withRoute(httptest.NewRequest("POST", "/", nil),
						map[string]string{"id": agentID, "bid": b.ID}))
					done <- nil
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		done <- nil
	}()
}

// The agent-host program, against a running Identity Agent, over HTTP: it checks
// the Identity Agent's published key log against the string, enrols with its own
// key, waits, is approved, and its signed requests are then the AI agent's.
func TestAnAgentHostEnrolsAgainstARunningIdentityAgent(t *testing.T) {
	s, agentID := bodyWorld(t)
	// Sealed requests are replayed through the server's own router, as in production.
	rebuildRouter(s)
	srv := httptest.NewServer(s.router)
	defer srv.Close()
	t.Setenv("PUBLIC_URL", srv.URL)

	m := newTestMachine(t)
	host, _, _ := agentbody.Identity(m)
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: m, Hardware: true, PollEvery: 20 * time.Millisecond}

	enrolment := enrolmentVia(t, s, srv.URL, agentID)
	done := make(chan error, 1)
	approveWhenAsked(t, s, agentID, strings.Join(agentbody.Words(host), " "), done)
	st, err := h.Enrol(enrolment, "computer", 20*time.Second)
	<-done
	if err != nil {
		t.Fatalf("enrolling: %v", err)
	}
	if st.BindingID == "" {
		t.Fatal("no binding was recorded")
	}

	code, body, err := h.Call("POST", "/api/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil || code != http.StatusOK || !strings.Contains(string(body), `"system.info.read"`) {
		t.Fatalf("a signed request from the enrolled machine: %d %s %v", code, body, err)
	}
	status, err := h.Status()
	if err != nil || status["state"] != agentbody.StateActive || status["grade"] != agentbody.GradeHardwareAsserted {
		t.Fatalf("status: %v %v", status, err)
	}

	// Running the same command again on the machine that is already the body
	// says so, and is not reported as a refused string.
	var out strings.Builder
	h.Out = &out
	if _, err := h.Enrol(enrolment, "computer", time.Second); err != nil {
		t.Fatalf("re-running on the enrolled machine: %v", err)
	}
	if !strings.Contains(out.String(), "already the body") || strings.Contains(out.String(), "six words") {
		t.Fatalf("re-running on the enrolled machine said: %q", out.String())
	}
}

// enrolmentVia asks for an enrolment string the way the desktop app does, so the
// address in it is the one the machine will reach.
func enrolmentVia(t *testing.T, s *CoreServer, base, agentID string) string {
	t.Helper()
	r := withRoute(httptest.NewRequest("POST", base+"/api/mcp/agents/"+agentID+"/body-enrolment", nil),
		map[string]string{"id": agentID})
	code, out := call(t, s.handleCreateBodyEnrolment, r)
	if code != http.StatusCreated {
		t.Fatalf("enrolment string: %d %v", code, out)
	}
	e, _ := agentbody.ParseEnrolment(out["enrolment"].(string))
	if e.URL != base {
		e.URL = base
		str, _ := e.Encode()
		return str
	}
	return out["enrolment"].(string)
}

// A string that names a point in the key log the Identity Agent does not have —
// what a relay answering with another identity's log looks like — stops the
// machine before it sends anything.
func TestAnAgentHostRefusesAnIdentityAgentThatIsNotTheOneNamed(t *testing.T) {
	s, agentID := bodyWorld(t)
	// Sealed requests are replayed through the server's own router, as in production.
	rebuildRouter(s)
	srv := httptest.NewServer(s.router)
	defer srv.Close()
	good, _ := agentbody.ParseEnrolment(enrolmentVia(t, s, srv.URL, agentID))

	for name, tamper := range map[string]func(*agentbody.Enrolment){
		"another event":          func(e *agentbody.Enrolment) { e.KeyStateSAID = "EAnEventThisLogDoesNotHave000000000000000000" },
		"another Identity Agent": func(e *agentbody.Enrolment) { e.IdentityAgent = "ESomeOtherIdentityAgent00000000000000000000" },
	} {
		e := good
		tamper(&e)
		str, _ := e.Encode()
		h := &agenthost.Host{DataDir: t.TempDir(), Signer: newTestMachine(t), PollEvery: 20 * time.Millisecond}
		if _, err := h.Enrol(str, "computer", time.Second); err == nil {
			t.Fatalf("%s: the machine enrolled", name)
		}
		if n := len(s.bodies().ForAgent(agentID)); n != 0 {
			t.Fatalf("%s: the machine sent its enrolment before checking (%d bodies)", name, n)
		}
	}
}
