package aiagents

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An AI agent with a model chosen calls that model and no other: a call that
// names another model, none, or a list to fall back on is refused before it
// reaches the provider, and recorded. A program's own default or helper model
// would otherwise be called, and paid for, unasked.
func TestOnlyTheChosenModelIsCalled(t *testing.T) {
	w, p := keyWorld(t)
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"brain":{"kind":"api_key","provider":"anthropic","model":"claude-stand-in"}}`); code != http.StatusOK {
		t.Fatalf("choosing the model: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]string{"Content-Type": "application/json", "Anthropic-Version": "2023-06-01"}
	for _, body := range []string{
		`{"model":"claude-its-own-default","stream":true,"messages":[]}`,
		`{"stream":true,"messages":[]}`,
		`{"model":"claude-stand-in","models":["claude-stand-in","claude-other"],"stream":true,"messages":[]}`,
		`{"model":"claude-stand-in ","stream":true,"messages":[]}`,
		// Read one way here and another by the provider: never let through.
		`{"model":"claude-its-own-default","model":"claude-stand-in","stream":true,"messages":[]}`,
		`{"model":"claude-its-own-default","Model":"claude-stand-in","stream":true,"messages":[]}`,
		`{"MODEL":"claude-stand-in","stream":true,"messages":[]}`,
		`{"models":null,"model":"claude-stand-in","stream":true,"messages":[]}`,
		`{"model":"claude-stand-in","stream":true,"messages":[]} {"model":"claude-its-own-default"}`,
		`[{"model":"claude-stand-in"}]`,
		`{"model":["claude-stand-in"],"stream":true,"messages":[]}`,
	} {
		code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages", header, []byte(body))
		if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(a["error"]), "calls only its chosen model, claude-stand-in") {
			t.Fatalf("%s was made: %d %v", body, code, a)
		}
	}
	if n := len(p.calls()); n != 0 {
		t.Fatalf("%d calls naming another model reached the provider", n)
	}
	denied := 0
	for _, r := range governanceRows(t, w, "agent.model.call") {
		if strings.Contains(fmt.Sprintf("%+v", r), "calls only its chosen model") {
			denied++
		}
	}
	if denied != 11 {
		t.Fatalf("%d refusals recorded, not 11", denied)
	}
	// The chosen model is called, its name spelt in JSON's escapes or not.
	if code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/messages", header,
		[]byte(`{"mod\u0065l":"claude-stand-in","stream":true,"messages":[]}`)); code != http.StatusOK {
		t.Fatalf("calling the chosen model, escaped: %d %v", code, a)
	} else {
		collectAll(t, w.hostA, a)
	}
	code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK {
		t.Fatalf("calling the chosen model: %d %v", code, a)
	}
	if got := collectAll(t, w.hostA, a); !strings.Contains(got, "from the model") {
		t.Fatalf("the answer: %q", got)
	}
}

// A call its brain lets go — the brain gave up on it, or its run ended — is
// passed on to nobody, but its answer is read to the end, so what it cost is
// recorded; it counts against its body until then. A call the AI agent may no
// longer make is still cut at once.
func TestACallLetGoIsReadToItsEndForWhatItCost(t *testing.T) {
	quickRecheck(t)
	w, p := keyWorld(t)
	hold := make(chan struct{})
	p.hold = hold
	ctx := context.Background()
	held, err := w.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages")
	if code != http.StatusOK || a["done"] == true {
		t.Fatalf("starting: %d %v", code, a)
	}
	if code, out, err := w.hostA.CallContext(ctx, "DELETE", fmt.Sprintf("/api/agent-host/model-calls/%s", a["call_id"]), nil); err != nil || code != http.StatusOK {
		t.Fatalf("letting it go: %d %s %v", code, out, err)
	}
	// Its run ends too, and gives its lease back.
	if err := w.hostA.Return(ctx, held); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // several rechecks
	of(w.s).modelCalls.mu.Lock()
	kept := len(of(w.s).modelCalls.calls)
	of(w.s).modelCalls.mu.Unlock()
	if kept != 1 {
		t.Fatalf("a call let go and still under way counted %d against its body, not 1", kept)
	}
	select {
	case <-p.cancelled:
		t.Fatal("the provider's answer was cut off, so what it cost is not known")
	default:
	}
	close(hold)
	var said string
	deadline := time.Now().Add(5 * time.Second)
	for said == "" {
		for _, r := range governanceRows(t, w, "agent.model.call") {
			said = fmt.Sprintf("%+v", r)
		}
		if said == "" && time.Now().After(deadline) {
			t.Fatal("the call let go was never recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{"120 tokens in, 42 out", "its brain let it go"} {
		if !strings.Contains(said, want) {
			t.Fatalf("the record does not say %q: %s", want, said)
		}
	}
	for time.Now().Before(deadline) {
		of(w.s).modelCalls.mu.Lock()
		kept = len(of(w.s).modelCalls.calls)
		of(w.s).modelCalls.mu.Unlock()
		if kept == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if kept != 0 {
		t.Fatal("a call let go was kept after it ended")
	}

	// Let go, and then the AI agent revoked: cut at once.
	w2, p2 := keyWorld(t)
	hold2 := make(chan struct{})
	p2.hold = hold2
	defer close(hold2)
	held2, err := w2.hostA.Borrow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, a = startModelCall(t, w2.hostA, held2.LeaseID, "/v1/messages")
	if code != http.StatusOK {
		t.Fatalf("starting: %d %v", code, a)
	}
	if code, out, err := w2.hostA.CallContext(ctx, "DELETE", fmt.Sprintf("/api/agent-host/model-calls/%s", a["call_id"]), nil); err != nil || code != http.StatusOK {
		t.Fatalf("letting it go: %d %s %v", code, out, err)
	}
	if code, _, raw := w2.asOwner(t, "POST", "/api/mcp/agents/"+w2.a.ID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	select {
	case <-p2.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the provider kept answering a call let go after its AI agent was revoked")
	}
}

// A call nobody collects is let go the same way: read to its end, its cost
// recorded, never cut off for want of a reader.
func TestACallNobodyCollectsIsReadToItsEnd(t *testing.T) {
	quickRecheck(t)
	modelCallIdle.Store(100 * time.Millisecond)
	w, p := keyWorld(t)
	hold := make(chan struct{})
	p.hold = hold
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if code, a := startModelCall(t, w.hostA, held.LeaseID, "/v1/messages"); code != http.StatusOK {
		t.Fatalf("starting: %d %v", code, a)
	}
	time.Sleep(500 * time.Millisecond) // idle, swept and rechecked several times over
	select {
	case <-p.cancelled:
		t.Fatal("a call nobody collected was cut off, so what it cost is not known")
	default:
	}
	close(hold)
	deadline := time.Now().Add(5 * time.Second)
	for {
		said := ""
		for _, r := range governanceRows(t, w, "agent.model.call") {
			said = fmt.Sprintf("%+v", r)
		}
		if strings.Contains(said, "120 tokens in, 42 out") && strings.Contains(said, "its brain let it go") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the call nobody collected was not recorded with what it used: %s", said)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A part of an answer that arrives as its call is let go is never held after
// it, and nothing held is left counted once the call is forgotten.
func TestLettingGoWhileAnswerArrivesHoldsNothing(t *testing.T) {
	for i := 0; i < 200; i++ {
		var buffered atomic.Int64
		c := &modelCall{id: "c", buffered: &buffered, letGoCh: make(chan struct{}), changed: make(chan struct{})}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				c.add(make([]byte, 1024))
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			c.letGo()
		}()
		close(start)
		wg.Wait()
		c.add(make([]byte, 1024))
		c.mu.Lock()
		held := len(c.buf)
		c.mu.Unlock()
		if held != 0 {
			t.Fatalf("%d bytes held after the call was let go", held)
		}
		if b := buffered.Load(); b != 0 {
			t.Fatalf("%d bytes still counted as held after the call was let go", b)
		}
	}
}
