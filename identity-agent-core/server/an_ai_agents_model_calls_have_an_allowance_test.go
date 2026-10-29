package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"identity-agent-core/brainsignin"
)

// costStep is a streamed answer that says it cost cost; a negative cost says
// nothing of what it cost.
func costStep(cost float64) func(map[string]any) string {
	return func(map[string]any) string {
		usage := `{"prompt_tokens":900,"completion_tokens":30}`
		if cost >= 0 {
			usage = fmt.Sprintf(`{"prompt_tokens":900,"completion_tokens":30,"cost":%g}`, cost)
		}
		return `data: {"id":"gen-stand-in","model":"vendor/model-a","choices":[{"delta":{"content":"ok"}}]}` + "\n\n" +
			`data: {"choices":[],"usage":` + usage + `}` + "\n\n" + "data: [DONE]\n\n"
	}
}

// allowanceWorld is a sign-in world whose first AI agent is signed in with an
// OpenRouter key kept here, its model chosen, and its provider stood in for.
func allowanceWorld(t *testing.T, steps ...func(map[string]any) string) (*talkWorld, *openRouterStandIn) {
	t.Helper()
	w := signInWorld(t)
	o := &openRouterStandIn{steps: steps}
	srv := o.serve(t)
	w.s.brainChecker = &brainsignin.Checker{OpenRouter: srv.URL + "/or", AddressRule: loopbackAllowed}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"openrouter","secret":"`+theOpenRouterKey+`"}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"brain":{"kind":"api_key","provider":"openrouter","model":"vendor/model-a"}}`); code != http.StatusOK {
		t.Fatalf("choosing the model: %d %s", code, raw)
	}
	return w, o
}

var openAIHeader = map[string]string{"Content-Type": "application/json"}

const chosenModelCall = `{"model":"vendor/model-a","stream":true,"max_tokens":16384,"messages":[]}`

// callOnce makes one model call through the Identity Agent and collects all
// of its answer, as a body does.
func callOnce(t *testing.T, w *talkWorld, lease string) (int, map[string]any) {
	t.Helper()
	code, a := startModelCallWith(t, w.hostA, lease, "POST", "/v1/chat/completions", openAIHeader, []byte(chosenModelCall))
	if code == http.StatusOK {
		collectAll(t, w.hostA, a)
		waitCounted(t, w)
	}
	return code, a
}

// waitCounted waits until none of the AI agent's calls is still to be counted.
func waitCounted(t *testing.T, w *talkWorld) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for w.s.modelCalls.callsUnderWay(w.a.ID) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("a call was never counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func allowanceOf(t *testing.T, w *talkWorld) map[string]any {
	t.Helper()
	code, out, raw := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/model-allowance", "")
	if code != http.StatusOK {
		t.Fatalf("reading the allowance: %d %s", code, raw)
	}
	m, _ := out["allowance"].(map[string]any)
	return m
}

// An allowance caps what an AI agent's model calls cost. Each call's cost, as
// the provider says it, is counted once its answer ends; once what is spent
// reaches the allowance, the next call is refused before it reaches the
// provider, and the refusal is recorded. Setting it again starts from nothing.
func TestAnAllowanceRefusesModelCallsOnceItIsSpent(t *testing.T) {
	w, o := allowanceWorld(t, costStep(0.0042), costStep(0.0042), costStep(0.0042), costStep(0.0042), costStep(0.0042))
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":0.01}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
			t.Fatalf("call %d, within the allowance, was refused: %d %v", i+1, code, a)
		}
	}
	code, a := callOnce(t, w, held.LeaseID)
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(a["error"]), "allowance of 0.010000 is spent (0.012600)") {
		t.Fatalf("a call past the allowance: %d %v", code, a)
	}
	if n := len(o.calls); n != 3 {
		t.Fatalf("the provider was called %d times, not 3", n)
	}
	m := allowanceOf(t, w)
	if m["amount"] != 0.01 || fmt.Sprintf("%.4f", m["spent"]) != "0.0126" || m["left"] != 0.0 {
		t.Fatalf("the allowance reads %v", m)
	}
	calls, _ := m["calls"].([]any)
	if len(calls) != 3 {
		t.Fatalf("the allowance lists %d calls, not 3", len(calls))
	}
	first := calls[0].(map[string]any)
	if first["model"] != "vendor/model-a" || first["cost"] != 0.0042 || first["cost_said"] != true || first["provider_id"] != "gen-stand-in" ||
		first["tokens_in"] != 900.0 || first["tokens_out"] != 30.0 {
		t.Fatalf("a call is listed as %v", first)
	}
	var said []string
	for _, r := range governanceRows(t, w, "agent.model.allowance") {
		said = append(said, r.ResultStatus+": "+r.Reason)
	}
	all := strings.Join(said, " | ")
	for _, want := range []string{"set: its model calls were given an allowance of 0.010000", "it was none",
		"spent: its allowance of 0.010000 is spent"} {
		if !strings.Contains(all, want) {
			t.Fatalf("the record does not say %q: %s", want, all)
		}
	}
	refused := false
	for _, r := range governanceRows(t, w, "agent.model.call") {
		if r.ResultStatus == "denied" && strings.Contains(r.Reason, "is spent") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the refused call was not recorded")
	}

	// Raised: what was spent is kept, so a cap over many tasks holds.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":0.0168}`); code != http.StatusOK {
		t.Fatalf("raising it: %d %s", code, raw)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("a call under the raised allowance: %d %v", code, a)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusForbidden {
		t.Fatalf("a call past the raised allowance: %d %v", code, a)
	}
	if m := allowanceOf(t, w); fmt.Sprintf("%.4f", m["spent"]) != "0.0168" || len(m["calls"].([]any)) != 4 {
		t.Fatalf("raising it did not keep what was spent: %v", m)
	}

	// Started over: counted from nothing, and what it was is recorded.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1,"start_over":true}`); code != http.StatusOK {
		t.Fatalf("starting over: %d %s", code, raw)
	}
	if m := allowanceOf(t, w); m["spent"] != 0.0 || len(m["calls"].([]any)) != 0 {
		t.Fatalf("starting over did not count from nothing: %v", m)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("a call under the new allowance: %d %v", code, a)
	}
	if m := allowanceOf(t, w); fmt.Sprintf("%.4f", m["spent"]) != "0.0042" {
		t.Fatalf("the new allowance counted %v", m["spent"])
	}

	// Nothing: the next call is refused, and nothing reaches the provider.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":0}`); code != http.StatusOK {
		t.Fatalf("an allowance of nothing: %d %s", code, raw)
	}
	before := len(o.calls)
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusForbidden {
		t.Fatalf("a call under an allowance of nothing: %d %v", code, a)
	}
	if len(o.calls) != before {
		t.Fatal("a call under an allowance of nothing reached the provider")
	}
	found := false
	for _, r := range governanceRows(t, w, "agent.model.allowance") {
		if strings.Contains(r.Reason, "counted from nothing") && strings.Contains(r.Reason, "it was 0.016800, 0.016800 spent") {
			found = true
		}
	}
	if !found {
		t.Fatal("starting over did not record what it was")
	}

	// Removed: calls are no longer capped, and that is recorded.
	if code, out, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":null}`); code != http.StatusOK ||
		out["allowance"] != nil {
		t.Fatalf("removing it: %d %s", code, raw)
	}
	removed := false
	for _, r := range governanceRows(t, w, "agent.model.allowance") {
		if r.ResultStatus == "removed" {
			removed = true
		}
	}
	if !removed {
		t.Fatal("removing the allowance was not recorded")
	}
}

// While an allowance is set the AI agent makes one model call at a time, so
// each call's cost is counted before the next can start: a second call while
// the first is under way is refused, and never reaches the provider.
func TestAnAllowanceLetsOneModelCallRunAtATime(t *testing.T) {
	release := make(chan struct{})
	slow := func(c map[string]any) string { <-release; return costStep(0.001)(c) }
	w, o := allowanceWorld(t, slow, costStep(0.001))
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	code, first := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(chosenModelCall))
	if code != http.StatusOK {
		t.Fatalf("the first call: %d %v", code, first)
	}
	if m, _, _ := w.s.allowanceOf(w.a.ID); m.Open != first["call_id"] {
		t.Fatalf("the call under way is not written down: %q, not %v", m.Open, first["call_id"])
	}
	if _, out, _ := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/model-allowance", ""); out["calls_under_way"] != 1.0 {
		t.Fatalf("calls under way: %v", out["calls_under_way"])
	}
	code, second := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(chosenModelCall))
	if code != http.StatusTooManyRequests || !strings.Contains(fmt.Sprint(second["error"]), "one model call at a time") {
		t.Fatalf("a second call while the first was under way: %d %v", code, second)
	}
	close(release)
	collectAll(t, w.hostA, first)
	waitCounted(t, w)
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("the next call, once the first was counted: %d %v", code, a)
	}
	if n := len(o.calls); n != 2 {
		t.Fatalf("the provider was called %d times, not 2", n)
	}

	// With no allowance, calls run side by side as before.
	w2, _ := allowanceWorld(t, slow, costStep(0.001))
	held2, err := w2.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release = make(chan struct{})
	defer close(release)
	if code, a := startModelCallWith(t, w2.hostA, held2.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(chosenModelCall)); code != http.StatusOK {
		t.Fatalf("the first call with no allowance: %d %v", code, a)
	}
	if code, a := startModelCallWith(t, w2.hostA, held2.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(chosenModelCall)); code != http.StatusOK {
		t.Fatalf("a second call with no allowance: %d %v", code, a)
	}
}

// A call answered without saying what it cost leaves what is left of the
// allowance unknown, so every call after it is refused until the allowance is
// set again. A call the provider refused costs nothing and is not that.
func TestACallWhoseCostIsNotSaidStopsTheAllowance(t *testing.T) {
	w, o := allowanceWorld(t, costStep(-1), costStep(0.001))
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("the first call: %d %v", code, a)
	}
	code, a := callOnce(t, w, held.LeaseID)
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(a["error"]), "without saying what it cost") {
		t.Fatalf("a call after one whose cost was not said: %d %v", code, a)
	}
	if m := allowanceOf(t, w); m["uncosted"] != 1.0 {
		t.Fatalf("the allowance reads %v", m)
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting it again: %d %s", code, raw)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("a call once it was set again: %d %v", code, a)
	}
	if n := len(o.calls); n != 2 {
		t.Fatalf("the provider was called %d times, not 2", n)
	}

	// A call the provider refuses (it has no more steps) is not uncosted.
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("a call the provider refuses still starts: %d %v", code, a)
	}
	if m := allowanceOf(t, w); m["uncosted"] != 0.0 {
		t.Fatalf("a refused call was counted as uncosted: %v", m)
	}
}

// An allowance is set only where it can be kept to: on an AI agent signed in
// with a key kept here, from a provider that says what each call costs, and
// to an amount that is more than nothing and not absurd. Nothing is kept when
// it is refused.
func TestAnAllowanceIsSetOnlyWhereItCanBeKeptTo(t *testing.T) {
	w, _ := keyWorld(t) // an Anthropic key, whose answers say no cost
	code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`)
	if code != http.StatusBadRequest || !strings.Contains(raw, "does not say what each call costs") {
		t.Fatalf("an allowance on an Anthropic key: %d %s", code, raw)
	}
	if m := allowanceOf(t, w); m != nil {
		t.Fatalf("an allowance was kept: %v", m)
	}
	unsigned := signInWorld(t)
	code, _, raw = unsigned.asOwner(t, "PUT", "/api/mcp/agents/"+unsigned.a.ID+"/model-allowance", `{"amount":1}`)
	if code != http.StatusBadRequest || !strings.Contains(raw, "sign this AI agent in") {
		t.Fatalf("an allowance with no sign-in: %d %s", code, raw)
	}
	w2, _ := allowanceWorld(t)
	for _, body := range []string{`{"amount":-1}`, `{"amount":1e9}`, `{"amount":"1"}`, `{}`, `nope`} {
		code, _, raw := w2.asOwner(t, "PUT", "/api/mcp/agents/"+w2.a.ID+"/model-allowance", body)
		if body == `{}` {
			// Naming no amount removes an allowance; there is none to remove.
			if code != http.StatusOK {
				t.Fatalf("%s: %d %s", body, code, raw)
			}
			continue
		}
		if code != http.StatusBadRequest {
			t.Fatalf("%s was accepted: %d %s", body, code, raw)
		}
	}
	if m := allowanceOf(t, w2); m != nil {
		t.Fatalf("an allowance was kept: %v", m)
	}
}

// A call is written down as under way before it is sent. One still written
// down that the Identity Agent no longer knows was lost when it restarted, and
// what it cost is not known, so every call after it is refused until a person
// sets the allowance again.
func TestACallLostInARestartStopsTheAllowance(t *testing.T) {
	w, o := allowanceWorld(t, costStep(0.001))
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	// As a restart leaves it: written down as under way, known to nobody.
	m, _, err := w.s.allowanceOf(w.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.Open = "a-call-from-before-the-restart"
	if err := w.s.SandboxManager.SetKept(allowanceRef(w.a.ID), keptAllowance, m); err != nil {
		t.Fatal(err)
	}
	if a := allowanceOf(t, w); a["lost_call"] != true {
		t.Fatalf("the allowance does not say a call was lost: %v", a)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	code, a := callOnce(t, w, held.LeaseID)
	if code != http.StatusForbidden || !strings.Contains(fmt.Sprint(a["error"]), "restarted") {
		t.Fatalf("a call after one was lost: %d %v", code, a)
	}
	if len(o.calls) != 0 {
		t.Fatal("a call after one was lost reached the provider")
	}
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting it again: %d %s", code, raw)
	}
	if code, a := callOnce(t, w, held.LeaseID); code != http.StatusOK {
		t.Fatalf("a call once it was set again: %d %v", code, a)
	}
	// The call was written down while under way, and cleared once counted.
	if m, _, _ := w.s.allowanceOf(w.a.ID); m.Open != "" {
		t.Fatalf("a counted call is still written down as under way: %q", m.Open)
	}
}

// Under an allowance a call says how long an answer it wants, within a bound,
// so the one call that crosses the allowance cannot cost without bound; said
// more than once, misspelt or not as a whole number, it is refused. Without
// an allowance nothing changes.
func TestACallUnderAnAllowanceBoundsItsAnswer(t *testing.T) {
	w, o := allowanceWorld(t, costStep(0.001), costStep(0.001), costStep(0.001))
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"model":"vendor/model-a","stream":true,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_tokens":40000,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_tokens":100,"max_completion_tokens":900000,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_tokens":100,"max_tokens":900000,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"MAX_TOKENS":100,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_tokens":"100","messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_tokens":0.5,"messages":[]}`,
	} {
		code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(body))
		if code != http.StatusForbidden {
			t.Fatalf("%s was made under an allowance: %d %v", body, code, a)
		}
	}
	if len(o.calls) != 0 {
		t.Fatalf("%d calls with no bound reached the provider", len(o.calls))
	}
	for _, body := range []string{
		`{"model":"vendor/model-a","stream":true,"max_tokens":32768,"messages":[]}`,
		`{"model":"vendor/model-a","stream":true,"max_output_tokens":100,"messages":[]}`,
	} {
		code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/chat/completions", openAIHeader, []byte(body))
		if code != http.StatusOK {
			t.Fatalf("%s was refused: %d %v", body, code, a)
		}
		collectAll(t, w.hostA, a)
		waitCounted(t, w)
	}
	// Removed: a call with no bound is made as before.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":null}`); code != http.StatusOK {
		t.Fatalf("removing it: %d %s", code, raw)
	}
	code, a := startModelCallWith(t, w.hostA, held.LeaseID, "POST", "/v1/chat/completions", openAIHeader,
		[]byte(`{"model":"vendor/model-a","stream":true,"messages":[]}`))
	if code != http.StatusOK {
		t.Fatalf("a call with no allowance: %d %v", code, a)
	}
	collectAll(t, w.hostA, a)
}

// A call the provider never answered costs nothing and is counted as ended,
// so it neither spends the allowance nor is later taken for a lost call.
func TestACallTheProviderNeverAnsweredIsNotLost(t *testing.T) {
	w, _ := allowanceWorld(t)
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/model-allowance", `{"amount":1}`); code != http.StatusOK {
		t.Fatalf("setting the allowance: %d %s", code, raw)
	}
	w.s.brainChecker = &brainsignin.Checker{OpenRouter: "http://127.0.0.1:1/or", AddressRule: loopbackAllowed}
	held, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		code, a := callOnce(t, w, held.LeaseID)
		if code != http.StatusOK {
			t.Fatalf("call %d was refused rather than tried: %d %v", i+1, code, a)
		}
	}
	m := allowanceOf(t, w)
	if m["spent"] != 0.0 || m["lost_call"] != false || len(m["calls"].([]any)) != 0 {
		t.Fatalf("calls never answered were counted: %v", m)
	}
	// Forgotten by the table, as a collected call is: still not lost.
	w.s.modelCalls.mu.Lock()
	for id := range w.s.modelCalls.calls {
		delete(w.s.modelCalls.calls, id)
	}
	w.s.modelCalls.mu.Unlock()
	if m := allowanceOf(t, w); m["lost_call"] != false {
		t.Fatalf("a call never answered was taken for a lost one: %v", m)
	}
}
