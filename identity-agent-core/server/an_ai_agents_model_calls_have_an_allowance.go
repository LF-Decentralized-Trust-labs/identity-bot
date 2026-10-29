package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// An AI agent's model calls may be given an allowance: an amount, in its
// provider's currency, that its calls through this Identity Agent may cost
// before the next is refused (ADR-057). It is how a person caps what a run
// spends — a benchmark, or a worker left on its own — so that no loop on the
// AI agent's machine can spend past it.
//
// Changing the amount keeps what has been spent, so a cap over many tasks
// holds across them, and an amount of nothing stops the next call; only
// starting over counts from nothing again. Removing it lifts the cap.
//
// What a call costs is known only once its answer has ended, from what the
// provider says, so while an allowance is set the AI agent makes one model
// call at a time, across every machine: a call is refused while another is
// still under way or not yet counted. What is spent can then pass the
// allowance by at most the one call that crossed it. A call whose provider
// did not say what it cost leaves the allowance unknowable, so every call
// after it is refused until the allowance is set again. An allowance can only
// be set on a sign-in whose provider says what each call costs.
//
// The allowance is kept in the vault, beside what is lent, so a restart does
// not forget what was spent. Setting and removing it is recorded, with what
// it was before.

// allowanceCalls bounds the calls an allowance lists, the latest kept.
const allowanceCalls = 200

// allowanceLargest bounds an allowance, as a check on a mistyped amount.
const allowanceLargest = 100000.0

// allowanceAnswerLongest bounds how long an answer a call under an allowance
// may ask for, in tokens, so the one call that crosses the allowance is
// bounded too: what it reads is bounded by how large a call may be.
const allowanceAnswerLongest = 32768

// modelAllowance is an AI agent's allowance and what has been spent from it.
type modelAllowance struct {
	Amount float64 `json:"amount"`
	Spent  float64 `json:"spent"`
	Since  string  `json:"since"`
	// Uncosted counts calls the provider answered without saying what they
	// cost; one is enough to refuse every call after it.
	Uncosted int             `json:"uncosted"`
	Calls    []allowanceCall `json:"calls"`
	// Open is the call under way, written before it is sent and cleared when
	// it is counted. One still open that this Identity Agent no longer knows
	// was lost in a restart, and what it cost is not known.
	Open string `json:"open,omitempty"`
}

// allowanceCall is one call counted against an allowance, as the provider
// reported it.
type allowanceCall struct {
	At string `json:"at"`
	// ProviderID is the provider's own id for the call, where it gave one.
	ProviderID string  `json:"provider_id,omitempty"`
	Model      string  `json:"model"`
	Status     int     `json:"status"`
	TokensIn   int64   `json:"tokens_in"`
	TokensOut  int64   `json:"tokens_out"`
	Cost       float64 `json:"cost"`
	CostSaid   bool    `json:"cost_said"`
}

func allowanceRef(agentID string) string { return sandbox.KeptRef("model-allowance:" + agentID) }

const keptAllowance = "model_allowance"

// allowanceMu serialises every read-and-write of an allowance, so two calls
// ending together both count.
var allowanceMu sync.Mutex

// providerSaysCost reports whether a provider's answers say what each call
// cost, which an allowance needs.
func providerSaysCost(provider string) bool { return provider == brainsignin.OpenRouter }

// allowanceOf is a's allowance, if it has one.
func (s *CoreServer) allowanceOf(agentID string) (modelAllowance, bool, error) {
	vault, err := s.brainVault()
	if err != nil {
		return modelAllowance{}, false, err
	}
	var m modelAllowance
	had, err := vault.Kept(allowanceRef(agentID), keptAllowance, &m)
	return m, had, err
}

// errAllowanceUnreadable is an allowance that cannot be read, which refuses
// the call rather than letting it spend unmeasured.
var errAllowanceUnreadable = errors.New("this AI agent's allowance cannot be read now")

// errOneCallAtATime is a call refused because another of the AI agent's calls
// is still under way, or not yet counted, while it has an allowance.
var errOneCallAtATime = errors.New("while an allowance is set, this AI agent makes one model call at a time, " +
	"so what each costs is counted before the next")

// theAnswerBound is how long an answer a call asks for, in tokens, read as
// strictly as its model is: each way of saying it at most once, spelt exactly,
// a whole number. The largest said counts; 0 where none is.
func theAnswerBound(body []byte) (int, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return 0, errors.New("this call is not one JSON object")
	}
	seen := map[string]bool{}
	most := 0
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return 0, errors.New("this call could not be read")
		}
		k, _ := t.(string)
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return 0, errors.New("this call could not be read")
		}
		name := ""
		for _, n := range answerBoundNames {
			if strings.EqualFold(k, n) {
				name = n
			}
		}
		if name == "" {
			continue
		}
		if k != name || seen[name] {
			return 0, errors.New("this call says how long an answer it wants more than once, or not as the provider spells it")
		}
		seen[name] = true
		var n float64
		if err := json.Unmarshal(v, &n); err != nil || n != math.Trunc(n) || n < 1 || n > math.MaxInt32 {
			return 0, errors.New("this call's answer length is not a whole number of tokens")
		}
		if int(n) > most {
			most = int(n)
		}
	}
	return most, nil
}

// answerBoundNames are the ways the providers' formats name how long an
// answer may be.
var answerBoundNames = []string{"max_tokens", "max_completion_tokens", "max_output_tokens"}

// errLostCall is a call that was under way when this Identity Agent last
// stopped: what it cost is not known.
var errLostCall = errors.New("a call under this AI agent's allowance was under way when its Identity Agent " +
	"restarted, so what it cost is not known; set the allowance again to go on")

// allowanceRefuses says why a call may not start under a's allowance, or
// nothing, and whether it has one. It is asked with the call table held, so
// no second call can start between the answer and the call being kept; known
// says whether the table holds a call.
//
// bound is how long an answer the call asks for, in tokens: 0 where it names
// none, and -1 where it is not a model call (a list of models costs nothing).
func (s *CoreServer) allowanceRefuses(a asset.Asset, provider string, bound, underWay int, known func(string) bool) (bool, error) {
	m, had, err := s.allowanceOf(a.ID)
	if err != nil {
		return false, errAllowanceUnreadable
	}
	if !had {
		return false, nil
	}
	return true, m.refuses(provider, bound, underWay, known)
}

func (m modelAllowance) refuses(provider string, bound, underWay int, known func(string) bool) error {
	switch {
	case bound == 0 || bound > allowanceAnswerLongest:
		return fmt.Errorf("while an allowance is set, a model call names how long an answer it wants, "+
			"at most %d tokens, so no one call can cost without bound", allowanceAnswerLongest)
	case m.Open != "" && !known(m.Open):
		return errLostCall
	case !providerSaysCost(provider):
		return fmt.Errorf("this AI agent has an allowance, and %s does not say what a call costs, so it cannot be kept to", provider)
	case m.Uncosted > 0:
		return errors.New("a call under this AI agent's allowance was answered without saying what it cost, " +
			"so what is left is not known; set the allowance again to go on")
	case m.Spent >= m.Amount:
		return fmt.Errorf("this AI agent's allowance of %s is spent (%s)", money(m.Amount), money(m.Spent))
	case underWay > 0:
		return errOneCallAtATime
	}
	return nil
}

// chargeAllowance counts one ended call against a's allowance, if it has one.
func (s *CoreServer) chargeAllowance(a asset.Asset, id string, call allowanceCall) {
	allowanceMu.Lock()
	defer allowanceMu.Unlock()
	m, had, err := s.allowanceOf(a.ID)
	if err != nil || !had {
		return
	}
	if m.Open == id {
		m.Open = ""
	}
	// A call never answered has nothing to count; it is only no longer under
	// way.
	if call.Status > 0 {
		m.Spent += call.Cost
		if !call.CostSaid && call.Status < 400 {
			m.Uncosted++
		}
		m.Calls = append(m.Calls, call)
		if len(m.Calls) > allowanceCalls {
			m.Calls = m.Calls[len(m.Calls)-allowanceCalls:]
		}
	}
	vault, err := s.brainVaultWritable()
	if err == nil {
		err = vault.SetKept(allowanceRef(a.ID), keptAllowance, m)
	}
	if err != nil {
		// The call has ended and cannot be undone; what is left is no longer
		// known, so nothing more is spent until it is set again.
		s.recordLentEvent(a, sandbox.CallerContext{}, "agent.model.allowance", "failed",
			"a call's cost could not be counted against the allowance: "+err.Error())
		return
	}
	if call.Status > 0 && m.Spent >= m.Amount {
		s.recordLentEvent(a, sandbox.CallerContext{}, "agent.model.allowance", "spent",
			fmt.Sprintf("its allowance of %s is spent (%s); its next model call is refused", money(m.Amount), money(m.Spent)))
	}
}

// openAllowanceCall writes, before a call is sent, that it is under way, so a
// restart that loses it is known to have lost what it cost.
func (s *CoreServer) openAllowanceCall(a asset.Asset, id string) error {
	allowanceMu.Lock()
	defer allowanceMu.Unlock()
	m, had, err := s.allowanceOf(a.ID)
	if err != nil {
		return errAllowanceUnreadable
	}
	if !had {
		return nil
	}
	m.Open = id
	vault, err := s.brainVaultWritable()
	if err != nil {
		return err
	}
	return vault.SetKept(allowanceRef(a.ID), keptAllowance, m)
}

// callsUnderWay counts a's model calls that have not ended and been counted,
// across every machine.
func (t *modelCallTable) callsUnderWay(agentID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, c := range t.calls {
		if c.agent == agentID && !c.counted.Load() {
			n++
		}
	}
	return n
}

// has says whether the table holds the call id.
func (t *modelCallTable) has(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.calls[id]
	return ok
}

func money(v float64) string { return fmt.Sprintf("%.6f", v) }

// allowanceView is an allowance as the owner's app reads it.
func (s *CoreServer) allowanceView(a asset.Asset, m modelAllowance, had bool) map[string]any {
	if !had {
		return map[string]any{"allowance": nil, "calls_under_way": s.modelCalls.callsUnderWay(a.ID)}
	}
	calls := m.Calls
	if calls == nil {
		calls = []allowanceCall{}
	}
	return map[string]any{"allowance": map[string]any{
		"amount": m.Amount, "spent": m.Spent, "left": math.Max(0, m.Amount-m.Spent), "since": m.Since,
		"uncosted": m.Uncosted, "calls": calls, "lost_call": m.Open != "" && !s.modelCalls.has(m.Open),
	}, "calls_under_way": s.modelCalls.callsUnderWay(a.ID)}
}

func (s *CoreServer) handleGetModelAllowance(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	m, had, err := s.allowanceOf(a.ID)
	if err != nil {
		jsonError(w, errAllowanceUnreadable.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, s.allowanceView(a, m, had))
}

// handleSetModelAllowance gives an AI agent's model calls an allowance,
// counted from nothing, or removes it ("amount": null).
func (s *CoreServer) handleSetModelAllowance(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	if s.refuseIfRevoked(w, a.ID) {
		return
	}
	var q struct {
		Amount    *float64 `json:"amount"`
		StartOver bool     `json:"start_over"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q); err != nil {
		jsonError(w, "the allowance is unreadable", http.StatusBadRequest)
		return
	}
	vault, err := s.brainVaultWritable()
	if err != nil {
		jsonError(w, "nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	who := firstNonEmptyString(madeByController(r), "the owner")
	allowanceMu.Lock()
	defer allowanceMu.Unlock()
	before, had, err := s.allowanceOf(a.ID)
	if err != nil {
		jsonError(w, "nothing was changed: "+errAllowanceUnreadable.Error(), http.StatusServiceUnavailable)
		return
	}
	was := "none"
	if had {
		was = fmt.Sprintf("%s, %s spent", money(before.Amount), money(before.Spent))
	}
	if q.Amount == nil {
		if had {
			if err := vault.RemoveKept(allowanceRef(a.ID)); err != nil {
				jsonError(w, "nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			s.recordLentEvent(a, sandbox.CallerContext{}, "agent.model.allowance", "removed",
				fmt.Sprintf("its model calls' allowance was removed by %s; it was %s", who, was))
		}
		writeJSONStatus(w, http.StatusOK, s.allowanceView(a, modelAllowance{}, false))
		return
	}
	amount := *q.Amount
	if math.IsNaN(amount) || amount < 0 || amount > allowanceLargest {
		jsonError(w, fmt.Sprintf("nothing was changed: an allowance is from nothing to at most %.0f", allowanceLargest),
			http.StatusBadRequest)
		return
	}
	rec, signedIn, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	if err != nil {
		jsonError(w, "nothing was changed: the AI agent's sign-in cannot be read now", http.StatusServiceUnavailable)
		return
	}
	if !signedIn || !rec.StaysInVault() {
		jsonError(w, "nothing was changed: an allowance caps model calls made with a key kept here; "+
			"sign this AI agent in with one first", http.StatusBadRequest)
		return
	}
	if !providerSaysCost(rec.Provider) {
		jsonError(w, fmt.Sprintf("nothing was changed: %s does not say what each call costs, so an allowance "+
			"could not be kept to", rec.Provider), http.StatusBadRequest)
		return
	}
	// A person setting it has seen what it reads, so a call whose cost was
	// not said no longer stops the next; what was spent is kept unless they
	// start over.
	m := modelAllowance{Amount: amount, Since: time.Now().UTC().Format(time.RFC3339Nano), Calls: []allowanceCall{}}
	how := "counted from nothing"
	if had && before.Open != "" && s.modelCalls.has(before.Open) {
		// A call still under way is counted when it ends, whatever is set now.
		m.Open = before.Open
	}
	if had && !q.StartOver {
		m.Spent, m.Since, m.Calls = before.Spent, before.Since, before.Calls
		how = fmt.Sprintf("with %s already spent", money(before.Spent))
	}
	if err := vault.SetKept(allowanceRef(a.ID), keptAllowance, m); err != nil {
		jsonError(w, "nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.recordLentEvent(a, sandbox.CallerContext{}, "agent.model.allowance", "set",
		fmt.Sprintf("its model calls were given an allowance of %s in %s's currency, %s, by %s; it was %s",
			money(amount), rec.Provider, how, who, was))
	writeJSONStatus(w, http.StatusOK, s.allowanceView(a, m, true))
}
