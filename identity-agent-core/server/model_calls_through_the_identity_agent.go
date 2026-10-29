package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"identity-agent-core/asset"
	"identity-agent-core/brainsignin"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// An AI agent whose brain is an API key never holds the key. Its body's brain
// is pointed at the body's own model address, and the body passes each model
// call here, sealed and signed like everything it sends, citing the lease its
// run holds on the sign-in. This Identity Agent checks the lease is still
// open and the AI agent may still act, adds the key from the vault, sends the
// call out the way its own model calls go — the same policy check, blocked
// domains, proxy log and trace — and records it. Taking the key away, revoking
// the AI agent or ending its grant therefore takes effect at the next call,
// not at the next run.
//
// The answer is read as it arrives. A model's answer streams for minutes, and
// a sealed request is answered whole, so the call runs here in the background
// and the body collects what has arrived so far, each collection waiting a
// little while for more. Nothing between the body and this Identity Agent
// holds a connection open for longer than one collection.

// modelCallsThroughHere is what a body says, when it borrows, to say it makes
// its brain's model calls through this Identity Agent.
const modelCallsThroughHere = "through_identity_agent"

const (
	// modelCallLongest is the longest one model call may take.
	modelCallLongest = 30 * time.Minute
	// modelCallUnread bounds what is held of an answer not yet collected.
	modelCallUnread = 16 << 20
	// modelCallLetGoLargest bounds how much more of an answer is read once its
	// brain let it go, so finishing it can cost no more than an answer that
	// long; one longer is cut, and recorded as cut.
	modelCallLetGoLargest = 16 << 20
	// modelRequestLargest bounds a model call's request, and modelCallChunk
	// what one collection carries of an answer. Both travel in a sealed
	// envelope of at most didcomm.SealedMaxBody (8 MB), base64-encoded three
	// times on the way: in the call, in the sealed request, and in the
	// envelope, about 2.4 times their size in all. 3 MB comes to a little over
	// 7 MB; 2 MB to under 5.
	modelRequestLargest = 3 << 20
	modelCallChunk      = 2 << 20
	// modelCallsPerBody bounds the calls one body may hold here at once for
	// its AI agent, under way or answered and not yet collected, whichever
	// leases they cite.
	modelCallsPerBody = 8
	// modelCallsBuffered bounds what is held of every answer not yet
	// collected, across all calls, and modelCallsHeld how many calls are kept
	// at once across every machine.
	modelCallsBuffered = 128 << 20
	modelCallsHeld     = 1024
	// modelPathLongest bounds a call's path.
	modelPathLongest = 256
	// modelDenialsRecorded bounds the refusals recorded for one body each
	// minute, so a body cannot fill the record by asking for what it may not.
	modelDenialsRecorded = 20
)

// modelQuery are the query parameters a model call may carry, by what each
// may be: Claude Code asks for Anthropic's beta features with beta=true, and a
// list of models pages with these.
var modelQuery = map[string]func(string) bool{
	"beta":      func(v string) bool { return v == "true" },
	"limit":     func(v string) bool { return len(v) <= 4 && strings.Trim(v, "0123456789") == "" },
	"after_id":  func(v string) bool { return len(v) <= 128 && printableName(v) },
	"before_id": func(v string) bool { return len(v) <= 128 && printableName(v) },
}

// modelCallQuery is the call's query as it is sent on, or why it is not
// allowed: only the parameters modelQuery names, each once, as it allows.
func modelCallQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return "", errors.New("the call's query is unreadable")
	}
	for k, vals := range v {
		ok := modelQuery[k]
		if ok == nil || len(vals) != 1 || !ok(vals[0]) {
			return "", fmt.Errorf("the query parameter %q is not one a model call may carry", printable(k, 40))
		}
	}
	return v.Encode(), nil
}

// printableName reports whether s is a plain name: letters, digits and
// . - _ : / only.
func printableName(s string) bool {
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-_:/", r)) {
			return false
		}
	}
	return true
}

// printable is s as the record may say it: at most n characters, and nothing
// that is not printable on one line, so what a body sends cannot write lines
// of its own into the record.
func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("…")
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

// modelCallIdle is how long a call goes on with nobody collecting it before
// it is let go, or, once its answer has ended, forgotten: its body is gone or
// gave up. Held so a test may shorten it while calls are being swept.
var modelCallIdle atomicDuration

func init() { modelCallIdle.Store(90 * time.Second) }

// atomicDuration is a duration read and set from more than one goroutine.
type atomicDuration struct{ n atomic.Int64 }

func (d *atomicDuration) Load() time.Duration   { return time.Duration(d.n.Load()) }
func (d *atomicDuration) Store(v time.Duration) { d.n.Store(int64(v)) }

// modelCallWait is how long one collection waits for more of an answer. A
// variable, like modelCallRecheck, so a test need not wait for it.
var modelCallWait = 20 * time.Second

// modelCallRecheck is how often a call under way checks again that its run
// may still make it, and that somebody is collecting it. A variable so a test
// need not wait for it.
var modelCallRecheck = 15 * time.Second

// modelRoutes are the calls a brain may make with its key, by provider: the
// model calls and the list of models, and nothing else the key could do.
// Grok's program also asks xAI what its key is before it starts — the key's
// name and what it may use, never the key — and does not start without it.
var modelRoutes = map[string][]string{
	brainsignin.Anthropic:  {"POST /v1/messages", "POST /v1/messages/count_tokens", "GET /v1/models"},
	brainsignin.OpenAI:     {"POST /v1/chat/completions", "POST /v1/responses", "GET /v1/models"},
	brainsignin.XAI:        {"POST /v1/chat/completions", "POST /v1/responses", "POST /v1/messages", "GET /v1/models", "GET /v1/api-key"},
	brainsignin.OpenRouter: {"POST /v1/chat/completions", "POST /v1/responses", "POST /v1/messages", "GET /v1/models"},
	brainsignin.Google:     {},
}

// modelRouteAllowed reports whether a brain signed in with provider may make
// this call. The path must be plain and short: nothing escaped, no query or
// fragment in it, and nothing that cleaning it would change, so what is
// checked is what is sent. Beyond the routes themselves, only one model may be asked about by
// name (GET /v1/models/{model}, whose name may hold a slash, as OpenRouter's
// do).
func modelRouteAllowed(provider, method, p string) bool {
	if len(p) > modelPathLongest || !strings.HasPrefix(p, "/") || !printableName(p) || path.Clean(p) != p {
		return false
	}
	for _, r := range modelRoutes[provider] {
		m, route, _ := strings.Cut(r, " ")
		if m != method {
			continue
		}
		if p == route || (m == http.MethodGet && route == "/v1/models" && strings.HasPrefix(p, route+"/")) {
			return true
		}
	}
	return false
}

// modelResponseHeaders are the headers of the provider's answer that travel
// back to the brain.
var modelResponseHeaders = []string{"Content-Type", "Retry-After", "Request-Id", "X-Request-Id"}

// modelCallRequest is a model call as a body sends it.
type modelCallRequest struct {
	LeaseID string            `json:"lease_id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

// modelCallAnswer is what a body collects of a call: the provider's status and
// headers once they have arrived, the part of its answer after what the body
// has already collected, where the next collection starts, and whether the
// answer is complete.
type modelCallAnswer struct {
	CallID  string            `json:"call_id"`
	Status  int               `json:"status,omitempty"`
	Header  map[string]string `json:"header,omitempty"`
	DataB64 string            `json:"data_b64,omitempty"`
	Next    int64             `json:"next"`
	Done    bool              `json:"done"`
	Error   string            `json:"error,omitempty"`
}

// modelCall is one model call under way.
type modelCall struct {
	id, agent, host string
	stopOnce        sync.Once
	stopCh          chan struct{}

	// letGo is closed once the brain has let the call go — it gave up on it,
	// or nobody collects it — and lettingGo says so. Its answer is then read to
	// its end and passed on to nobody, so what it cost is recorded.
	letGoOnce sync.Once
	letGoCh   chan struct{}
	lettingGo atomic.Bool

	// buffered counts what every call holds of answers not yet collected.
	buffered *atomic.Int64

	mu sync.Mutex
	// lease is the lease the run cites now: a run whose lease lapsed takes
	// another, and its next collection says so.
	lease string
	// changed is closed, and replaced, whenever something arrives.
	changed   chan struct{}
	status    int
	header    map[string]string
	buf       []byte
	base      int64 // what buf[0] is in the whole answer
	done      bool
	err       string
	collected time.Time
}

func (c *modelCall) stop() { c.stopOnce.Do(func() { close(c.stopCh) }) }

// letGo is the brain giving the call up: nothing more of its answer is held
// for it, and the answer is read to its end for what it cost.
//
// lettingGo is set under c.mu, with what is held let go in the same hold, so
// add — which checks it under c.mu too — never holds a part after it. letGoCh
// only wakes the watcher; lettingGo is what says the call was let go.
func (c *modelCall) letGo() {
	c.letGoOnce.Do(func() {
		c.mu.Lock()
		c.lettingGo.Store(true)
		c.held(-int64(len(c.buf)))
		c.base += int64(len(c.buf))
		c.buf = nil
		c.changedLocked()
		c.mu.Unlock()
		if c.letGoCh != nil {
			close(c.letGoCh)
		}
	})
}

func (c *modelCall) currentLease() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lease
}

// changedLocked wakes whoever waits for more, with c.mu held.
func (c *modelCall) changedLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *modelCall) head(status int, h map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.header = status, h
	c.changedLocked()
}

// add appends part of the answer, and says whether the body is keeping up and
// there is room for it among every answer held here.
//
// Once the call is let go nothing is held, and the answer is read on to its
// end for what it cost: add holds nothing and never asks for it to be cut.
func (c *modelCall) add(b []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lettingGo.Load() {
		return true
	}
	c.buf = append(c.buf, b...)
	total := c.held(int64(len(b)))
	c.changedLocked()
	return len(c.buf) <= modelCallUnread && total <= modelCallsBuffered
}

// held counts n more bytes held of answers not yet collected, and returns
// what every call holds now.
func (c *modelCall) held(n int64) int64 {
	if c.buffered == nil {
		return 0
	}
	return c.buffered.Add(n)
}

// release lets go of what c holds, once it is forgotten.
func (c *modelCall) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.held(-int64(len(c.buf)))
	c.base += int64(len(c.buf))
	c.buf = nil
}

func (c *modelCall) finish(why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.done, c.err = true, why
	c.changedLocked()
}

// idle reports whether nobody has collected the call for modelCallIdle. A call
// let go waits for nobody, so it is idle only once it has ended.
func (c *modelCall) idle(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lettingGo.Load() {
		return c.done
	}
	return now.Sub(c.collected) > modelCallIdle.Load()
}

// errCollectedAlready is a collection from before what the body already
// collected: that part was let go, so the answer cannot be given again.
var errCollectedAlready = errors.New("that part of the answer was collected already, and is gone")

// collect is what the body has not yet collected from offset from, at most
// modelCallChunk of it, waiting up to wait for something to arrive when
// nothing new has: the provider's status, when the body does not have it yet
// (haveHead), or more of the answer. Whatever is before from was collected,
// and is let go. The answer is done only once all of it has been collected.
func (c *modelCall) collect(ctx context.Context, from int64, haveHead bool, wait time.Duration) (modelCallAnswer, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		c.collected = time.Now()
		if from < c.base {
			c.mu.Unlock()
			return modelCallAnswer{}, errCollectedAlready
		}
		if drop := from - c.base; drop > 0 {
			if drop > int64(len(c.buf)) {
				drop = int64(len(c.buf))
			}
			c.buf = c.buf[drop:]
			c.base += drop
			c.held(-drop)
		}
		ready := c.done || (c.status != 0 && (len(c.buf) > 0 || !haveHead))
		if ready || wait <= 0 {
			part := c.buf
			if len(part) > modelCallChunk {
				part = part[:modelCallChunk]
			}
			a := modelCallAnswer{CallID: c.id, Status: c.status, Header: c.header,
				Next: c.base + int64(len(part)), Done: c.done && len(part) == len(c.buf), Error: c.err}
			if len(part) > 0 {
				a.DataB64 = base64.StdEncoding.EncodeToString(part)
			}
			c.mu.Unlock()
			return a, nil
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			wait = 0
		case <-ctx.Done():
			wait = 0
		}
	}
}

// modelCallTable is the model calls under way, and those answered but not yet
// collected.
type modelCallTable struct {
	mu       sync.Mutex
	calls    map[string]*modelCall
	buffered atomic.Int64
	sweeping sync.Once
	// denied counts each body's refusals recorded this minute.
	denied map[string]*denials
}

type denials struct {
	since time.Time
	n     int
}

// add keeps c, unless its body already holds modelCallsPerBody calls here for
// its AI agent: every call still kept counts, finished or not, until its
// answer is collected or it is swept.
//
// No more than modelCallsHeld calls are kept at once across every machine.
func (t *modelCallTable) add(c *modelCall) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.calls == nil {
		t.calls = map[string]*modelCall{}
	}
	n := 0
	for _, o := range t.calls {
		if o.host == c.host && o.agent == c.agent {
			n++
		}
	}
	if n >= modelCallsPerBody || len(t.calls) >= modelCallsHeld {
		return false
	}
	c.buffered = &t.buffered
	t.calls[c.id] = c
	return true
}

func (t *modelCallTable) get(id string) *modelCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls[id]
}

func (t *modelCallTable) remove(id string) {
	t.mu.Lock()
	c := t.calls[id]
	delete(t.calls, id)
	t.mu.Unlock()
	if c != nil {
		c.release()
	}
}

// sweep forgets every finished call nobody has collected for modelCallIdle,
// and lets go of every unfinished one, which is forgotten once it ends: it
// counts against its body until then.
func (t *modelCallTable) sweep(now time.Time) {
	t.mu.Lock()
	var gone, letGo []*modelCall
	for id, c := range t.calls {
		if !c.idle(now) {
			continue
		}
		c.mu.Lock()
		done := c.done
		c.mu.Unlock()
		if done {
			delete(t.calls, id)
			gone = append(gone, c)
		} else {
			letGo = append(letGo, c)
		}
	}
	for h, d := range t.denied {
		if now.Sub(d.since) > time.Minute {
			delete(t.denied, h)
		}
	}
	t.mu.Unlock()
	for _, c := range gone {
		c.stop()
		c.release()
	}
	for _, c := range letGo {
		c.letGo()
	}
}

// keepSweeping sweeps the table every modelCallRecheck for as long as the
// server runs, started once, with the first call.
func (t *modelCallTable) keepSweeping(inBackground func(func(context.Context))) {
	t.sweeping.Do(func() {
		inBackground(func(ctx context.Context) {
			tick := time.NewTicker(modelCallRecheck)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-tick.C:
					t.sweep(now)
				}
			}
		})
	})
}

// mayRecordDenial says whether one more of a body's refusals is recorded this
// minute.
func (t *modelCallTable) mayRecordDenial(host string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.denied == nil {
		t.denied = map[string]*denials{}
	}
	d := t.denied[host]
	if d == nil || now.Sub(d.since) > time.Minute {
		d = &denials{since: now}
		t.denied[host] = d
	}
	d.n++
	return d.n <= modelDenialsRecorded
}

// modelCallError answers a body's model call that was not made.
func modelCallError(w http.ResponseWriter, status int, why string, extra map[string]any) {
	out := map[string]any{"error": why}
	for k, v := range extra {
		out[k] = v
	}
	writeJSONStatus(w, status, out)
}

// heldSignInForCall is the API key a run's model call is made with: the run's
// lease on the sign-in must be open, and the sign-in kept still one that stays
// here. The reason is a sentence the body passes to its brain.
func (s *CoreServer) heldSignInForCall(a asset.Asset, host, lease string, now time.Time) (brainsignin.Record, int, error) {
	held, ok, err := s.lends().Find(lendBrainSignIn, lease, host, a.ID, now)
	if err != nil {
		return brainsignin.Record{}, http.StatusServiceUnavailable, errors.New("what is lent cannot be read now")
	}
	if !ok || !held.IsOpen(now) {
		return brainsignin.Record{}, http.StatusForbidden, errors.New("this run holds no open lease on its AI agent's sign-in")
	}
	vault, err := s.brainVault()
	if err != nil {
		return brainsignin.Record{}, http.StatusServiceUnavailable, errors.New("the AI agent's sign-in cannot be read now")
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	if err != nil {
		return brainsignin.Record{}, http.StatusServiceUnavailable, errors.New("the AI agent's sign-in cannot be read now")
	}
	if !had {
		return brainsignin.Record{}, http.StatusForbidden, errors.New("this AI agent's sign-in was removed")
	}
	if !rec.StaysInVault() {
		return brainsignin.Record{}, http.StatusForbidden, errors.New("this AI agent's sign-in is no longer a key " +
			"the Identity Agent uses itself; the next run borrows the one kept now")
	}
	if rec.Expired(now) {
		return brainsignin.Record{}, http.StatusForbidden, errors.New("this AI agent's sign-in has expired")
	}
	return rec, 0, nil
}

// openLeaseOf is the open lease host holds on a's sign-in, if it holds one.
func (s *CoreServer) openLeaseOf(a asset.Asset, host string, now time.Time) (string, bool) {
	open, err := s.lends().Open(lendBrainSignIn, now)
	if err != nil {
		return "", false
	}
	for _, x := range open {
		if x.Host == host && x.Agent == a.ID && x.IsOpen(now) {
			return x.ID, true
		}
	}
	return "", false
}

// modelAPIBase is where provider's model calls go, without a trailing slash:
// the same addresses a sign-in is checked at.
func (s *CoreServer) modelAPIBase(provider string) (brainsignin.Checker, string, error) {
	c, err := s.brainCheck()
	if err != nil {
		return c, "", err
	}
	switch provider {
	case brainsignin.Anthropic:
		return c, c.Anthropic, nil
	case brainsignin.OpenAI:
		return c, c.OpenAI, nil
	case brainsignin.XAI:
		return c, c.XAI, nil
	case brainsignin.OpenRouter:
		return c, c.OpenRouter, nil
	}
	return c, "", fmt.Errorf("no program a body runs makes model calls to %s", provider)
}

// withTheKey sets the provider's own way of carrying the key.
func withTheKey(h http.Header, rec brainsignin.Record, path string) {
	if rec.Provider == brainsignin.Anthropic {
		h.Set("x-api-key", rec.Secret)
		if h.Get("Anthropic-Version") == "" {
			h.Set("Anthropic-Version", "2023-06-01")
		}
		return
	}
	h.Set("Authorization", "Bearer "+rec.Secret)
	if rec.Provider == brainsignin.OpenRouter {
		h.Set("X-Title", "Identity Agent")
	}
	if strings.HasPrefix(path, "/v1/messages") && h.Get("Anthropic-Version") == "" {
		h.Set("Anthropic-Version", "2023-06-01")
	}
}

// modelCallClient sends a model call: never following a redirect, so the key
// goes only to the provider, and with no limit on how long the answer takes to
// stream beyond modelCallLongest.
func modelCallClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newCallID() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "mc_" + base64.RawURLEncoding.EncodeToString(b)
}

// handleBodyStartsModelCall makes one model call for a body's brain, adding
// the key here, and answers with what has arrived of the answer so far.
func (s *CoreServer) handleBodyStartsModelCall(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q modelCallRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, modelRequestLargest*2)).Decode(&q); err != nil || q.LeaseID == "" {
		modelCallError(w, http.StatusBadRequest, "name the run's lease and the call to make", nil)
		return
	}
	body, err := base64.StdEncoding.DecodeString(q.BodyB64)
	if err != nil || len(body) > modelRequestLargest {
		modelCallError(w, http.StatusRequestEntityTooLarge, "this model call is too large or unreadable", nil)
		return
	}
	now := time.Now().UTC()
	s.modelCalls.keepSweeping(s.inBackground)
	s.modelCalls.sweep(now)
	s.recordLapsedLends()
	refuse := func(status int, why string) {
		s.recordModelCallDenied(a, cc, b.Host, why, now)
		modelCallError(w, status, why, map[string]any{"refused": true})
	}
	if err := s.mayBeLent(a, cc, "its brain's model calls"); err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	rec, code, err := s.heldSignInForCall(a, b.Host, q.LeaseID, now)
	if err != nil {
		refuse(code, err.Error())
		return
	}
	method := strings.ToUpper(q.Method)
	if !modelRouteAllowed(rec.Provider, method, q.Path) {
		refuse(http.StatusForbidden, fmt.Sprintf("%s %s is not a model call a brain signed in with %s may make",
			printable(method, 10), printable(q.Path, 80), rec.Provider))
		return
	}
	query, err := modelCallQuery(q.Query)
	if err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	if err := callsTheChosenModel(a, method, body); err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	checker, base, err := s.modelAPIBase(rec.Provider)
	if err != nil {
		modelCallError(w, http.StatusServiceUnavailable, err.Error(), nil)
		return
	}
	target := base + q.Path
	if query != "" {
		target += "?" + query
	}
	c := &modelCall{id: newCallID(), agent: a.ID, host: b.Host, lease: q.LeaseID, stopCh: make(chan struct{}),
		letGoCh: make(chan struct{}), changed: make(chan struct{}), collected: now}
	if !s.modelCalls.add(c) {
		why := fmt.Sprintf("this machine already holds %d model calls for this AI agent; collect their answers first",
			modelCallsPerBody)
		s.recordModelCallDenied(a, cc, b.Host, why, now)
		modelCallError(w, http.StatusTooManyRequests, why, nil)
		return
	}
	requested := printable(requestedModel(body), 128)
	s.inBackground(func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, modelCallLongest)
		defer cancel()
		go s.watchModelCall(ctx, cancel, c, a, cc, rec)
		s.runModelCall(ctx, c, checker, rec, method, target, q, body, requested, a, cc)
	})
	s.answerCollection(w, r, c, 0, false)
}

// recordModelCallDenied records a refused model call, at most
// modelDenialsRecorded a minute for one body; the rest are refused unrecorded.
func (s *CoreServer) recordModelCallDenied(a asset.Asset, cc sandbox.CallerContext, host, why string, now time.Time) {
	if s.modelCalls.mayRecordDenial(host, now) {
		s.recordLentEvent(a, cc, "agent.model.call", "denied", why)
	}
}

// standingNow is what the AI agent may do now, as a body asking now would be
// told: started stands for the caller as it was when the call began.
func (s *CoreServer) standingNow(a asset.Asset, started sandbox.CallerContext) sandbox.CallerContext {
	now, ok := s.ResolveAgentCaller(a.PairwiseAID)
	if !ok {
		started.NoScopesBecause = "this AI agent is gone"
		return started
	}
	started.Scopes, started.NoScopesBecause = now.Scopes, now.NoScopesBecause
	return started
}

// watchModelCall stops a call under way, and with it the provider's answer and
// what it costs, once the run may no longer make it — the AI agent revoked,
// its grant lapsed or not in force, the sign-in removed or replaced, the
// run's lease ended. A call nobody collects is let go instead, and a call let
// go is stopped only once the AI agent may no longer act or its key is gone:
// its run has ended, and its answer is read to the end for what it cost. It
// checks every modelCallRecheck, whether or not the body collects, and asks
// afresh what the AI agent may do each time.
func (s *CoreServer) watchModelCall(ctx context.Context, cancel context.CancelFunc, c *modelCall, a asset.Asset,
	cc sandbox.CallerContext, rec brainsignin.Record) {
	t := time.NewTicker(modelCallRecheck)
	defer t.Stop()
	letGo := c.letGoCh
	for {
		select {
		case <-c.stopCh:
			cancel()
			return
		case <-ctx.Done():
			return
		case <-letGo:
			// Its run may have ended and returned its lease: a call let go is
			// read to its end all the same, while the AI agent may still act and
			// the key it was made with is still the one kept — checked now, and
			// at every tick after. The channel only wakes this; lettingGo is the
			// state.
			letGo = nil
		case <-t.C:
		}
		now := time.Now().UTC()
		why := ""
		if c.lettingGo.Load() {
			if err := s.mayBeLent(a, s.standingNow(a, cc), "its brain's model calls"); err != nil {
				why = err.Error()
			} else if err := s.stillTheKey(a, rec, now); err != nil {
				why = err.Error()
			}
		} else if c.idle(now) {
			// Nobody collects it: let go, and read to its end for what it cost.
			c.letGo()
			continue
		} else if err := s.mayBeLent(a, s.standingNow(a, cc), "its brain's model calls"); err != nil {
			why = err.Error()
		} else if _, _, err := s.heldSignInForCall(a, c.host, c.currentLease(), now); err != nil {
			// A run whose lease lapsed takes another; the call goes on under
			// it, so long as this body holds one.
			if lease, ok := s.openLeaseOf(a, c.host, now); ok {
				c.mu.Lock()
				c.lease = lease
				c.mu.Unlock()
			} else {
				why = err.Error()
			}
		}
		if why != "" {
			c.finish(why)
			c.stop()
			cancel()
			s.recordLentEvent(a, cc, "agent.model.call", "denied", "an answer under way was stopped: "+why)
			return
		}
	}
}

// answerCollection answers a body with what it has not yet collected of c,
// and forgets c once all of its answer is collected.
func (s *CoreServer) answerCollection(w http.ResponseWriter, r *http.Request, c *modelCall, from int64, haveHead bool) {
	ans, err := c.collect(r.Context(), from, haveHead, modelCallWait)
	if err != nil {
		modelCallError(w, http.StatusConflict, err.Error(), nil)
		return
	}
	if ans.Done {
		s.modelCalls.remove(c.id)
	}
	writeJSONStatus(w, http.StatusOK, ans)
}

// errAnswerCarriesKey is a provider's answer that holds the key itself: a
// provider can quote what it was sent, in an error above all, and the key
// must never reach the brain.
var errAnswerCarriesKey = errors.New("the provider's answer carried the key, so it was not passed on")

// keyWatch passes an answer on with the key cut out of reach: it holds back
// the last len(key)-1 bytes of what has arrived until more comes, so a key
// split across two parts is seen whole before any of it is passed on.
type keyWatch struct {
	key  []byte
	held []byte
}

// next is what may be passed on of what arrived, or errAnswerCarriesKey.
func (k *keyWatch) next(b []byte) ([]byte, error) {
	all := append(k.held, b...)
	if len(k.key) > 0 && bytes.Contains(all, k.key) {
		return nil, errAnswerCarriesKey
	}
	keep := len(k.key) - 1
	if keep < 0 || keep > len(all) {
		keep = len(all)
		if len(k.key) <= 1 {
			keep = 0
		}
	}
	out := all[:len(all)-keep]
	k.held = append([]byte(nil), all[len(all)-keep:]...)
	return out, nil
}

// rest is what was held back, once the answer is complete.
func (k *keyWatch) rest() []byte { return k.held }

// runModelCall sends the call to the provider and keeps its answer for the
// body to collect, then records the call.
func (s *CoreServer) runModelCall(ctx context.Context, c *modelCall, checker brainsignin.Checker, rec brainsignin.Record,
	method, target string, q modelCallRequest, body []byte, requested string, a asset.Asset, cc sandbox.CallerContext) {
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		c.finish("the model call could not be made")
		return
	}
	for _, name := range brainsignin.ModelCallHeaders {
		for k, v := range q.Header {
			if strings.EqualFold(k, name) && v != "" {
				req.Header.Set(name, v)
			}
		}
	}
	withTheKey(req.Header, rec, q.Path)
	started := time.Now()
	resp, err := checker.Send(ctx, req, modelCallClient())
	if err != nil {
		why := "the model's provider could not be reached"
		if strings.Contains(err.Error(), "auto_blocked") || strings.Contains(err.Error(), "held") {
			why = "this Identity Agent's owner does not allow calls to " + req.URL.Hostname()
		}
		c.finish(why)
		s.recordLentEvent(a, cc, "agent.model.call", "failed", fmt.Sprintf("%s %s for %s: %s", method, q.Path, rec.Provider, why))
		return
	}
	defer resp.Body.Close()
	h := map[string]string{}
	for _, name := range modelResponseHeaders {
		if v := resp.Header.Get(name); v != "" && !strings.Contains(v, rec.Secret) {
			h[name] = v
		}
	}
	c.head(resp.StatusCode, h)
	var use modelUsage
	use.model = requested
	watch := keyWatch{key: []byte(rec.Secret)}
	buf := make([]byte, 32<<10)
	why := ""
	var afterLetGo int64
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 && c.lettingGo.Load() {
			if afterLetGo += int64(n); afterLetGo > modelCallLetGoLargest {
				why = "its brain let it go, and its answer ran longer than one let go is read; what it cost is not all known"
				break
			}
		}
		if n > 0 {
			use.feed(buf[:n])
			out, kerr := watch.next(buf[:n])
			if kerr != nil {
				why = kerr.Error()
				break
			}
			if len(out) > 0 && !c.add(out) {
				why = "the brain was not reading the model's answer"
				break
			}
		}
		if rerr == io.EOF {
			if rest := watch.rest(); len(rest) > 0 && !c.add(rest) {
				why = "the brain was not reading the model's answer"
			}
			break
		}
		if rerr != nil {
			why = "the model's answer was cut off"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				why = "the model's answer took longer than a model call may"
			} else if ctx.Err() != nil {
				why = "the call was stopped"
			}
			break
		}
	}
	use.end()
	c.finish(why)
	letGo := c.lettingGo.Load()
	if letGo {
		s.modelCalls.remove(c.id)
	}
	status := "ok"
	if resp.StatusCode >= 400 || why != "" {
		status = "failed"
	}
	said := fmt.Sprintf("%s %s for %s, model %s, answered %d in %s%s", method, q.Path, rec.Provider,
		firstNonEmptyString(printable(use.model, 128), "not named"), resp.StatusCode,
		time.Since(started).Round(time.Millisecond), use.String())
	if letGo {
		said += "; its brain let it go, and its answer was read to the end for what it cost"
	}
	if why != "" {
		said += "; " + why
	}
	s.recordLentEvent(a, cc, "agent.model.call", status, said)
}

// theCallAsked is the model call a body names, if it is that body's own. A
// call this Identity Agent does not know — it was restarted, or the call was
// stopped — is answered as gone, which the body tells its brain as a failed
// call to try again.
func (s *CoreServer) theCallAsked(w http.ResponseWriter, r *http.Request) (*modelCall, sandbox.CallerContext, asset.Asset, bool) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return nil, cc, a, false
	}
	c := s.modelCalls.get(chi.URLParam(r, "call"))
	if c == nil || c.agent != a.ID || c.host != b.Host {
		modelCallError(w, http.StatusGone, "this model call is no longer under way here; make it again",
			map[string]any{"no_call": true})
		return nil, cc, a, false
	}
	return c, cc, a, true
}

// handleBodyReadsModelCall answers with what has arrived of a call's answer
// since what the body last collected, waiting a while for more. A body whose
// run took a new lease, after its first lapsed, names it.
func (s *CoreServer) handleBodyReadsModelCall(w http.ResponseWriter, r *http.Request) {
	c, cc, a, ok := s.theCallAsked(w, r)
	if !ok {
		return
	}
	var from int64
	if _, err := fmt.Sscan(r.URL.Query().Get("from"), &from); err != nil || from < 0 {
		from = 0
	}
	now := time.Now().UTC()
	s.modelCalls.sweep(now)
	if lease := r.URL.Query().Get("lease"); lease != "" && lease != c.currentLease() {
		if _, _, err := s.heldSignInForCall(a, c.host, lease, now); err != nil {
			modelCallError(w, http.StatusForbidden, err.Error(), map[string]any{"refused": true})
			return
		}
		c.mu.Lock()
		c.lease = lease
		c.mu.Unlock()
	}
	if err := s.mayBeLent(a, cc, "its brain's model calls"); err != nil {
		c.finish(err.Error())
		c.stop()
		s.modelCalls.remove(c.id)
		modelCallError(w, http.StatusForbidden, err.Error(), map[string]any{"refused": true})
		return
	}
	s.answerCollection(w, r, c, from, r.URL.Query().Get("head") == "1")
}

// handleBodyStopsModelCall lets go of a call whose brain gave up on it: none
// of the rest of its answer is passed on, but the answer is read to its end, so
// what the call cost is recorded. The call counts against its body until then.
func (s *CoreServer) handleBodyStopsModelCall(w http.ResponseWriter, r *http.Request) {
	c, _, _, ok := s.theCallAsked(w, r)
	if !ok {
		return
	}
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done {
		s.modelCalls.remove(c.id)
	} else {
		c.letGo()
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"stopped": true})
}

// requestedModel is the model a call's request names, if it names one.
func requestedModel(body []byte) string {
	var q struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &q)
	return q.Model
}

// callsTheChosenModel refuses a model call that names a model other than the
// one chosen for the AI agent, or none, or more than one: a program's own
// default or helper model would otherwise be called, and paid for, unasked.
// An AI agent with no model chosen makes whatever calls its program does.
// Only a POST is a model call; a list of models, or one model asked about by
// name, costs nothing.
func callsTheChosenModel(a asset.Asset, method string, body []byte) error {
	if a.AgentConfig == nil || method != http.MethodPost {
		return nil
	}
	chosen := strings.TrimSpace(a.AgentConfig.Brain.Model)
	if chosen == "" {
		return nil
	}
	named, err := theModelNamed(body)
	if err != nil {
		return fmt.Errorf("this AI agent calls only its chosen model, %s; %s", printable(chosen, 128), err.Error())
	}
	if named != chosen {
		return fmt.Errorf("this AI agent calls only its chosen model, %s; this call named %s",
			printable(chosen, 128), printable(firstNonEmptyString(named, "no model"), 128))
	}
	return nil
}

// theModelNamed is the one model a call's request names, read the way a
// provider reads it: the request must be one JSON object naming its model once,
// as "model" exactly. A provider's parser and this one could otherwise read a
// different model from the same bytes — a second "model", or one spelt
// "Model", which Go would read case-blind and a provider would not — and what
// is checked would not be what is sent. A list of models to fall back on is
// refused outright.
func theModelNamed(body []byte) (string, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return "", errors.New("this call is not one JSON object, so which model it calls is not known")
	}
	named, seen := "", false
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return "", errors.New("this call could not be read, so which model it calls is not known")
		}
		k, _ := t.(string)
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return "", errors.New("this call could not be read, so which model it calls is not known")
		}
		switch {
		case strings.EqualFold(k, "models"):
			return "", errors.New("this call names a list of models to fall back on")
		case !strings.EqualFold(k, "model"):
			continue
		case k != "model" || seen:
			return "", errors.New("this call names its model more than once, or not as \"model\"")
		}
		seen = true
		if err := json.Unmarshal(v, &named); err != nil {
			return "", errors.New("this call's model is not a name")
		}
	}
	if _, err := d.Token(); err != nil {
		return "", errors.New("this call could not be read, so which model it calls is not known")
	}
	if _, err := d.Token(); err != io.EOF {
		return "", errors.New("this call is not one JSON object, so which model it calls is not known")
	}
	return named, nil
}

// stillTheKey says whether the key a call was made with is still the AI
// agent's sign-in, kept here and in force.
func (s *CoreServer) stillTheKey(a asset.Asset, made brainsignin.Record, now time.Time) error {
	vault, err := s.brainVault()
	if err != nil {
		return errors.New("the AI agent's sign-in cannot be read now")
	}
	rec, had, err := vault.BrainSignIn(brainsignin.Ref(a.ID))
	switch {
	case err != nil:
		return errors.New("the AI agent's sign-in cannot be read now")
	case !had:
		return errors.New("this AI agent's sign-in was removed")
	case rec.Secret != made.Secret || !rec.StaysInVault():
		return errors.New("this AI agent's sign-in was replaced")
	case rec.Expired(now):
		return errors.New("this AI agent's sign-in has expired")
	}
	return nil
}

// modelUsage is what the provider says a call used, read from its answer as
// it passes: the tokens in and out, and the cost where the provider says it
// (OpenRouter does). Every provider's shape is read the same way — each
// "usage" object's counts, keeping the largest seen of each — because an
// answer that streams reports them across several events.
type modelUsage struct {
	model             string
	in, out, cacheIn  int64
	cost              float64
	line, whole       []byte
	sse               bool
	sawData, tooLarge bool
}

func (u *modelUsage) feed(b []byte) {
	if !u.sawData {
		u.sawData = true
		u.sse = bytes.HasPrefix(bytes.TrimLeft(b, " \r\n"), []byte("event:")) ||
			bytes.HasPrefix(bytes.TrimLeft(b, " \r\n"), []byte("data:")) ||
			bytes.HasPrefix(bytes.TrimLeft(b, " \r\n"), []byte(":"))
	}
	if !u.sse {
		if len(u.whole)+len(b) <= 1<<20 {
			u.whole = append(u.whole, b...)
		} else {
			u.tooLarge = true
		}
		return
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if len(u.line)+len(b) <= 1<<20 {
				u.line = append(u.line, b...)
			}
			return
		}
		u.line = append(u.line, b[:i]...)
		u.event(u.line)
		u.line = u.line[:0]
		b = b[i+1:]
	}
}

func (u *modelUsage) event(line []byte) {
	data, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
	if !ok {
		return
	}
	u.read(bytes.TrimSpace(data))
}

func (u *modelUsage) end() {
	if u.sse {
		if len(u.line) > 0 {
			u.event(u.line)
		}
		return
	}
	if !u.tooLarge {
		u.read(u.whole)
	}
}

func (u *modelUsage) read(b []byte) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return
	}
	u.walk(v, 0)
}

func (u *modelUsage) walk(v any, depth int) {
	if depth > 6 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if m, ok := t["model"].(string); ok && m != "" {
			u.model = m
		}
		if use, ok := t["usage"].(map[string]any); ok {
			u.counts(use)
		}
		for k, x := range t {
			if k != "usage" {
				u.walk(x, depth+1)
			}
		}
	case []any:
		for _, x := range t {
			u.walk(x, depth+1)
		}
	}
}

func (u *modelUsage) counts(use map[string]any) {
	most := func(dst *int64, keys ...string) {
		for _, k := range keys {
			if f, ok := use[k].(float64); ok && int64(f) > *dst {
				*dst = int64(f)
			}
		}
	}
	most(&u.in, "prompt_tokens", "input_tokens")
	most(&u.out, "completion_tokens", "output_tokens")
	most(&u.cacheIn, "cache_read_input_tokens")
	if f, ok := use["cost"].(float64); ok && f > u.cost {
		u.cost = f
	}
}

// String is the usage as the record says it, or nothing when the provider
// said nothing.
func (u *modelUsage) String() string {
	if u.in == 0 && u.out == 0 && u.cost == 0 {
		return ""
	}
	s := fmt.Sprintf("; %d tokens in, %d out", u.in, u.out)
	if u.cacheIn > 0 {
		s += fmt.Sprintf(", %d read from cache", u.cacheIn)
	}
	if u.cost > 0 {
		s += fmt.Sprintf(", cost %.6f in the provider's currency", u.cost)
	}
	return s
}

// answersOnly reports whether a only reads and answers: its brain runs no
// program, so its body is lent nothing a program would use, and it answers
// only whoever asked it. What it may do is still its grant's to say.
func answersOnly(a asset.Asset) bool {
	return a.AgentConfig != nil && a.AgentConfig.Brain.Program == brainsignin.ProgramNone
}
