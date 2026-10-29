package agenthost

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/brainsignin"
)

// The model address of a brain whose key stays with the Identity Agent.
//
// Such a brain is never given its key. It is pointed at this body's model
// address, on the same loopback server as the host's tools, with a token good
// for its run alone. The body passes each call to the Identity Agent, sealed
// and signed like everything it sends, and the Identity Agent adds the key.
// The answer is collected as it arrives and written straight on to the brain,
// so an answer that streams still streams.

// modelCallsThroughIdentityAgent is what a body says, when it borrows, to say
// it makes its brain's model calls through the Identity Agent.
const modelCallsThroughIdentityAgent = "through_identity_agent"

// modelPath is where the model address starts on the host's loopback server.
const modelPath = "/model"

// modelRequestLargest bounds one model call's request: it travels to the
// Identity Agent sealed, base64-encoded three times over, in an envelope of
// at most 8 MB, which the Identity Agent holds it to as well.
const modelRequestLargest = 3 << 20

// openModel gives a borrowed sign-in whose key stays with the Identity Agent
// this body's model address, and a token good for its run.
func (ts *toolServer) openModel(b *Borrowed) {
	t := make([]byte, 24)
	if _, err := rand.Read(t); err != nil {
		panic(err)
	}
	tok := "ahm-" + base64.RawURLEncoding.EncodeToString(t)
	ts.mu.Lock()
	if ts.model == nil {
		ts.model = map[string]*Borrowed{}
	}
	ts.model[tok] = b
	ts.mu.Unlock()
	b.modelURL, b.modelToken = ts.url()+modelPath, tok
}

// shutModel withdraws a run's model token once the run has ended.
func (ts *toolServer) shutModel(b *Borrowed) {
	if b == nil || b.modelToken == "" {
		return
	}
	ts.mu.Lock()
	delete(ts.model, b.modelToken)
	ts.mu.Unlock()
}

// modelFor is the run a model call's token is for: given as a bearer token,
// as Claude Code and OpenAI's clients send it, or as Anthropic's key header.
func (ts *toolServer) modelFor(r *http.Request) *Borrowed {
	tok := r.Header.Get("X-Api-Key")
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && strings.TrimSpace(v) != "" {
		tok = strings.TrimSpace(v)
	}
	if tok == "" {
		return nil
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for k, b := range ts.model {
		if subtle.ConstantTimeCompare([]byte(k), []byte(tok)) == 1 {
			return b
		}
	}
	return nil
}

// modelAnswer is what the body collects of a call from the Identity Agent.
type modelAnswer struct {
	CallID  string            `json:"call_id"`
	Status  int               `json:"status"`
	Header  map[string]string `json:"header"`
	DataB64 string            `json:"data_b64"`
	Next    int64             `json:"next"`
	Done    bool              `json:"done"`
	Error   string            `json:"error"`
}

// modelError answers a brain's model call that was not made, in the shape its
// program reads: Anthropic's for its messages, OpenAI's otherwise.
func modelError(w http.ResponseWriter, path string, status int, why string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if strings.HasPrefix(path, "/v1/messages") {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "error",
			"error": map[string]string{"type": "api_error", "message": why}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": why, "type": "api_error"}})
}

// serveModel passes one of the brain's model calls to the Identity Agent and
// writes its answer on as it arrives.
func (ts *toolServer) serveModel(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, modelPath)
	b := ts.modelFor(r)
	if b == nil {
		modelError(w, path, http.StatusUnauthorized, "this run has ended")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, modelRequestLargest+1))
	if err != nil {
		modelError(w, path, http.StatusBadRequest, "the model call could not be read")
		return
	}
	if len(body) > modelRequestLargest {
		modelError(w, path, http.StatusRequestEntityTooLarge, "this model call is larger than one may be")
		return
	}
	header := map[string]string{}
	for _, name := range brainsignin.ModelCallHeaders {
		if v := r.Header.Get(name); v != "" {
			header[name] = v
		}
	}
	q, _ := json.Marshal(map[string]any{"lease_id": b.lease(), "method": r.Method, "path": path,
		"query": r.URL.RawQuery, "header": header, "body_b64": base64.StdEncoding.EncodeToString(body)})
	ctx := r.Context()
	code, out, err := ts.h.CallContext(ctx, "POST", "/api/agent-host/model-calls", q)
	if err != nil {
		modelError(w, path, http.StatusBadGateway, "the Identity Agent could not be reached for this model call")
		return
	}
	var a modelAnswer
	if code != http.StatusOK || json.Unmarshal(out, &a) != nil || a.CallID == "" {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(out, &e)
		status := code
		if status == http.StatusOK || status == 0 {
			status = http.StatusBadGateway
		}
		modelError(w, path, status, firstNonEmpty(e.Error, "the Identity Agent did not make this model call"))
		return
	}
	flusher, _ := w.(http.Flusher)
	wrote := false
	for {
		if !wrote && a.Status != 0 {
			for k, v := range a.Header {
				w.Header().Set(k, v)
			}
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(a.Status)
			wrote = true
		}
		if a.DataB64 != "" && wrote {
			data, derr := base64.StdEncoding.DecodeString(a.DataB64)
			if derr != nil {
				ts.stopModelCall(a.CallID)
				return
			}
			if _, werr := w.Write(data); werr != nil {
				ts.stopModelCall(a.CallID)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if a.Done {
			if !wrote {
				modelError(w, path, http.StatusBadGateway, firstNonEmpty(a.Error, "the model gave no answer"))
			}
			return
		}
		next := a.Next
		// The run's lease is named each time: one that lapsed is replaced
		// while the call goes on.
		u := "/api/agent-host/model-calls/" + url.PathEscape(a.CallID) + "?from=" + strconv.FormatInt(next, 10) +
			"&lease=" + url.QueryEscape(b.lease())
		if wrote {
			u += "&head=1"
		}
		code, out, err = ts.h.CallContext(ctx, "GET", u, nil)
		if ctx.Err() != nil {
			// The brain gave up on the call.
			ts.stopModelCall(a.CallID)
			return
		}
		var more modelAnswer
		if err != nil || code != http.StatusOK || json.Unmarshal(out, &more) != nil {
			why := "the Identity Agent could not be reached for the rest of this model call"
			var e struct {
				Error string `json:"error"`
			}
			if err == nil && json.Unmarshal(out, &e) == nil && e.Error != "" {
				why = e.Error
			}
			if !wrote {
				// The call is gone or could not be collected: to the brain that
				// is a failed call to make again, never a missing address.
				status := code
				if err != nil || status == http.StatusOK || status == 0 || status == http.StatusGone ||
					status == http.StatusNotFound || status == http.StatusConflict {
					status = http.StatusBadGateway
				}
				modelError(w, path, status, why)
			}
			// An answer already under way can only be cut off; the brain sees it
			// end early.
			ts.stopModelCall(a.CallID)
			return
		}
		a = more
	}
}

// stopModelCall tells the Identity Agent the brain gave up on a call.
func (ts *toolServer) stopModelCall(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = ts.h.CallContext(ctx, "DELETE", "/api/agent-host/model-calls/"+url.PathEscape(id), nil)
}

// envThroughIdentityAgent is the environment of a brain whose key stays with
// the Identity Agent: the program pointed at this body's model address, with
// the run's token where it would read a key. No key is in it.
func (b *Borrowed) envThroughIdentityAgent(harness string) ([]string, error) {
	if b.modelURL == "" || b.modelToken == "" {
		return nil, errors.New("this machine gave the run no model address, so a brain whose key stays with its " +
			"Identity Agent cannot run")
	}
	v1 := b.modelURL + "/v1"
	switch {
	case harness == brainsignin.HarnessClaudeCode && b.Provider == brainsignin.Anthropic:
		// Claude Code adds /v1/messages to its base address, and sends an auth
		// token as a bearer token.
		return []string{"ANTHROPIC_BASE_URL=" + b.modelURL, "ANTHROPIC_AUTH_TOKEN=" + b.modelToken}, nil
	case harness == brainsignin.HarnessGrok && b.Provider == brainsignin.XAI:
		// Grok's own models, at the address its xAI API is reached at.
		return []string{"XAI_API_KEY=" + b.modelToken, "GROK_XAI_API_BASE_URL=" + v1,
			b.homeEnv(brainHome{Var: "GROK_HOME"})}, nil
	case harness == brainsignin.HarnessCodex && b.Provider == brainsignin.OpenAI:
		return []string{"CODEX_API_KEY=" + b.modelToken, "OPENAI_BASE_URL=" + v1,
			b.homeEnv(brainHome{Var: "CODEX_HOME"})}, nil
	}
	return nil, fmt.Errorf("this machine cannot yet run a %s key for %s through its Identity Agent", b.Kind, b.Provider)
}
