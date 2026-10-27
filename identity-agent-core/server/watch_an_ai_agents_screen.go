package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/sandbox"
	"identity-agent-core/screenview"

	"github.com/go-chi/chi/v5"
)

// Watching an AI agent's screen, and taking control of it.
//
// The screen travels the way the AI agent's messages already do: the body
// keeps a sealed connection open to this Identity Agent, and a person reaches
// this Identity Agent from their app. Neither end reaches the other directly,
// so watching needs no open port on the AI agent's machine, no remote-desktop
// program and no particular network.
//
// Two actions, each passed through the one check by the router before a
// handler here runs:
//
//   - watching: opening a viewing, fetching its pictures and ending it, at the
//     default minimum score;
//   - taking control: turning control on or off and sending clicks and keys,
//     at the score set for taking control (the default unless the owner raises it),
//     and never from a browser session.
//
// A viewing belongs to whoever opened it and to one body of one AI agent. Each
// start and end of watching, and of control, is written to the signed
// governance record.

// The routes, keyed as the router gate keys them.
const (
	routeScreenControl = "POST /api/mcp/agents/{id}/screen/{sid}/control"
	routeScreenInput   = "POST /api/mcp/agents/{id}/screen/{sid}/input"
)

// Every request from the app here carries a "nonce" in its body, which nothing
// reads. A controller's signature covers the path, the second it was made and
// the body, and a signed request is taken once, so two identical requests in
// one second — two fetches of the screen, two identical clicks — would
// otherwise be refused as a replay of the first.

// fetchWait is how long one fetch waits for a newer picture. Short, so the
// app's next fetch, which is what keeps a viewing open, comes well inside
// screenview.IdleAfter.
const fetchWait = 3 * time.Second

var screenHubs sync.Map

// screens is this Identity Agent's viewings.
func (s *CoreServer) screens() *screenview.Hub {
	dir, err := filepath.Abs(s.DataDir)
	if err != nil {
		dir = s.DataDir
	}
	if v, ok := screenHubs.Load(dir); ok {
		return v.(*screenview.Hub)
	}
	h := &screenview.Hub{}
	h.OnEnd = func(v screenview.Viewing) { s.recordViewingEnded(v) }
	v, _ := screenHubs.LoadOrStore(dir, h)
	return v.(*screenview.Hub)
}

func (s *CoreServer) mountScreenRoutes(r chi.Router) {
	// A person, from a paired app.
	r.Get("/mcp/agent-screens", s.handleListAgentScreens)
	r.Post("/mcp/agents/{id}/screen", s.handleOpenViewing)
	r.Post("/mcp/agents/{id}/screen/{sid}/picture", s.handleFetchScreen)
	r.Delete("/mcp/agents/{id}/screen/{sid}", s.handleEndViewing)
	r.Post("/mcp/agents/{id}/screen/{sid}/control", s.handleTakeControl)
	r.Post("/mcp/agents/{id}/screen/{sid}/input", s.handleSendInput)
	// A body, signed by its machine key and sealed to this Identity Agent.
	r.Post("/agent-host/screen", s.handleBodyAwaitsViewer)
	r.Post("/agent-host/screen/frame", s.handleBodySendsFrame)
}

// ── Who is watching ──────────────────────────────────────────────────────────

// theViewer is who is asking, as a viewing is tied to them and as the record
// names them: the authorised machine that signed the request, a browser
// session, or the owner.
func (s *CoreServer) theViewer(r *http.Request) (string, sandbox.CallerContext) {
	cc := sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r)}
	if g, ok := TheControllerThatAsked(r); ok {
		cc.CallerAID, cc.Transport = g.ControllerAID, "controller"
		return "controller:" + g.ControllerAID, cc
	}
	if s.hasBrowserSession(r) {
		// Named by a digest of the session, never the session itself, which
		// is a bearer secret.
		sum := sha256.Sum256([]byte(bearerToken(r)))
		cc.CallerAID, cc.Transport = "browser-session:"+hex.EncodeToString(sum[:8]), "browser_session"
		return cc.CallerAID, cc
	}
	cc.Transport = "owner"
	cc.CallerAID = "owner"
	if owner, ok := s.theOwner(); ok {
		cc.CallerAID = owner
	}
	return "owner", cc
}

// screenOf is what the app is told about a body's screen, or nil when it has
// none that can be watched now.
type screenOf struct {
	Available  bool `json:"available"`
	CanControl bool `json:"can_control"`
	Width      int  `json:"width"`
	Height     int  `json:"height"`
}

func (s *CoreServer) screenOfBody(b agentbody.Binding) *screenOf {
	if b.State != agentbody.StateActive {
		return nil
	}
	sc, ok := s.screens().Available(b.Host)
	if !ok {
		return nil
	}
	return &screenOf{Available: true, CanControl: sc.CanControl, Width: sc.Width, Height: sc.Height}
}

// handleListAgentScreens says which AI agents have a machine whose screen can
// be watched now, so the app offers the button only on those.
func (s *CoreServer) handleListAgentScreens(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	if s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.AssetType != "ai_agent" {
				continue
			}
			for _, b := range s.bodies().ForAgent(a.ID) {
				if sc := s.screenOfBody(b); sc != nil {
					out[a.ID] = map[string]any{"has_screen": true, "can_control": sc.CanControl}
					break
				}
			}
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"agents": out})
}

// ── Watching ────────────────────────────────────────────────────────────────

// refuseViewing writes a refusal to the record and answers with it.
func (s *CoreServer) refuseViewing(w http.ResponseWriter, cc sandbox.CallerContext, event, why, reason string, status int) {
	log.Printf("[screen] refused %s to %s: %s", event, cc.CallerAID, why)
	if s.SandboxManager != nil {
		cc.Reason = clampWhy(why)
		s.SandboxManager.RecordGovernanceEvent(cc, event, "denied")
	}
	body := map[string]string{"error": why}
	if reason != "" {
		body["reason"] = reason
	}
	writeJSONStatus(w, status, body)
}

func (s *CoreServer) handleOpenViewing(w http.ResponseWriter, r *http.Request) {
	viewer, cc := s.theViewer(r)
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		s.refuseViewing(w, cc, "agent.screen.watch", "AI agent not found", "", http.StatusNotFound)
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if raw, err := readSignedBody(r); err == nil && len(raw) > 0 {
		if json.Unmarshal(raw, &req) != nil {
			jsonError(w, "the request must be JSON", http.StatusBadRequest)
			return
		}
	}
	// The body watched: the one asked for, or the AI agent's live body that
	// most recently said it has a screen.
	var chosen *agentbody.Binding
	bodies := s.bodies().ForAgent(a.ID)
	sort.SliceStable(bodies, func(i, j int) bool { return bodies[i].DecidedAt.After(bodies[j].DecidedAt) })
	for i := range bodies {
		b := bodies[i]
		if req.Body != "" && b.ID != req.Body {
			continue
		}
		if s.screenOfBody(b) != nil {
			chosen = &b
			break
		}
	}
	if chosen == nil {
		s.refuseViewing(w, cc, "agent.screen.watch", a.DisplayName+"'s machine has no screen that can be watched now",
			"no_screen", http.StatusConflict)
		return
	}
	v, err := s.screens().Open(a.ID, chosen.ID, chosen.Host, viewer)
	switch {
	case errors.Is(err, screenview.ErrTooMany):
		s.refuseViewing(w, cc, "agent.screen.watch", err.Error(), "too_many", http.StatusTooManyRequests)
		return
	case err != nil:
		s.refuseViewing(w, cc, "agent.screen.watch", a.DisplayName+"'s machine has no screen that can be watched now",
			"no_screen", http.StatusConflict)
		return
	}
	s.recordViewing(cc, v, "agent.screen.watch.started",
		fmt.Sprintf("started watching the screen of %s (%s) on its body %s", a.DisplayName, a.PairwiseAID, v.Host))
	writeJSONStatus(w, http.StatusCreated, map[string]any{"session": v.ID, "body": v.Body, "state": "waiting"})
}

// viewingAnswer is a refusal from the hub as the app is told it.
func viewingAnswer(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, screenview.ErrEnded):
		writeJSONStatus(w, http.StatusOK, map[string]any{"state": "ended"})
	case errors.Is(err, screenview.ErrNotYours):
		jsonError(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, screenview.ErrNotInControl), errors.Is(err, screenview.ErrCannotControl):
		jsonError(w, err.Error(), http.StatusConflict)
	case errors.Is(err, screenview.ErrQueueFull):
		jsonError(w, err.Error(), http.StatusTooManyRequests)
	default:
		jsonError(w, err.Error(), http.StatusBadRequest)
	}
}

func (s *CoreServer) handleFetchScreen(w http.ResponseWriter, r *http.Request) {
	viewer, _ := s.theViewer(r)
	agent, sid := chi.URLParam(r, "id"), chi.URLParam(r, "sid")
	var req struct {
		After int `json:"after"`
	}
	if raw, err := readSignedBody(r); err != nil || (len(raw) > 0 && json.Unmarshal(raw, &req) != nil) {
		jsonError(w, `ask as {"after": the number of the picture you have}`, http.StatusBadRequest)
		return
	}
	after := req.After
	hub := s.screens()
	seen, err := hub.Fetch(r.Context(), sid, viewer, agent, after, fetchWait)
	if err != nil {
		viewingAnswer(w, err)
		return
	}
	// A body revoked mid-viewing is no longer the AI agent's: what it shows is
	// not the AI agent's screen any more.
	if b, ok := s.bodies().Get(seen.Viewing.Body); !ok || b.State != agentbody.StateActive {
		hub.EndBody(seen.Viewing.Host, "the machine is no longer this AI agent's body")
		writeJSONStatus(w, http.StatusOK, map[string]any{"state": "ended"})
		return
	}
	out := map[string]any{
		"state": "waiting", "seq": after, "control": seen.Viewing.Control, "can_control": seen.CanControl,
	}
	if seen.Frame != nil {
		out["state"] = "watching"
		out["seq"] = seen.Frame.Seq
		out["width"], out["height"] = seen.Frame.Width, seen.Frame.Height
		out["image"] = base64.StdEncoding.EncodeToString(seen.Frame.Image)
	} else if after > 0 {
		// Nothing newer, but the viewer already has a picture.
		out["state"] = "watching"
	}
	writeJSONStatus(w, http.StatusOK, out)
}

func (s *CoreServer) handleEndViewing(w http.ResponseWriter, r *http.Request) {
	viewer, _ := s.theViewer(r)
	_, err := s.screens().End(chi.URLParam(r, "sid"), viewer, chi.URLParam(r, "id"), "the person closed the window")
	if err != nil && !errors.Is(err, screenview.ErrEnded) {
		viewingAnswer(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"ended": true})
}

// ── Taking control ──────────────────────────────────────────────────────────

func (s *CoreServer) handleTakeControl(w http.ResponseWriter, r *http.Request) {
	viewer, cc := s.theViewer(r)
	var req struct {
		On *bool `json:"on"`
	}
	raw, err := readSignedBody(r)
	if err != nil || json.Unmarshal(raw, &req) != nil || req.On == nil {
		jsonError(w, `say {"on": true} to take control, or {"on": false} to give it back`, http.StatusBadRequest)
		return
	}
	agent, sid := chi.URLParam(r, "id"), chi.URLParam(r, "sid")
	hub := s.screens()
	before, err := hub.Get(sid, viewer, agent)
	if err != nil {
		viewingAnswer(w, err)
		return
	}
	v, err := hub.Control(sid, viewer, agent, *req.On)
	if err != nil {
		if errors.Is(err, screenview.ErrCannotControl) {
			cc.WorkItem = sid
			s.refuseViewing(w, cc, "agent.screen.control", err.Error(), "cannot_control", http.StatusConflict)
			return
		}
		viewingAnswer(w, err)
		return
	}
	name := agent
	if a, ok := s.aiAgentAsset(agent); ok {
		name = a.DisplayName + " (" + a.PairwiseAID + ")"
	}
	switch {
	case v.Control && !before.Control:
		s.recordViewing(cc, v, "agent.screen.control.started",
			fmt.Sprintf("took control of the screen of %s on its body %s", name, v.Host))
	case !v.Control && before.Control:
		s.recordViewing(cc, v, "agent.screen.control.ended",
			fmt.Sprintf("gave back control of the screen of %s on its body %s", name, v.Host))
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"control": v.Control})
}

func (s *CoreServer) handleSendInput(w http.ResponseWriter, r *http.Request) {
	viewer, _ := s.theViewer(r)
	var req struct {
		Events []screenview.Event `json:"events"`
	}
	raw, err := readSignedBody(r)
	if err != nil || json.Unmarshal(raw, &req) != nil {
		jsonError(w, "the clicks and keys are unreadable", http.StatusBadRequest)
		return
	}
	n, err := s.screens().Send(chi.URLParam(r, "sid"), viewer, chi.URLParam(r, "id"), req.Events)
	if err != nil {
		viewingAnswer(w, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"queued": n})
}

// ── The record ──────────────────────────────────────────────────────────────

func (s *CoreServer) recordViewing(cc sandbox.CallerContext, v screenview.Viewing, event, why string) {
	log.Printf("[screen] %s: %s", cc.CallerAID, why)
	if s.SandboxManager == nil {
		return
	}
	cc.WorkItem = v.ID
	cc.Reason = clampWhy(why)
	s.SandboxManager.RecordGovernanceEvent(cc, event, "ok")
}

// recordViewingEnded records a viewing that ended, and the control given up
// with it, under the viewer who opened it.
func (s *CoreServer) recordViewingEnded(v screenview.Viewing) {
	cc := sandbox.CallerContext{Remote: true, CallerAID: v.Viewer}
	switch {
	case len(v.Viewer) > len("controller:") && v.Viewer[:len("controller:")] == "controller:":
		cc.CallerAID, cc.Transport = v.Viewer[len("controller:"):], "controller"
	case v.Viewer == "owner":
		cc.Transport = "owner"
		if owner, ok := s.theOwner(); ok {
			cc.CallerAID = owner
		}
	default:
		cc.Transport = "browser_session"
	}
	name := v.Agent
	if a, ok := s.aiAgentAsset(v.Agent); ok {
		name = a.DisplayName + " (" + a.PairwiseAID + ")"
	}
	took := v.Ended.Sub(v.Started).Round(time.Second)
	if v.Control {
		s.recordViewing(cc, v, "agent.screen.control.ended",
			fmt.Sprintf("control of the screen of %s on its body %s ended with the viewing: %s", name, v.Host, v.EndedBecause))
	}
	s.recordViewing(cc, v, "agent.screen.watch.ended",
		fmt.Sprintf("stopped watching the screen of %s on its body %s after %s: %s", name, v.Host, took, v.EndedBecause))
}

// ── A body ──────────────────────────────────────────────────────────────────

// handleBodyAwaitsViewer is a body saying what screen it has, and waiting,
// for up to screenview.WaitLimit, for somebody to watch it.
func (s *CoreServer) handleBodyAwaitsViewer(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	var req struct {
		Screen *screenview.Screen `json:"screen"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		jsonError(w, "the screen's description is unreadable", http.StatusBadRequest)
		return
	}
	if req.Screen != nil {
		if err := req.Screen.Check(); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	hub := s.screens()
	hub.Advertise(b.Host, b.AgentAssetID, req.Screen)
	watched := req.Screen != nil && hub.WaitForViewer(r.Context(), b.Host, screenview.WaitLimit)
	if req.Screen == nil {
		hub.EndBody(b.Host, "the machine no longer has a screen")
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"watch": watched, "fps": screenview.FramesPerSecond})
}

// handleBodySendsFrame takes a picture of a body's screen, or its word that
// nothing changed, and hands back whether to keep going and the clicks and
// keys to act on.
func (s *CoreServer) handleBodySendsFrame(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	var req struct {
		Width  int    `json:"width"`
		Height int    `json:"height"`
		Image  string `json:"image"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, screenview.MaxImage*4/3+16<<10)).Decode(&req); err != nil {
		jsonError(w, "the picture is unreadable", http.StatusBadRequest)
		return
	}
	f := screenview.Frame{Width: req.Width, Height: req.Height}
	if req.Image != "" {
		if f.Image, err = base64.StdEncoding.DecodeString(req.Image); err != nil {
			jsonError(w, "the picture is not base64", http.StatusBadRequest)
			return
		}
	}
	out, err := s.screens().Post(b.Host, b.AgentAssetID, f)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	events := out.Events
	if events == nil {
		events = []screenview.Event{}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"keep_going": out.KeepGoing, "control": out.Control, "events": events})
}
