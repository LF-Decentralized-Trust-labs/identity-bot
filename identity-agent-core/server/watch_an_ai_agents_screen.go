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
	"identity-agent-core/permission"
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
//     at the default minimum score unless it is raised for these routes in
//     controllerMinimumScore, and never from a browser session.
//
// They are separate actions so that taking control can be set to need a
// higher score than watching without changing it. The minimums are a table in
// the code today; a setting the owner can change is future work.
//
// A viewing belongs to whoever opened it and to one body of one AI agent. Each
// start and end of watching, and of control, is written to the signed
// governance record, and so is every refusal a handler here makes, with its
// reason. A refusal by the one check happens at the router, before these
// handlers, and is answered with its reason but not recorded.
//
// Every refusal here carries a "reason" code the app turns into words, as do
// the router gate's refusals for too low a score and for a browser session, so
// the app never reads this program's sentences.

// The routes: the paths as mounted under /api, and the method and full path
// as the router gate keys them, both from the one spelling.
const (
	screensPath         = "/mcp/agent-screens"
	screenPath          = "/mcp/agents/{id}/screen"
	screenViewingPath   = screenPath + "/{sid}"
	screenPicturePath   = screenViewingPath + "/picture"
	screenControlPath   = screenViewingPath + "/control"
	screenInputPath     = screenViewingPath + "/input"
	bodyScreenPath      = "/agent-host/screen"
	bodyScreenFramePath = bodyScreenPath + "/frame"

	routeScreenControl   = "POST /api" + screenControlPath
	routeScreenInput     = "POST /api" + screenInputPath
	routeBodyScreen      = "POST /api" + bodyScreenPath
	routeBodyScreenFrame = "POST /api" + bodyScreenFramePath
)

// The reason codes a refusal here carries, besides the ones the router gate
// gives (score_too_low, browser_session).
const (
	reasonNoScreen      = "no_screen"
	reasonTooMany       = "too_many"
	reasonTooFast       = "too_fast"
	reasonNotYours      = "not_yours"
	reasonEnded         = "ended"
	reasonNotInControl  = "not_in_control"
	reasonCannotControl = "cannot_control"
	reasonQueueFull     = "queue_full"
	reasonNoPictureYet  = "no_picture_yet"
	reasonBadRequest    = "bad_request"
	reasonUnknownCaller = "unknown_caller"
)

// The record's names for the two actions.
const (
	eventWatch   = "agent.screen.watch"
	eventControl = "agent.screen.control"
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
	r.Get(screensPath, s.handleListAgentScreens)
	r.Post(screenPath, s.handleOpenViewing)
	r.Post(screenPicturePath, s.handleFetchScreen)
	r.Delete(screenViewingPath, s.handleEndViewing)
	r.Post(screenControlPath, s.handleTakeControl)
	r.Post(screenInputPath, s.handleSendInput)
	// A body, signed by its machine key and sealed to this Identity Agent.
	r.Post(bodyScreenPath, s.handleBodyAwaitsViewer)
	r.Post(bodyScreenFramePath, s.handleBodySendsFrame)
}

// ── Who is watching ──────────────────────────────────────────────────────────

// theViewer is who is asking, as a viewing is tied to them and as the record
// names them: the owner, the authorised machine that signed the request, or a
// browser session — asked in the order the router gate admits them, so the
// viewer is whoever the gate let in. False when the gate admitted none of
// them, which only a request that did not come through the gate can be.
func (s *CoreServer) theViewer(r *http.Request) (string, permission.CallerContext, bool) {
	cc := permission.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r)}
	if theGateAdmittedTheOwner(r) {
		cc.Transport, cc.CallerAID, cc.Owner = "owner", "owner", true
		if owner, ok := s.theOwner(); ok {
			cc.CallerAID = owner
		}
		return "owner", cc, true
	}
	if g, ok := TheControllerThatAsked(r); ok {
		cc.CallerAID, cc.Transport = g.ControllerAID, "controller"
		return "controller:" + g.ControllerAID, cc, true
	}
	if s.hasBrowserSession(r) {
		// Named by a digest of the session, never the session itself, which
		// is a bearer secret.
		sum := sha256.Sum256([]byte(bearerToken(r)))
		cc.CallerAID, cc.Transport = "browser-session:"+hex.EncodeToString(sum[:8]), "browser_session"
		return cc.CallerAID, cc, true
	}
	return "", cc, false
}

// theViewerOrRefuse is theViewer, answering for the handler when there is
// none.
func (s *CoreServer) theViewerOrRefuse(w http.ResponseWriter, r *http.Request, event string) (string, permission.CallerContext, bool) {
	viewer, cc, ok := s.theViewer(r)
	if !ok {
		cc.CallerAID = "unknown"
		s.refuseViewing(w, cc, event, "who is asking could not be told", reasonUnknownCaller, http.StatusForbidden)
	}
	return viewer, cc, ok
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

// screenNotYet says a body is on a Mac or a Windows computer, whose screen
// cannot be shown yet: the app shows the button there, disabled, and says so.
func screenNotYet(b agentbody.Binding) bool {
	return b.State == agentbody.StateActive && screenview.NotYetOn(b.Platform)
}

// handleListAgentScreens says which AI agents have a machine whose screen can
// be watched now, so the app offers the button only on those, and which have
// only machines whose screens cannot be watched yet.
func (s *CoreServer) handleListAgentScreens(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	if s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.AssetType != "ai_agent" {
				continue
			}
			notYet := false
			for _, b := range s.bodies().ForAgent(a.ID) {
				if sc := s.screenOfBody(b); sc != nil {
					out[a.ID] = map[string]any{"has_screen": true, "can_control": sc.CanControl}
					notYet = false
					break
				}
				notYet = notYet || screenNotYet(b)
			}
			if notYet {
				out[a.ID] = map[string]any{"has_screen": false, "not_available_yet": screenview.NotYetReason}
			}
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"agents": out})
}

// ── Watching ────────────────────────────────────────────────────────────────

// refuseViewing writes a refusal to the record, with its reason, and answers
// with it: the sentence as "error", and the code the app turns into words as
// "reason".
func (s *CoreServer) refuseViewing(w http.ResponseWriter, cc permission.CallerContext, event, why, reason string, status int) {
	s.refuseViewingWith(w, cc, event, why, reason, status, nil)
}

func (s *CoreServer) refuseViewingWith(w http.ResponseWriter, cc permission.CallerContext, event, why, reason string,
	status int, extra map[string]string) {
	log.Printf("[screen] refused %s to %s: %s (%s)", event, cc.CallerAID, why, reason)
	if s.ActivityLog != nil {
		cc.Reason = clampWhy(reason + ": " + why)
		s.ActivityLog.RecordGovernanceEvent(cc, event, "denied")
	}
	body := map[string]string{"error": why, "reason": reason}
	for k, v := range extra {
		body[k] = v
	}
	writeJSONStatus(w, status, body)
}

// refuseFromHub answers a refusal from the hub, with its reason code, and
// records it. Opening too often is answered and not recorded, so a caller
// opening in a loop cannot fill the record by being refused.
func (s *CoreServer) refuseFromHub(w http.ResponseWriter, cc permission.CallerContext, event, sid string, err error) {
	cc.WorkItem = sid
	switch {
	case errors.Is(err, screenview.ErrEnded):
		s.refuseViewingWith(w, cc, event, err.Error(), reasonEnded, http.StatusConflict,
			map[string]string{"ended_because": screenview.EndedBecause(err)})
	case errors.Is(err, screenview.ErrNotYours):
		s.refuseViewing(w, cc, event, err.Error(), reasonNotYours, http.StatusNotFound)
	case errors.Is(err, screenview.ErrNotInControl):
		s.refuseViewing(w, cc, event, err.Error(), reasonNotInControl, http.StatusConflict)
	case errors.Is(err, screenview.ErrCannotControl):
		s.refuseViewing(w, cc, event, err.Error(), reasonCannotControl, http.StatusConflict)
	case errors.Is(err, screenview.ErrQueueFull):
		s.refuseViewing(w, cc, event, err.Error(), reasonQueueFull, http.StatusTooManyRequests)
	case errors.Is(err, screenview.ErrNoPictureYet):
		s.refuseViewing(w, cc, event, err.Error(), reasonNoPictureYet, http.StatusConflict)
	case errors.Is(err, screenview.ErrTooMany):
		s.refuseViewing(w, cc, event, err.Error(), reasonTooMany, http.StatusTooManyRequests)
	case errors.Is(err, screenview.ErrTooFast):
		log.Printf("[screen] refused %s to %s: %v", event, cc.CallerAID, err)
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": err.Error(), "reason": reasonTooFast})
	case errors.Is(err, screenview.ErrNoScreen):
		s.refuseViewing(w, cc, event, err.Error(), reasonNoScreen, http.StatusConflict)
	default:
		s.refuseViewing(w, cc, event, err.Error(), reasonBadRequest, http.StatusBadRequest)
	}
}

// openAnswer is what the app is told when its viewing opens: the viewing, and
// the limits and key names it sends clicks and keys within, from the one
// place they are set.
func openAnswer(v screenview.Viewing) map[string]any {
	return map[string]any{
		"session": v.ID, "body": v.Body, "state": "waiting",
		"limits": map[string]any{
			"events_per_send": screenview.MaxEventsPerSend,
			"text":            screenview.MaxText,
		},
		"keys": screenview.KeyNames(),
		"mods": screenview.ModNames(),
	}
}

func (s *CoreServer) handleOpenViewing(w http.ResponseWriter, r *http.Request) {
	viewer, cc, ok := s.theViewerOrRefuse(w, r, eventWatch)
	if !ok {
		return
	}
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		s.refuseViewing(w, cc, eventWatch, "AI agent not found", reasonNotYours, http.StatusNotFound)
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if raw, err := readSignedBody(r); err == nil && len(raw) > 0 {
		if json.Unmarshal(raw, &req) != nil {
			s.refuseViewing(w, cc, eventWatch, "the request must be JSON", reasonBadRequest, http.StatusBadRequest)
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
		s.refuseViewing(w, cc, eventWatch, a.DisplayName+"'s machine has no screen that can be watched now",
			reasonNoScreen, http.StatusConflict)
		return
	}
	v, err := s.screens().Open(a.ID, chosen.ID, chosen.Host, viewer)
	if err != nil {
		s.refuseFromHub(w, cc, eventWatch, "", err)
		return
	}
	s.recordViewing(cc, v, "agent.screen.watch.started",
		fmt.Sprintf("started watching the screen of %s (%s) on its body %s", a.DisplayName, a.PairwiseAID, v.Host))
	writeJSONStatus(w, http.StatusCreated, openAnswer(v))
}

// endedAnswer tells the app its viewing ended, and why, as a code.
func endedAnswer(w http.ResponseWriter, because string) {
	writeJSONStatus(w, http.StatusOK, map[string]any{"state": "ended", "reason": reasonEnded, "ended_because": because})
}

func (s *CoreServer) handleFetchScreen(w http.ResponseWriter, r *http.Request) {
	viewer, cc, ok := s.theViewerOrRefuse(w, r, eventWatch)
	if !ok {
		return
	}
	agent, sid := chi.URLParam(r, "id"), chi.URLParam(r, "sid")
	var req struct {
		After int `json:"after"`
	}
	if raw, err := readSignedBody(r); err != nil || (len(raw) > 0 && json.Unmarshal(raw, &req) != nil) {
		cc.WorkItem = sid
		s.refuseViewing(w, cc, eventWatch, `ask as {"after": the number of the picture you have}`,
			reasonBadRequest, http.StatusBadRequest)
		return
	}
	after := req.After
	hub := s.screens()
	seen, err := hub.Fetch(r.Context(), sid, viewer, agent, after, fetchWait)
	if errors.Is(err, screenview.ErrEnded) {
		// Not a refusal: the window is told, and says so.
		endedAnswer(w, screenview.EndedBecause(err))
		return
	}
	if err != nil {
		s.refuseFromHub(w, cc, eventWatch, sid, err)
		return
	}
	// A body revoked mid-viewing is no longer the AI agent's: what it shows is
	// not the AI agent's screen any more.
	if b, ok := s.bodies().Get(seen.Viewing.Body); !ok || b.State != agentbody.StateActive {
		hub.EndBody(seen.Viewing.Host, screenview.EndedBodyInactive)
		endedAnswer(w, screenview.EndedBodyInactive)
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
	viewer, cc, ok := s.theViewerOrRefuse(w, r, eventWatch)
	if !ok {
		return
	}
	sid := chi.URLParam(r, "sid")
	_, err := s.screens().End(sid, viewer, chi.URLParam(r, "id"), screenview.EndedClosed)
	if err != nil && !errors.Is(err, screenview.ErrEnded) {
		s.refuseFromHub(w, cc, eventWatch, sid, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"ended": true})
}

// ── Taking control ──────────────────────────────────────────────────────────

func (s *CoreServer) handleTakeControl(w http.ResponseWriter, r *http.Request) {
	viewer, cc, ok := s.theViewerOrRefuse(w, r, eventControl)
	if !ok {
		return
	}
	agent, sid := chi.URLParam(r, "id"), chi.URLParam(r, "sid")
	var req struct {
		On *bool `json:"on"`
	}
	raw, err := readSignedBody(r)
	if err != nil || json.Unmarshal(raw, &req) != nil || req.On == nil {
		cc.WorkItem = sid
		s.refuseViewing(w, cc, eventControl, `say {"on": true} to take control, or {"on": false} to give it back`,
			reasonBadRequest, http.StatusBadRequest)
		return
	}
	// Whether control was on before is read with the change, under one lock,
	// so two requests at once record one start or one end, never two.
	was, v, err := s.screens().Control(sid, viewer, agent, *req.On)
	if err != nil {
		s.refuseFromHub(w, cc, eventControl, sid, err)
		return
	}
	name := agent
	if a, ok := s.aiAgentAsset(agent); ok {
		name = a.DisplayName + " (" + a.PairwiseAID + ")"
	}
	switch {
	case v.Control && !was:
		s.recordViewing(cc, v, "agent.screen.control.started",
			fmt.Sprintf("took control of the screen of %s on its body %s", name, v.Host))
	case !v.Control && was:
		s.recordViewing(cc, v, "agent.screen.control.ended",
			fmt.Sprintf("gave back control of the screen of %s on its body %s", name, v.Host))
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"control": v.Control})
}

func (s *CoreServer) handleSendInput(w http.ResponseWriter, r *http.Request) {
	viewer, cc, ok := s.theViewerOrRefuse(w, r, eventControl)
	if !ok {
		return
	}
	sid := chi.URLParam(r, "sid")
	var req struct {
		Events []screenview.Event `json:"events"`
	}
	raw, err := readSignedBody(r)
	if err != nil || json.Unmarshal(raw, &req) != nil {
		cc.WorkItem = sid
		s.refuseViewing(w, cc, eventControl, "the clicks and keys are unreadable", reasonBadRequest, http.StatusBadRequest)
		return
	}
	n, err := s.screens().Send(sid, viewer, chi.URLParam(r, "id"), req.Events)
	if err != nil {
		s.refuseFromHub(w, cc, eventControl, sid, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"queued": n})
}

// ── The record ──────────────────────────────────────────────────────────────

func (s *CoreServer) recordViewing(cc permission.CallerContext, v screenview.Viewing, event, why string) {
	log.Printf("[screen] %s: %s", cc.CallerAID, why)
	if s.ActivityLog == nil {
		return
	}
	cc.WorkItem = v.ID
	cc.Reason = clampWhy(why)
	s.ActivityLog.RecordGovernanceEvent(cc, event, "ok")
}

// recordViewingEnded records a viewing that ended, and the control given up
// with it, under the viewer who opened it.
func (s *CoreServer) recordViewingEnded(v screenview.Viewing) {
	cc := permission.CallerContext{Remote: true, CallerAID: v.Viewer}
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
			fmt.Sprintf("control of the screen of %s on its body %s ended with the viewing: %s",
				name, v.Host, screenview.EndedSentence(v.EndedBecause)))
	}
	s.recordViewing(cc, v, "agent.screen.watch.ended",
		fmt.Sprintf("stopped watching the screen of %s on its body %s after %s: %s",
			name, v.Host, took, screenview.EndedSentence(v.EndedBecause)))
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
		// Restarting says the body's display went away and is being opened
		// again, so a viewing of it ends saying that.
		Restarting bool `json:"restarting"`
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
		why := screenview.EndedNoScreen
		if req.Restarting {
			why = screenview.EndedScreenRestarted
		}
		hub.EndBody(b.Host, why)
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
