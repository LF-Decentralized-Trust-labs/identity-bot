package aiagents

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agenthost"
	"identity-agent-core/authprovider"
	"identity-agent-core/conversation"
	"identity-agent-core/screenview"
)

// aScreen is a machine's screen in a test: a picture that changes when told,
// and a record of every click and key passed to it.
type aScreen struct {
	mu       sync.Mutex
	w, h     int
	shade    uint8
	captures int
	applied  []screenview.Event
	released int
	gone     bool
}

func (s *aScreen) Describe() (screenview.Screen, error) {
	return screenview.Screen{Width: s.w, Height: s.h, CanControl: true}, nil
}

func (s *aScreen) Capture() (*image.RGBA, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captures++
	img := image.NewRGBA(image.Rect(0, 0, s.w, s.h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = s.shade, 0x40, 0x80, 0xff
	}
	return img, nil
}

func (s *aScreen) Apply(e screenview.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, e)
	return nil
}

func (s *aScreen) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released++
	return nil
}

func (s *aScreen) Close() error { return nil }

func (s *aScreen) letGo() int { s.mu.Lock(); defer s.mu.Unlock(); return s.released }

func (s *aScreen) looked() int { s.mu.Lock(); defer s.mu.Unlock(); return s.captures }
func (s *aScreen) got() []screenview.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]screenview.Event(nil), s.applied...)
}

// screenWorld is two AI agents with bodies, the first with a screen offered
// and the second with none, and the founder's paired app.
type screenWorld struct {
	*talkWorld
	scr *aScreen
}

func newScreenWorld(t *testing.T) *screenWorld {
	t.Helper()
	w := &screenWorld{talkWorld: newTalkWorld(t), scr: &aScreen{w: 2560, h: 1440, shade: 1}}
	of(w.s).screens().Idle = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.hostA.ShowScreen(ctx, w.scr, agenthost.ScreenControl, nil)
	go w.hostB.ShowScreen(ctx, nil, agenthost.ScreenControl, nil)
	return w
}

// asApp is a request from the founder's paired app: signed by that machine,
// with the score the person has until human authentication is built, or a
// vouched score when given.
func (w *screenWorld) asApp(t *testing.T, method, path, body string, score int) (int, map[string]any, string) {
	t.Helper()
	// Every request carries a nonce, as the app's do, so two identical ones
	// in a second are not one request sent twice.
	if strings.HasPrefix(body, "{") {
		body = `{"nonce":"` + conversation.NewID("n_") + `",` + strings.TrimPrefix(body, "{")
		body = strings.Replace(body, ",}", "}", 1)
	}
	var req *http.Request
	if score == 0 {
		req = helpers.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, method, path, body, w.ctlSeed, "", time.Time{})
	} else {
		req = helpers.AsThatMachineScored(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, method, path, body, w.ctlSeed,
			authprovider.LevelHigh, time.Now().Add(-time.Minute), score)
	}
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// picture is the app fetching the screen of a viewing, newer than after.
func (w *screenWorld) picture(t *testing.T, agentID, sid string, after float64) (int, map[string]any, string) {
	t.Helper()
	return w.asApp(t, "POST", "/api/mcp/agents/"+agentID+"/screen/"+sid+"/picture", `{"after":`+jsonNumber(after)+`}`, 0)
}

func (w *screenWorld) agentsWithScreens(t *testing.T) map[string]any {
	_, out, _ := w.asApp(t, "GET", "/api/mcp/agent-screens", "", 0)
	m, _ := out["agents"].(map[string]any)
	return m
}

// hasScreen says the app is offered the button for this AI agent.
func (w *screenWorld) hasScreen(t *testing.T, agentID string) bool {
	m, _ := w.agentsWithScreens(t)[agentID].(map[string]any)
	return m["has_screen"] == true
}

// eventually waits for cond, failing with what after a few seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// watch opens a viewing of the first AI agent from the app and fetches until a
// picture arrives, returning the viewing and the picture's answer.
func (w *screenWorld) watch(t *testing.T) (string, map[string]any) {
	t.Helper()
	code, out, raw := w.asApp(t, "POST", "/api/mcp/agents/"+w.a.ID+"/screen", `{}`, 0)
	if code != http.StatusCreated {
		t.Fatalf("opening a viewing: %d %s", code, raw)
	}
	sid := out["session"].(string)
	var frame map[string]any
	eventually(t, "no picture of the screen arrived", func() bool {
		code, got, raw := w.picture(t, w.a.ID, sid, 0)
		if code != http.StatusOK || got["state"] == "ended" {
			t.Fatalf("the viewing ended before a picture arrived: %s", raw)
		}
		if got["image"] != nil {
			frame = got
			return true
		}
		return false
	})
	return sid, frame
}

// A body whose machine has a screen says so, and the app is offered the
// button for its AI agent; a body with none says that, and is not.
func TestABodyWithAScreenSaysSoAndOneWithoutDoesNot(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the AI agent with a screen was never offered", func() bool {
		return w.hasScreen(t, w.a.ID)
	})
	if w.hasScreen(t, w.b.ID) {
		t.Fatal("an AI agent whose machine has no screen was offered as having one")
	}
	_, out, _ := w.asApp(t, "GET", "/api/mcp/agents/"+w.a.ID+"/bodies", "", 0)
	bodies := out["bodies"].([]any)
	if sc, _ := bodies[0].(map[string]any)["screen"].(map[string]any); sc == nil || sc["available"] != true ||
		sc["width"].(float64) != 2560 {
		t.Fatalf("the body's screen is not shown with it: %v", bodies[0])
	}
	code, out, _ := w.asApp(t, "POST", "/api/mcp/agents/"+w.b.ID+"/screen", `{}`, 0)
	if code != http.StatusConflict || out["reason"] != "no_screen" {
		t.Fatalf("watching a machine with no screen: %d %v", code, out)
	}
}

// Asking to watch reaches the body over its own sealed connection, and
// pictures flow back only while somebody fetches them. Once nobody does, the
// body stops looking at its screen and the viewing's end is recorded.
func TestPicturesFlowOnlyWhileSomebodyWatches(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	time.Sleep(300 * time.Millisecond)
	if n := w.scr.looked(); n != 0 {
		t.Fatalf("the body looked at its screen %d times with nobody watching", n)
	}
	sid, frame := w.watch(t)
	if frame["state"] != "watching" || frame["width"].(float64) != 1280 || frame["height"].(float64) != 720 {
		t.Fatalf("the picture is not the screen shrunk to send: %v", frame)
	}
	raw, _ := base64.StdEncoding.DecodeString(frame["image"].(string))
	img, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the picture is not an image: %v", err)
	}
	if r, _, _, _ := img.At(10, 10).RGBA(); r>>8 > 8 {
		t.Fatalf("the picture is not of the screen: %v", color.RGBAModel.Convert(img.At(10, 10)))
	}
	// A change on the screen arrives as a newer picture.
	w.scr.mu.Lock()
	w.scr.shade = 200
	w.scr.mu.Unlock()
	seq := frame["seq"].(float64)
	eventually(t, "the change on the screen never arrived", func() bool {
		_, got, _ := w.picture(t, w.a.ID, sid, seq)
		return got["image"] != nil && got["seq"].(float64) > seq
	})

	// Nobody fetches any more: the viewing ends, and the body stops.
	eventually(t, "the viewing never ended", func() bool { return len(governanceRows(t, w.talkWorld, "agent.screen.watch.ended")) == 1 })
	time.Sleep(500 * time.Millisecond)
	stopped := w.scr.looked()
	time.Sleep(time.Second)
	if n := w.scr.looked(); n != stopped {
		t.Fatalf("the body kept looking at its screen after its viewer left (%d, then %d)", stopped, n)
	}
	_, out, _ := w.picture(t, w.a.ID, sid, 0)
	if out["state"] != "ended" {
		t.Fatalf("the app was not told the viewing ended: %v", out)
	}
	started := governanceRows(t, w.talkWorld, "agent.screen.watch.started")
	if len(started) != 1 || started[0].CallerAID != w.ctlAID || !strings.Contains(started[0].Reason, w.a.PairwiseAID) {
		t.Fatalf("who watched which AI agent is not recorded: %+v", started)
	}
}

func jsonNumber(f float64) string { b, _ := json.Marshal(f); return string(b) }

// A click is refused to somebody who has not proved enough to take control,
// and reaches the machine once they have, at the place on the screen they
// clicked. Taking and giving back control are recorded.
func TestAClickNeedsTheTakeControlPermission(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	base := "/api/mcp/agents/" + w.a.ID + "/screen/" + sid
	click := `{"events":[{"type":"click","x":640,"y":360,"button":1}]}`

	// Taking control is its own action, so it can need more than watching.
	// Set here to 90 to show the two are judged apart; by default it needs
	// the same as everything else (TestControlNeedsOnlyTheDefaultUnlessRaised).
	helpers.ControllerMinimumScore()[routeScreenControl], helpers.ControllerMinimumScore()[routeScreenInput] = 90, 90
	t.Cleanup(func() {
		delete(helpers.ControllerMinimumScore(), routeScreenControl)
		delete(helpers.ControllerMinimumScore(), routeScreenInput)
	})
	// At the score every person has until human authentication is built.
	if code, out, raw := w.asApp(t, "POST", base+"/control", `{"on":true}`, 0); code != http.StatusForbidden ||
		out["reason"] != "score_too_low" {
		t.Fatalf("control was given at the watching score: %d %s", code, raw)
	}
	if code, _, raw := w.asApp(t, "POST", base+"/input", click, 0); code != http.StatusForbidden {
		t.Fatalf("a click was taken at the watching score: %d %s", code, raw)
	}
	// Proved, vouched for by the device holding the identity's key.
	if code, _, raw := w.asApp(t, "POST", base+"/input", click, 90); code != http.StatusConflict {
		t.Fatalf("a click was taken before control was: %d %s", code, raw)
	}
	if code, out, raw := w.asApp(t, "POST", base+"/control", `{"on":true}`, 90); code != http.StatusOK || out["control"] != true {
		t.Fatalf("taking control: %d %s", code, raw)
	}
	if code, _, raw := w.asApp(t, "POST", base+"/input", click, 90); code != http.StatusAccepted {
		t.Fatalf("clicking: %d %s", code, raw)
	}
	var got []screenview.Event
	eventually(t, "the click never reached the machine", func() bool {
		if got = w.scr.got(); len(got) > 0 {
			return true
		}
		// Fetching keeps the viewing open while the body collects the click.
		w.picture(t, w.a.ID, sid, 1000)
		return false
	})
	if got[0].Type != "click" || got[0].X != 1280 || got[0].Y != 720 || got[0].Button != 1 {
		t.Fatalf("the click reached the machine somewhere else: %+v", got[0])
	}
	if code, _, raw := w.asApp(t, "POST", base+"/control", `{"on":false}`, 90); code != http.StatusOK {
		t.Fatalf("giving control back: %d %s", code, raw)
	}
	// The machine lets go of anything held down once control is given back.
	eventually(t, "the machine never let go of what was held when control was given back", func() bool {
		if w.scr.letGo() > 0 {
			return true
		}
		w.picture(t, w.a.ID, sid, 1000)
		return false
	})
	if n := len(governanceRows(t, w.talkWorld, "agent.screen.control.started")); n != 1 {
		t.Fatalf("%d control starts recorded, want 1", n)
	}
	if n := len(governanceRows(t, w.talkWorld, "agent.screen.control.ended")); n != 1 {
		t.Fatalf("%d control ends recorded, want 1", n)
	}
}

// A browser session may watch, and may never take control or click.
func TestABrowserSessionCannotTakeControl(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	const secret = "the-browser-keeps-this"
	token := helpers.SignInABrowser(t, w.s, secret)
	asBrowser := func(method, path, body string) (int, map[string]any) {
		req := helpers.Remote(method, path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		hostOf(w.s).Router().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	st, out := asBrowser("POST", "/api/mcp/agents/"+w.a.ID+"/screen", `{}`)
	if st != http.StatusCreated {
		t.Fatalf("a browser session could not watch: %d %v", st, out)
	}
	base := "/api/mcp/agents/" + w.a.ID + "/screen/" + out["session"].(string)
	for _, tc := range []struct{ path, body string }{
		{base + "/control", `{"on":true}`},
		{base + "/input", `{"events":[{"type":"click","x":1,"y":1,"button":1}]}`},
	} {
		st, out := asBrowser("POST", tc.path, tc.body)
		if st != http.StatusForbidden || out["reason"] != "browser_session" {
			t.Fatalf("a browser session reached %s: %d %v", tc.path, st, out)
		}
	}
	// And the founder's app cannot reach the browser's viewing.
	if st, _, _ := w.picture(t, w.a.ID, out["session"].(string), 0); st != http.StatusNotFound {
		t.Fatalf("one viewer fetched another's viewing: %d", st)
	}
}

// A viewing is of one AI agent: its id under another AI agent finds nothing,
// and the body of another AI agent never receives the first one's clicks.
func TestAViewingIsOfOneAIAgent(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	if st, _, _ := w.picture(t, w.b.ID, sid, 0); st != http.StatusNotFound {
		t.Fatalf("a viewing of one AI agent was fetched under another: %d", st)
	}
	if st, _, _ := w.asApp(t, "DELETE", "/api/mcp/agents/"+w.b.ID+"/screen/"+sid, "", 0); st != http.StatusNotFound {
		t.Fatalf("a viewing of one AI agent was ended under another: %d", st)
	}
	// Ending it is recorded at once.
	if st, _, raw := w.asApp(t, "DELETE", "/api/mcp/agents/"+w.a.ID+"/screen/"+sid, "", 0); st != http.StatusOK {
		t.Fatalf("ending the viewing: %d %s", st, raw)
	}
	if n := len(governanceRows(t, w.talkWorld, "agent.screen.watch.ended")); n != 1 {
		t.Fatalf("%d viewing ends recorded, want 1", n)
	}
	// The body routes take only a sealed request a live body signed.
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, httptest.NewRequest("POST", "/api/agent-host/screen/frame",
		strings.NewReader(`{"width":1,"height":1,"image":"AA=="}`)))
	if rec.Code == http.StatusOK {
		t.Fatal("a picture was taken from a request that is not a body's")
	}
}

// By default taking control needs what every action needs: the person at an
// authorised controller can take control at the score everyone has today.
func TestControlNeedsOnlyTheDefaultUnlessRaised(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	base := "/api/mcp/agents/" + w.a.ID + "/screen/" + sid
	if code, out, raw := w.asApp(t, "POST", base+"/control", `{"on":true}`, 0); code != http.StatusOK || out["control"] != true {
		t.Fatalf("taking control at the default score: %d %s", code, raw)
	}
	click := `{"events":[{"type":"click","x":10,"y":10,"button":1}]}`
	if code, _, raw := w.asApp(t, "POST", base+"/input", click, 0); code != http.StatusAccepted {
		t.Fatalf("clicking at the default score: %d %s", code, raw)
	}
}

// The window is told what it may send — the limits and key names — from the
// one place they are set, and why its viewing ended, as a code.
func TestTheAppIsToldTheLimitsAndWhyAViewingEnded(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	code, out, raw := w.asApp(t, "POST", "/api/mcp/agents/"+w.a.ID+"/screen", `{}`, 0)
	if code != http.StatusCreated {
		t.Fatalf("opening: %d %s", code, raw)
	}
	limits, _ := out["limits"].(map[string]any)
	if limits["events_per_send"].(float64) != screenview.MaxEventsPerSend || limits["text"].(float64) != screenview.MaxText {
		t.Fatalf("the limits are not sent: %s", raw)
	}
	keys, _ := out["keys"].([]any)
	if len(keys) != len(screenview.Keys) {
		t.Fatalf("the key names are not sent: %s", raw)
	}
	sid := out["session"].(string)
	if st, _, raw := w.asApp(t, "DELETE", "/api/mcp/agents/"+w.a.ID+"/screen/"+sid, "", 0); st != http.StatusOK {
		t.Fatalf("ending: %d %s", st, raw)
	}
	_, got, raw := w.picture(t, w.a.ID, sid, 0)
	if got["state"] != "ended" || got["ended_because"] != screenview.EndedClosed {
		t.Fatalf("the window was not told why its viewing ended: %s", raw)
	}
	if st, got, raw := w.asApp(t, "POST", "/api/mcp/agents/"+w.a.ID+"/screen/"+sid+"/control", `{"on":true}`, 0); st != http.StatusConflict ||
		got["reason"] != "ended" || got["ended_because"] != screenview.EndedClosed {
		t.Fatalf("taking control of an ended viewing: %d %s", st, raw)
	}
}

// Every refusal a handler here makes is recorded with its reason: a viewing
// that is not yours, clicks sent while not in control.
func TestRefusalsAreRecordedWithTheirReason(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	base := "/api/mcp/agents/" + w.a.ID + "/screen/"
	click := `{"events":[{"type":"click","x":1,"y":1,"button":1}]}`
	if st, out, raw := w.asApp(t, "POST", base+sid+"/input", click, 0); st != http.StatusConflict || out["reason"] != "not_in_control" {
		t.Fatalf("a click before taking control: %d %s", st, raw)
	}
	if st, out, raw := w.asApp(t, "POST", base+"sv_nobodys/control", `{"on":true}`, 0); st != http.StatusNotFound || out["reason"] != "not_yours" {
		t.Fatalf("control of a viewing that is not yours: %d %s", st, raw)
	}
	var denied []string
	for _, row := range governanceRows(t, w.talkWorld, "agent.screen.control") {
		if row.ResultStatus == "denied" {
			denied = append(denied, row.Reason)
		}
	}
	if len(denied) != 2 || !strings.HasPrefix(denied[0], "not_in_control") && !strings.HasPrefix(denied[1], "not_in_control") ||
		!strings.HasPrefix(denied[0], "not_yours") && !strings.HasPrefix(denied[1], "not_yours") {
		t.Fatalf("the refusals were not recorded with their reasons: %q", denied)
	}
}

// Two requests to take control at once record one start.
func TestTakingControlTwiceAtOnceIsRecordedOnce(t *testing.T) {
	w := newScreenWorld(t)
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	path := "/api/mcp/agents/" + w.a.ID + "/screen/" + sid + "/control"
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.asApp(t, "POST", path, `{"on":true}`, 0)
		}()
	}
	wg.Wait()
	if n := len(governanceRows(t, w.talkWorld, "agent.screen.control.started")); n != 1 {
		t.Fatalf("%d control starts recorded for one start, want 1", n)
	}
}

// The record names the caller the gate admitted. The owner at this computer
// who also holds a browser session is the owner, as the gate admitted them.
func TestTheRecordNamesWhoTheGateAdmitted(t *testing.T) {
	w := newScreenWorld(t)
	helpers.WithOwnerSecret(w.s, helpers.TestOwnerSecret())
	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	const secret = "the-browser-keeps-this"
	token := helpers.SignInABrowser(t, w.s, secret)
	req := helpers.Local("POST", "/api/mcp/agents/"+w.a.ID+"/screen", `{}`)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("the owner could not watch: %d %s", rec.Code, rec.Body.String())
	}
	started := governanceRows(t, w.talkWorld, "agent.screen.watch.started")
	if len(started) != 1 || started[0].Transport != "owner" {
		t.Fatalf("the owner's viewing was recorded as somebody else's: %+v", started)
	}
}

// aRestartingDisplay is a display that can go away and come back, as one does
// when an update restarts its service. A screen opened on it before it went
// away answers EOF, as an X connection to a restarted display does.
type aRestartingDisplay struct {
	mu  sync.Mutex
	up  bool
	cur *aScreen
}

func (d *aRestartingDisplay) open() (agenthost.Screen, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return nil, errors.New("no display yet")
	}
	d.cur = &aScreen{w: 1280, h: 720, shade: 1}
	return &onADisplay{aScreen: d.cur}, nil
}

func (d *aRestartingDisplay) restart() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.up = false
	d.cur.mu.Lock()
	d.cur.gone = true
	d.cur.mu.Unlock()
}

func (d *aRestartingDisplay) comeBack() { d.mu.Lock(); d.up = true; d.mu.Unlock() }

// onADisplay is aScreen answering EOF once its display has gone.
type onADisplay struct{ *aScreen }

func (s *onADisplay) Describe() (screenview.Screen, error) {
	s.mu.Lock()
	gone := s.gone
	s.mu.Unlock()
	if gone {
		return screenview.Screen{}, io.EOF
	}
	return s.aScreen.Describe()
}

func (s *onADisplay) Capture() (*image.RGBA, error) {
	s.mu.Lock()
	gone := s.gone
	s.mu.Unlock()
	if gone {
		return nil, io.EOF
	}
	return s.aScreen.Capture()
}

// A display that restarts under a body ends the viewing of it saying so, and
// the screen is offered again once the display is back, without the body
// being restarted.
func TestAScreenIsOfferedAgainAfterItsDisplayRestarts(t *testing.T) {
	w := &screenWorld{talkWorld: newTalkWorld(t)}
	of(w.s).screens().Idle = 2 * time.Second
	d := &aRestartingDisplay{up: true}
	scr, err := agenthost.KeepScreenOpen(d.open, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scr.Close() })
	w.scr = d.cur
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.hostA.ShowScreen(ctx, scr, agenthost.ScreenControl, nil)

	eventually(t, "the screen was never offered", func() bool { return w.hasScreen(t, w.a.ID) })
	sid, _ := w.watch(t)
	d.restart()
	eventually(t, "the viewing did not end when the display went away", func() bool {
		_, out, _ := w.picture(t, w.a.ID, sid, 1000)
		if out["state"] != "ended" {
			return false
		}
		if out["ended_because"] != screenview.EndedScreenRestarted {
			t.Fatalf("the viewing ended for another reason: %v", out)
		}
		return true
	})
	if w.hasScreen(t, w.a.ID) {
		t.Fatal("a screen whose display is gone is still offered")
	}
	d.comeBack()
	eventually(t, "the screen was not offered again once its display came back", func() bool {
		return w.hasScreen(t, w.a.ID)
	})
	if _, frame := w.watch(t); frame["image"] == nil {
		t.Fatal("the screen offered again shows nothing")
	}
}
