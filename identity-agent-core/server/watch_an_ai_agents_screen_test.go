package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
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

func (s *aScreen) Close() error { return nil }

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
	w.s.screens().Idle = 2 * time.Second
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
		req = asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, method, path, body, w.ctlSeed, "", time.Time{})
	} else {
		req = asThatMachineScored(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, method, path, body, w.ctlSeed,
			authprovider.LevelHigh, time.Now().Add(-time.Minute), score)
	}
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
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
		return w.agentsWithScreens(t)[w.a.ID] != nil
	})
	if w.agentsWithScreens(t)[w.b.ID] != nil {
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
	eventually(t, "the screen was never offered", func() bool { return w.agentsWithScreens(t)[w.a.ID] != nil })
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
	eventually(t, "the screen was never offered", func() bool { return w.agentsWithScreens(t)[w.a.ID] != nil })
	sid, _ := w.watch(t)
	base := "/api/mcp/agents/" + w.a.ID + "/screen/" + sid
	click := `{"events":[{"type":"click","x":640,"y":360,"button":1}]}`

	// At the score every person has until human authentication is built.
	if code, out, raw := w.asApp(t, "POST", base+"/control", `{"on":true}`, 0); code != http.StatusForbidden ||
		!strings.Contains(out["detail"].(string), "score of at least 90") {
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
	eventually(t, "the screen was never offered", func() bool { return w.agentsWithScreens(t)[w.a.ID] != nil })
	w.s.BrowserSessions = newBrowserSessions()
	const secret = "the-browser-keeps-this"
	id, code, _, _ := w.s.BrowserSessions.newChallenge(hashSecret(secret))
	if err := w.s.BrowserSessions.grant(code); err != nil {
		t.Fatal(err)
	}
	token, _, err := w.s.BrowserSessions.claim(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	asBrowser := func(method, path, body string) (int, map[string]any) {
		req := remote(method, path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, req)
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
		if st != http.StatusForbidden || !strings.Contains(out["detail"].(string), "browser session") {
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
	eventually(t, "the screen was never offered", func() bool { return w.agentsWithScreens(t)[w.a.ID] != nil })
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
	w.s.router.ServeHTTP(rec, httptest.NewRequest("POST", "/api/agent-host/screen/frame",
		strings.NewReader(`{"width":1,"height":1,"image":"AA=="}`)))
	if rec.Code == http.StatusOK {
		t.Fatal("a picture was taken from a request that is not a body's")
	}
}
