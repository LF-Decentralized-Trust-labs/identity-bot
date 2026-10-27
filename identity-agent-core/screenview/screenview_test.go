package screenview

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newHub() (*Hub, *clock, *[]Viewing) {
	c := &clock{t: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	var ended []Viewing
	var mu sync.Mutex
	h := &Hub{Now: c.now, OnEnd: func(v Viewing) { mu.Lock(); ended = append(ended, v); mu.Unlock() }}
	return h, c, &ended
}

var screen = &Screen{Width: 1920, Height: 1080, CanControl: true}

// A body that never said it has a screen cannot be watched; one that said so
// can, until its word runs out.
func TestOnlyABodyThatSaidItHasAScreenCanBeWatched(t *testing.T) {
	h, c, _ := newHub()
	if _, err := h.Open("agent-a", "b1", "host-a", "alice"); !errors.Is(err, ErrNoScreen) {
		t.Fatalf("a body that said nothing was watched: %v", err)
	}
	h.Advertise("host-a", "agent-a", nil)
	if _, err := h.Open("agent-a", "b1", "host-a", "alice"); !errors.Is(err, ErrNoScreen) {
		t.Fatalf("a body with no screen was watched: %v", err)
	}
	h.Advertise("host-a", "agent-a", screen)
	if _, ok := h.Available("host-a"); !ok {
		t.Fatal("a body that said it has a screen is not offered")
	}
	// Another AI agent's id with this body's key is not this body's viewing.
	if _, err := h.Open("agent-b", "b1", "host-a", "alice"); !errors.Is(err, ErrNoScreen) {
		t.Fatalf("a body was watched under another AI agent: %v", err)
	}
	c.add(AdvertisedFor + time.Second)
	if _, ok := h.Available("host-a"); ok {
		t.Fatal("a body's word that it has a screen never ran out")
	}
}

// A picture is kept only while somebody watches, and a body is told to stop
// once nobody is; the viewing then ends and is reported, and the picture is
// forgotten.
func TestPicturesFlowOnlyWhileWatched(t *testing.T) {
	h, c, ended := newHub()
	h.Idle = time.Hour // swept by hand below
	h.Advertise("host-a", "agent-a", screen)
	if d, _ := h.Post("host-a", "agent-a", Frame{Width: 2, Height: 2, Image: []byte("jpeg")}); d.KeepGoing {
		t.Fatal("a body was told to keep sending with nobody watching")
	}
	v, err := h.Open("agent-a", "b1", "host-a", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !h.WaitForViewer(context.Background(), "host-a", 0) {
		t.Fatal("the body was not told somebody is watching")
	}
	if d, _ := h.Post("host-a", "agent-a", Frame{Width: 2, Height: 2, Image: []byte("jpeg")}); !d.KeepGoing {
		t.Fatal("a body was told to stop while watched")
	}
	seen, err := h.Fetch(context.Background(), v.ID, "alice", "agent-a", 0, 0)
	if err != nil || seen.Frame == nil || string(seen.Frame.Image) != "jpeg" {
		t.Fatalf("the viewer did not get the picture: %+v %v", seen, err)
	}
	// Nobody fetches for longer than the idle time.
	h.Idle = 5 * time.Second
	c.add(6 * time.Second)
	if d, _ := h.Post("host-a", "agent-a", Frame{Width: 2, Height: 2, Image: []byte("later")}); d.KeepGoing {
		t.Fatal("a body was told to keep sending after its viewer left")
	}
	if len(*ended) != 1 || (*ended)[0].ID != v.ID || (*ended)[0].EndedBecause == "" {
		t.Fatalf("the viewing's end was not reported: %+v", *ended)
	}
	if _, err := h.Fetch(context.Background(), v.ID, "alice", "agent-a", 0, 0); !errors.Is(err, ErrEnded) {
		t.Fatalf("the viewer was not told the viewing ended: %v", err)
	}
	h.mu.Lock()
	kept := h.bodies["host-a"].frame.Image
	h.mu.Unlock()
	if kept != nil {
		t.Fatal("a picture outlived its viewing")
	}
}

// A viewing is its viewer's and its AI agent's: nobody else fetches, controls
// or ends it, and asking under another AI agent finds nothing.
func TestAViewingIsOnlyItsViewers(t *testing.T) {
	h, _, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	v, _ := h.Open("agent-a", "b1", "host-a", "alice")
	for _, tc := range []struct{ viewer, agent string }{{"mallory", "agent-a"}, {"alice", "agent-b"}} {
		if _, err := h.Fetch(context.Background(), v.ID, tc.viewer, tc.agent, 0, 0); !errors.Is(err, ErrNotYours) {
			t.Errorf("%s fetched %s's viewing under %s: %v", tc.viewer, "alice", tc.agent, err)
		}
		if _, _, err := h.Control(v.ID, tc.viewer, tc.agent, true); !errors.Is(err, ErrNotYours) {
			t.Errorf("%s took control of another's viewing: %v", tc.viewer, err)
		}
		if _, err := h.End(v.ID, tc.viewer, tc.agent, EndedClosed); !errors.Is(err, ErrNotYours) {
			t.Errorf("%s ended another's viewing: %v", tc.viewer, err)
		}
	}
}

// Clicks and keys are taken only from a viewer in control, only on a body
// that can take them, only on the picture, and only so many.
func TestClicksAndKeysNeedControlAndStayOnThePicture(t *testing.T) {
	h, _, _ := newHub()
	h.Advertise("host-a", "agent-a", &Screen{Width: 100, Height: 100})
	v, _ := h.Open("agent-a", "b1", "host-a", "alice")
	if _, _, err := h.Control(v.ID, "alice", "agent-a", true); !errors.Is(err, ErrCannotControl) {
		t.Fatalf("control was taken of a body that cannot be controlled: %v", err)
	}
	h.Advertise("host-a", "agent-a", &Screen{Width: 100, Height: 100, CanControl: true})
	h.Post("host-a", "agent-a", Frame{Width: 100, Height: 50, Image: []byte("jpeg")})
	click := Event{Type: "click", X: 10, Y: 10, Button: 1}
	if _, err := h.Send(v.ID, "alice", "agent-a", []Event{click}); !errors.Is(err, ErrNotInControl) {
		t.Fatalf("a click was taken from a viewer not in control: %v", err)
	}
	if _, _, err := h.Control(v.ID, "alice", "agent-a", true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Event{
		{Type: "click", X: 10, Y: 60, Button: 1}, // below the 100x50 picture
		{Type: "click", X: -1, Y: 1, Button: 1},
		{Type: "click", X: 1, Y: 1, Button: 9},
		{Type: "key", Key: "XF86PowerOff"},
		{Type: "key", Key: "cc"},
		{Type: "key", Key: "\x00"},
		{Type: "key", Key: "Enter", Mods: []string{"hyper"}},
		{Type: "key", Key: "Return"}, // an X name, not one of the names the app is sent
		{Type: "text", Text: strings.Repeat("a", MaxText+1)},
		{Type: "text", Text: "\x1b[2J"},
		{Type: "exec", Text: "rm -rf /"},
	} {
		if _, err := h.Send(v.ID, "alice", "agent-a", []Event{bad}); err == nil {
			t.Errorf("%+v was taken", bad)
		}
	}
	if _, err := h.Send(v.ID, "alice", "agent-a", make([]Event, MaxEventsPerSend+1)); err == nil {
		t.Error("more events than one send allows were taken")
	}
	many := make([]Event, MaxEventsPerSend)
	for i := range many {
		many[i] = click
	}
	var err error
	for i := 0; i < MaxQueuedEvents/MaxEventsPerSend+1 && err == nil; i++ {
		_, err = h.Send(v.ID, "alice", "agent-a", many)
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("a body that does not collect could be sent without bound: %v", err)
	}
	d, _ := h.Post("host-a", "agent-a", Frame{})
	if !d.Control || len(d.Events) == 0 || d.Events[0].Type != "click" || d.Events[0].X != 10 {
		t.Fatalf("the body was not handed the clicks: %+v", d)
	}
	if d2, _ := h.Post("host-a", "agent-a", Frame{}); len(d2.Events) != 0 {
		t.Fatal("clicks were handed over twice")
	}
	// Giving control back drops anything not yet collected.
	h.Send(v.ID, "alice", "agent-a", []Event{click})
	h.Control(v.ID, "alice", "agent-a", false)
	if d3, _ := h.Post("host-a", "agent-a", Frame{}); d3.Control || len(d3.Events) != 0 {
		t.Fatalf("clicks were handed over after control was given back: %+v", d3)
	}
}

// How many viewings can be open is bounded, per viewer, per body and in all.
func TestViewingsAreBounded(t *testing.T) {
	h, _, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	for i := 0; i < MaxViewingsPerViewer; i++ {
		if _, err := h.Open("agent-a", "b1", "host-a", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Open("agent-a", "b1", "host-a", "alice"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("one viewer opened more viewings than allowed: %v", err)
	}
	for i := 0; i < MaxViewingsPerBody-MaxViewingsPerViewer; i++ {
		if _, err := h.Open("agent-a", "b1", "host-a", "viewer-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Open("agent-a", "b1", "host-a", "zed"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("one body was opened to more viewings than allowed: %v", err)
	}
	if _, err := h.Post("host-a", "agent-a", Frame{Width: 1, Height: 1, Image: make([]byte, MaxImage+1)}); err == nil {
		t.Fatal("a picture larger than allowed was taken")
	}
}

// A body that is no longer one ends what was being watched of it.
func TestEndingABodyEndsItsViewings(t *testing.T) {
	h, _, ended := newHub()
	h.Advertise("host-a", "agent-a", screen)
	v, _ := h.Open("agent-a", "b1", "host-a", "alice")
	h.Control(v.ID, "alice", "agent-a", true)
	h.EndBody("host-a", EndedBodyRemoved)
	if len(*ended) != 1 || !(*ended)[0].Control {
		t.Fatalf("the viewing, with its control, was not reported ended: %+v", *ended)
	}
	if h.WaitForViewer(context.Background(), "host-a", 0) {
		t.Fatal("a removed body was still watched")
	}
}

// A viewing that ended says why to its viewer, as a code.
func TestAnEndedViewingSaysWhy(t *testing.T) {
	h, _, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	v, _ := h.Open("agent-a", "b1", "host-a", "alice")
	h.EndBody("host-a", EndedBodyRemoved)
	_, err := h.Fetch(context.Background(), v.ID, "alice", "agent-a", 0, 0)
	if !errors.Is(err, ErrEnded) || EndedBecause(err) != EndedBodyRemoved {
		t.Fatalf("the viewer was not told why the viewing ended: %v", err)
	}
	// A machine that becomes another AI agent's body ends its viewings, and
	// says so to whoever records it.
	h2, _, ended := newHub()
	h2.Advertise("host-a", "agent-a", screen)
	h2.Open("agent-a", "b1", "host-a", "alice")
	h2.Advertise("host-a", "agent-b", screen)
	if len(*ended) != 1 || (*ended)[0].EndedBecause != EndedBodyReassigned {
		t.Fatalf("a viewing of a machine that changed AI agent was not reported ended: %+v", *ended)
	}
}

// Opening is limited per viewer and per body in any minute, so a loop of
// opening and closing is refused rather than recorded without end.
func TestOpeningIsRateLimited(t *testing.T) {
	h, c, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	for i := 0; i < OpensPerViewerPerMinute; i++ {
		v, err := h.Open("agent-a", "b1", "host-a", "alice")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		h.End(v.ID, "alice", "agent-a", EndedClosed)
	}
	if _, err := h.Open("agent-a", "b1", "host-a", "alice"); !errors.Is(err, ErrTooFast) {
		t.Fatalf("a viewer opened more viewings in a minute than allowed: %v", err)
	}
	// Somebody else may still open, until the body's own limit.
	n := OpensPerViewerPerMinute
	for i := 0; n < OpensPerBodyPerMinute; i++ {
		v, err := h.Open("agent-a", "b1", "host-a", "viewer-"+string(rune('a'+i/OpensPerViewerPerMinute)))
		if err != nil {
			t.Fatalf("open %d: %v", n, err)
		}
		h.End(v.ID, v.Viewer, "agent-a", EndedClosed)
		n++
	}
	if _, err := h.Open("agent-a", "b1", "host-a", "zed"); !errors.Is(err, ErrTooFast) {
		t.Fatalf("a body was opened more often in a minute than allowed: %v", err)
	}
	c.add(time.Minute)
	if _, err := h.Open("agent-a", "b1", "host-a", "alice"); err != nil {
		t.Fatalf("a minute later the viewer still could not open: %v", err)
	}
	h.Sweep()
	h.mu.Lock()
	kept := len(h.opens)
	h.mu.Unlock()
	if kept > 2 {
		t.Fatalf("%d open records kept after a minute, want only the new one's", kept)
	}
}

// How many ended viewings are remembered is bounded.
func TestEndedViewingsAreBounded(t *testing.T) {
	h, c, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	for i := 0; i < MaxRemembered+20; i++ {
		v, err := h.Open("agent-a", "b1", "host-a", "alice")
		if err != nil {
			t.Fatal(err)
		}
		h.End(v.ID, "alice", "agent-a", EndedClosed)
		// Well inside RememberEnded; the rate limits are cleared by hand.
		c.add(time.Millisecond)
		h.mu.Lock()
		h.opens = map[string][]time.Time{}
		h.mu.Unlock()
	}
	h.mu.Lock()
	n := len(h.ended)
	h.mu.Unlock()
	if n > MaxRemembered {
		t.Fatalf("%d ended viewings remembered, more than %d", n, MaxRemembered)
	}
}

// Only one fetch of a viewing waits at a time: a newer one sends the one
// waiting back at once.
func TestOneFetchWaitsPerViewing(t *testing.T) {
	h, _, _ := newHub()
	h.Advertise("host-a", "agent-a", screen)
	v, _ := h.Open("agent-a", "b1", "host-a", "alice")
	first := make(chan error, 1)
	go func() {
		_, err := h.Fetch(context.Background(), v.ID, "alice", "agent-a", 0, time.Minute)
		first <- err
	}()
	waitFor(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.viewings[v.ID].fetching == 1 })
	second := make(chan error, 1)
	go func() {
		_, err := h.Fetch(context.Background(), v.ID, "alice", "agent-a", 0, time.Minute)
		second <- err
	}()
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("the replaced fetch failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a second fetch did not send the first back")
	}
	h.mu.Lock()
	waiting := h.viewings[v.ID].fetching
	h.mu.Unlock()
	if waiting != 1 {
		t.Fatalf("%d fetches waiting, want 1", waiting)
	}
	h.End(v.ID, "alice", "agent-a", EndedClosed)
	select {
	case err := <-second:
		if !errors.Is(err, ErrEnded) {
			t.Fatalf("the waiting fetch of an ended viewing was told %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ending the viewing did not send the waiting fetch back")
	}
}

// Of two requests to take control at once, only one finds it was off; of a
// take and a give-back at once, each sees the state the other left.
func TestControlChangesAreSeenOnce(t *testing.T) {
	for round := 0; round < 200; round++ {
		h, _, _ := newHub()
		h.Advertise("host-a", "agent-a", screen)
		v, _ := h.Open("agent-a", "b1", "host-a", "alice")
		var wg sync.WaitGroup
		var mu sync.Mutex
		started := 0
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				was, now, err := h.Control(v.ID, "alice", "agent-a", true)
				if err == nil && now.Control && !was {
					mu.Lock()
					started++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if started != 1 {
			t.Fatalf("round %d: %d starts of control seen, want 1", round, started)
		}
		changes := 0
		for _, on := range []bool{false, true} {
			wg.Add(1)
			go func(on bool) {
				defer wg.Done()
				was, now, err := h.Control(v.ID, "alice", "agent-a", on)
				if err == nil && was != now.Control {
					mu.Lock()
					changes++
					mu.Unlock()
				}
			}(on)
		}
		wg.Wait()
		final, _ := h.Get(v.ID, "alice", "agent-a")
		// From on: an off then an on is two changes and leaves it on; an on
		// then an off is one and leaves it off. Anything else is a change
		// recorded that did not happen, or one that did and was not.
		want := 1
		if final.Control {
			want = 2
		}
		if changes != want {
			t.Fatalf("round %d: %d changes seen, ending with control %v", round, changes, final.Control)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A body on a Mac or a Windows computer is one whose screen cannot be watched
// yet; any other is judged by what it says.
func TestMacAndWindowsBodiesAreNotYet(t *testing.T) {
	for p, notYet := range map[string]bool{
		"darwin/arm64": true, "windows/amd64": true, "linux/amd64": false, "freebsd/amd64": false, "": false,
	} {
		if NotYetOn(p) != notYet {
			t.Errorf("%q: not yet %v, want %v", p, !notYet, notYet)
		}
	}
}
