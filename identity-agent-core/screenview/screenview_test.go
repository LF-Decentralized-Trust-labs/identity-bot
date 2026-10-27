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
		if _, err := h.Control(v.ID, tc.viewer, tc.agent, true); !errors.Is(err, ErrNotYours) {
			t.Errorf("%s took control of another's viewing: %v", tc.viewer, err)
		}
		if _, err := h.End(v.ID, tc.viewer, tc.agent, "x"); !errors.Is(err, ErrNotYours) {
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
	if _, err := h.Control(v.ID, "alice", "agent-a", true); !errors.Is(err, ErrCannotControl) {
		t.Fatalf("control was taken of a body that cannot be controlled: %v", err)
	}
	h.Advertise("host-a", "agent-a", &Screen{Width: 100, Height: 100, CanControl: true})
	h.Post("host-a", "agent-a", Frame{Width: 100, Height: 50, Image: []byte("jpeg")})
	click := Event{Type: "click", X: 10, Y: 10, Button: 1}
	if _, err := h.Send(v.ID, "alice", "agent-a", []Event{click}); !errors.Is(err, ErrNotInControl) {
		t.Fatalf("a click was taken from a viewer not in control: %v", err)
	}
	if _, err := h.Control(v.ID, "alice", "agent-a", true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Event{
		{Type: "click", X: 10, Y: 60, Button: 1}, // below the 100x50 picture
		{Type: "click", X: -1, Y: 1, Button: 1},
		{Type: "click", X: 1, Y: 1, Button: 9},
		{Type: "key", Key: "XF86PowerOff"},
		{Type: "key", Key: "cc"},
		{Type: "key", Key: "\x00"},
		{Type: "key", Key: "Return", Mods: []string{"hyper"}},
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
	h.EndBody("host-a", "the machine was removed")
	if len(*ended) != 1 || !(*ended)[0].Control {
		t.Fatalf("the viewing, with its control, was not reported ended: %+v", *ended)
	}
	if h.WaitForViewer(context.Background(), "host-a", 0) {
		t.Fatal("a removed body was still watched")
	}
}
