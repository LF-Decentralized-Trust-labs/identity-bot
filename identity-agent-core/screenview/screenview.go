// Package screenview carries an AI agent's screen to the people allowed to
// watch it, and their clicks and keys back, through the Identity Agent that
// holds the AI agent.
//
// The AI agent's body already keeps a sealed connection open to the Identity
// Agent. A body with a screen says so on that connection and waits there for
// somebody to watch. When a person asks to watch, the Identity Agent opens a
// viewing for that body; the body then sends pictures of its screen, only
// while somebody keeps fetching them, and takes back whatever clicks and keys
// a person who took control sent.
//
// Nothing here decides who may watch or take control. That is the one check,
// asked by the routes in front of this. This package keeps the viewings apart
// — a viewing belongs to the person who opened it and to one AI agent's body —
// bounds what they can cost, and forgets every picture once nobody is watching.
package screenview

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// AdvertisedFor is how long a body's word that it has a screen holds. A
	// body renews it on every wait for a viewer, which lasts at most WaitLimit,
	// and on every picture it sends.
	AdvertisedFor = 60 * time.Second
	// WaitLimit bounds one wait, well inside the shortest relay limit on any
	// path to an Identity Agent.
	WaitLimit = 25 * time.Second
	// IdleAfter is how long a viewing lasts once nobody fetches its pictures.
	// The app fetches continuously while its window is open, so this is a
	// closed window, a sleeping computer or a lost connection.
	IdleAfter = 5 * time.Second
	// RememberEnded is how long an ended viewing is remembered, so its
	// viewer is told it ended rather than that there is no such viewing.
	RememberEnded = time.Minute
	// FramesPerSecond is how often a body looks at its screen while watched.
	FramesPerSecond = 4

	// MaxImage bounds one picture as sent: a compressed image of a screen.
	MaxImage = 2 << 20
	// MaxWidth and MaxHeight bound the screen a body may describe.
	MaxWidth, MaxHeight = 8192, 8192
	// MaxEventsPerSend, MaxQueuedEvents and MaxText bound what a person who
	// took control can queue for a body.
	MaxEventsPerSend = 50
	MaxQueuedEvents  = 256
	MaxText          = 200
	// MaxViewings, MaxViewingsPerViewer and MaxViewingsPerBody bound how many
	// viewings can be open at once.
	MaxViewings          = 64
	MaxViewingsPerViewer = 4
	MaxViewingsPerBody   = 8
	// OpensPerViewerPerMinute and OpensPerBodyPerMinute bound how often
	// viewings can be opened, so opening and closing in a loop cannot fill the
	// record or keep a body starting and stopping.
	OpensPerViewerPerMinute = 10
	OpensPerBodyPerMinute   = 30
	// MaxRemembered bounds how many ended viewings are remembered at once.
	MaxRemembered = 256
)

// Why a viewing ended, as a code the app turns into words. EndedSentence is
// the same in words, for the record.
const (
	EndedClosed         = "closed"
	EndedIdle           = "idle"
	EndedBodyRemoved    = "body_removed"
	EndedBodyReassigned = "body_reassigned"
	EndedNoScreen       = "no_screen"
	EndedBodyInactive   = "body_inactive"
)

var endedSentences = map[string]string{
	EndedClosed:         "the person closed the window",
	EndedIdle:           "nobody was watching any more",
	EndedBodyRemoved:    "the machine was removed as this AI agent's body",
	EndedBodyReassigned: "the machine became another AI agent's body",
	EndedNoScreen:       "the machine no longer has a screen",
	EndedBodyInactive:   "the machine is no longer this AI agent's body",
}

// EndedSentence is why a viewing ended, in words.
func EndedSentence(code string) string {
	if s, ok := endedSentences[code]; ok {
		return s
	}
	return code
}

// Screen is what a body says about its screen.
type Screen struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	// CanControl says the body can pass on clicks and keys, as well as show
	// its screen.
	CanControl bool `json:"can_control"`
}

// Check refuses a screen nobody could have.
func (s Screen) Check() error {
	if s.Width <= 0 || s.Height <= 0 || s.Width > MaxWidth || s.Height > MaxHeight {
		return fmt.Errorf("a screen is between 1x1 and %dx%d", MaxWidth, MaxHeight)
	}
	return nil
}

// Event is one thing a person controlling a screen did. Coordinates are in the
// picture's pixels, as the person saw it.
type Event struct {
	// Type is move, click, down, up, scroll, key or text.
	Type   string   `json:"type"`
	X      int      `json:"x,omitempty"`
	Y      int      `json:"y,omitempty"`
	Button int      `json:"button,omitempty"`
	DY     int      `json:"dy,omitempty"`
	Key    string   `json:"key,omitempty"`
	Mods   []string `json:"mods,omitempty"`
	Text   string   `json:"text,omitempty"`
}

// Keys a person may press, besides the characters they type, by the names
// keyboards are given in web browsers and app toolkits ("Enter", "ArrowLeft",
// "PageUp"), each with the X keysym it presses. This is the one list: the app
// is sent the names when it opens a viewing, and a body presses what they
// stand for. A key event may also name one printable character, pressed with
// the keys held.
//
// Whoever is in control can press any combination of these with the held
// keys, as a person at the machine could: that includes switching to another
// virtual terminal or ending the machine's graphical session.
var Keys = map[string]uint32{
	"Enter": 0xff0d, "NumpadEnter": 0xff0d, "Backspace": 0xff08, "Tab": 0xff09, "Escape": 0xff1b,
	"Delete": 0xffff, "Insert": 0xff63, "Home": 0xff50, "End": 0xff57, "PageUp": 0xff55, "PageDown": 0xff56,
	"ArrowLeft": 0xff51, "ArrowUp": 0xff52, "ArrowRight": 0xff53, "ArrowDown": 0xff54,
	"F1": 0xffbe, "F2": 0xffbf, "F3": 0xffc0, "F4": 0xffc1, "F5": 0xffc2, "F6": 0xffc3,
	"F7": 0xffc4, "F8": 0xffc5, "F9": 0xffc6, "F10": 0xffc7, "F11": 0xffc8, "F12": 0xffc9,
	"Space": 0x0020,
}

// KeyNames is every name in Keys, in order, as the app is sent them.
func KeyNames() []string { return sortedNames(Keys) }

// ModNames is every name in Mods, in order, as the app is sent them.
func ModNames() []string { return sortedNames(Mods) }

func sortedNames(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Mods are the keys a person may hold while pressing another.
var Mods = map[string]uint32{"shift": 0xffe1, "ctrl": 0xffe3, "alt": 0xffe9, "super": 0xffeb}

// Check refuses an event a body could not or should not act on: an unknown
// kind, a point off the picture, a key that is not on the list, or too much
// text.
func (e Event) Check(width, height int) error {
	onPicture := func() error {
		if e.X < 0 || e.Y < 0 || e.X >= width || e.Y >= height {
			return fmt.Errorf("%s at %d,%d is off the %dx%d picture", e.Type, e.X, e.Y, width, height)
		}
		return nil
	}
	button := func() error {
		if e.Button < 1 || e.Button > 3 {
			return fmt.Errorf("a mouse has buttons 1 to 3")
		}
		return nil
	}
	for _, m := range e.Mods {
		if _, ok := Mods[m]; !ok {
			return fmt.Errorf("%q is not a key that can be held", m)
		}
	}
	if len(e.Mods) > len(Mods) {
		return fmt.Errorf("too many keys held")
	}
	switch e.Type {
	case "move":
		return onPicture()
	case "click", "down", "up":
		if err := button(); err != nil {
			return err
		}
		return onPicture()
	case "scroll":
		if e.DY == 0 || e.DY < -20 || e.DY > 20 {
			return fmt.Errorf("a scroll is between -20 and 20 steps, and not none")
		}
		return onPicture()
	case "key":
		// A named key, or one printable character pressed with held keys —
		// a shortcut such as ctrl and c.
		if _, ok := Keys[e.Key]; !ok && !(len(e.Key) == 1 && e.Key[0] >= 0x20 && e.Key[0] < 0x7f) {
			return fmt.Errorf("%q is not a key that can be pressed", e.Key)
		}
		return nil
	case "text":
		if e.Text == "" || utf8.RuneCountInString(e.Text) > MaxText || !utf8.ValidString(e.Text) {
			return fmt.Errorf("text is 1 to %d characters", MaxText)
		}
		for _, r := range e.Text {
			if r < 0x20 && r != '\n' && r != '\t' {
				return fmt.Errorf("text carries no control characters; press a key instead")
			}
		}
		return nil
	}
	return fmt.Errorf("%q is not something a person can do on a screen", e.Type)
}

// Frame is one picture of a body's screen.
type Frame struct {
	Seq    int
	Width  int
	Height int
	// Image is the picture, compressed as JPEG.
	Image []byte
	At    time.Time
}

// Viewing is one person watching one AI agent's body.
type Viewing struct {
	ID string
	// Agent is the AI agent's asset id, Body the binding and Host the machine
	// key of the body being watched.
	Agent, Body, Host string
	// Viewer is who opened it, as the routes in front name them. Only they can
	// fetch its pictures, control through it or end it.
	Viewer  string
	Started time.Time
	// Control is whether the viewer has taken control, and since when.
	Control      bool
	ControlSince time.Time
	// Ended and EndedBecause say the viewing is over and why, as one of the
	// Ended codes.
	Ended        time.Time
	EndedBecause string

	lastFetch time.Time
	// fetching counts fetches waiting for a picture now: a viewer waiting is
	// a viewer watching.
	fetching int
	// waiter is closed to send back at once the fetch waiting now, when a
	// newer fetch of the same viewing arrives: one fetch waits per viewing.
	waiter chan struct{}
	events []Event
}

// Errors a route turns into an answer.
var (
	ErrNoScreen      = errors.New("this AI agent's machine has no screen to watch")
	ErrNotYours      = errors.New("no such viewing")
	ErrEnded         = errors.New("this viewing has ended")
	ErrTooFast       = errors.New("viewings are being opened too often; wait a minute and try again")
	ErrNotInControl  = errors.New("take control before sending clicks and keys")
	ErrCannotControl = errors.New("this AI agent's machine cannot be controlled: it shows its screen but takes no clicks and keys")
	ErrTooMany       = errors.New("too many viewings are open; close one and try again")
	ErrQueueFull     = errors.New("the machine has not caught up with what was sent; wait a moment")
	ErrNoPictureYet  = errors.New("wait for the screen to appear before clicking on it")
)

// NotYetReason and NotYetSentence say why a Mac's or a Windows computer's
// screen cannot be watched: reading and driving those screens is not built
// yet. The reason is the code the app is sent; the sentence is what a body
// on such a computer prints.
const (
	NotYetReason   = "mac_or_windows"
	NotYetSentence = "Watching is not available yet for AI agents on a Mac or Windows computer."
)

// NotYetOn says a body's platform, as it reported it when it enrolled
// ("darwin/arm64", "windows/amd64"), is one whose screen cannot be watched
// yet.
func NotYetOn(platform string) bool {
	p := strings.ToLower(platform)
	return strings.HasPrefix(p, "darwin") || strings.HasPrefix(p, "macos") || strings.HasPrefix(p, "windows")
}

// EndedError is ErrEnded, saying why the viewing ended.
type EndedError struct{ Because string }

func (e *EndedError) Error() string        { return ErrEnded.Error() + ": " + EndedSentence(e.Because) }
func (e *EndedError) Is(target error) bool { return target == ErrEnded }

// EndedBecause is why a viewing ended, when err says it did.
func EndedBecause(err error) string {
	var e *EndedError
	if errors.As(err, &e) {
		return e.Because
	}
	return ""
}

// body is what is known about one body's screen.
type body struct {
	agent  string
	screen *Screen
	seenAt time.Time
	// watched is closed, and replaced, when a viewing opens for this body.
	watched chan struct{}
	frame   Frame
	// fresh is closed, and replaced, when a new picture arrives.
	fresh chan struct{}
}

// Hub holds the viewings of one Identity Agent. It is safe for concurrent use.
type Hub struct {
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Idle is how long a viewing lasts unfetched; IdleAfter when zero.
	Idle time.Duration
	// OnEnd is told of every viewing that ends, and of control given up with
	// it, after the hub's lock is released, so it can record them.
	OnEnd func(v Viewing)

	mu       sync.Mutex
	bodies   map[string]*body
	viewings map[string]*Viewing
	// ended remembers viewings that ended in the last RememberEnded, at most
	// MaxRemembered of them.
	ended map[string]Viewing
	// opens are when viewings were opened in the last minute, by viewer and
	// by body.
	opens    map[string][]time.Time
	sweeping bool
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hub) idle() time.Duration {
	if h.Idle > 0 {
		return h.Idle
	}
	return IdleAfter
}

func (h *Hub) bodyLocked(host string) *body {
	if h.bodies == nil {
		h.bodies = map[string]*body{}
		h.viewings = map[string]*Viewing{}
		h.ended = map[string]Viewing{}
		h.opens = map[string][]time.Time{}
	}
	b, ok := h.bodies[host]
	if !ok {
		b = &body{watched: make(chan struct{}), fresh: make(chan struct{})}
		h.bodies[host] = b
	}
	return b
}

// Advertise records what a body says about its screen: nil for none.
func (h *Hub) Advertise(host, agent string, s *Screen) {
	h.mu.Lock()
	var ended []Viewing
	b := h.bodyLocked(host)
	if b.agent != "" && b.agent != agent {
		// A machine key is one AI agent's body. A different AI agent for the
		// same key is a new body; what was being watched of the old one ends.
		ended = h.endHostLocked(host, EndedBodyReassigned)
	}
	b.agent, b.screen, b.seenAt = agent, s, h.now()
	h.mu.Unlock()
	h.told(ended)
}

// Available says whether a body's screen can be watched now, and what it is.
func (h *Hub) Available(host string) (Screen, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.bodies[host]
	if !ok || b.screen == nil || h.now().Sub(b.seenAt) > AdvertisedFor {
		return Screen{}, false
	}
	return *b.screen, true
}

// Open starts a viewing of a body by a viewer. The body must have said, and
// recently, that it has a screen.
func (h *Hub) Open(agent, bodyID, host, viewer string) (Viewing, error) {
	if _, ok := h.Available(host); !ok {
		return Viewing{}, ErrNoScreen
	}
	h.mu.Lock()
	ended := h.sweepLocked()
	b := h.bodyLocked(host)
	if b.agent != agent {
		h.mu.Unlock()
		h.told(ended)
		return Viewing{}, ErrNoScreen
	}
	open, mine, here := 0, 0, 0
	for _, v := range h.viewings {
		open++
		if v.Viewer == viewer {
			mine++
		}
		if v.Host == host {
			here++
		}
	}
	if open >= MaxViewings || mine >= MaxViewingsPerViewer || here >= MaxViewingsPerBody {
		h.mu.Unlock()
		h.told(ended)
		return Viewing{}, ErrTooMany
	}
	now := h.now()
	byViewer, byBody := "viewer:"+viewer, "body:"+host
	if !h.mayOpenLocked(byViewer, OpensPerViewerPerMinute, now) || !h.mayOpenLocked(byBody, OpensPerBodyPerMinute, now) {
		h.mu.Unlock()
		h.told(ended)
		return Viewing{}, ErrTooFast
	}
	h.opens[byViewer] = append(h.opens[byViewer], now)
	h.opens[byBody] = append(h.opens[byBody], now)
	v := &Viewing{ID: newID(), Agent: agent, Body: bodyID, Host: host, Viewer: viewer, Started: now, lastFetch: now}
	h.viewings[v.ID] = v
	close(b.watched)
	b.watched = make(chan struct{})
	h.startSweeperLocked()
	out := *v
	h.mu.Unlock()
	h.told(ended)
	return out, nil
}

// mayOpenLocked reports whether fewer than limit viewings were opened under
// key in the last minute, forgetting the older ones.
func (h *Hub) mayOpenLocked(key string, limit int, now time.Time) bool {
	recent := pruneOpens(h.opens[key], now)
	if len(recent) == 0 {
		delete(h.opens, key)
	} else {
		h.opens[key] = recent
	}
	return len(recent) < limit
}

func pruneOpens(at []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(at) && now.Sub(at[i]) >= time.Minute {
		i++
	}
	return at[i:]
}

// mine is the viewing id, if it is the viewer's and of this AI agent. Anything
// else — somebody else's viewing, another AI agent's — is no such viewing.
func (h *Hub) mineLocked(id, viewer, agent string) (*Viewing, error) {
	v, ok := h.viewings[id]
	if !ok {
		// A viewing that ended a moment ago is reported as ended, to its own
		// viewer, so their window can say so rather than that it never was.
		if e, was := h.ended[id]; was && e.Viewer == viewer && e.Agent == agent {
			return nil, &EndedError{Because: e.EndedBecause}
		}
		return nil, ErrNotYours
	}
	if v.Viewer != viewer || v.Agent != agent {
		return nil, ErrNotYours
	}
	return v, nil
}

// Seen is what a viewer fetches: the latest picture, when it is newer than the
// one they have.
type Seen struct {
	Viewing Viewing
	Frame   *Frame
	// CanControl is whether the body can take clicks and keys.
	CanControl bool
}

// Fetch is a viewer asking for the screen. It keeps the viewing open, and
// waits up to wait for a picture newer than after. Only one fetch of a
// viewing waits at a time: a newer one sends the one waiting back at once,
// with what there is.
func (h *Hub) Fetch(ctx context.Context, id, viewer, agent string, after int, wait time.Duration) (Seen, error) {
	h.mu.Lock()
	ended := h.sweepLocked()
	v, err := h.mineLocked(id, viewer, agent)
	if err == nil {
		v.lastFetch = h.now()
		if b := h.bodyLocked(v.Host); b.frame.Seq <= after && wait > 0 {
			fresh := b.fresh
			if v.waiter != nil {
				close(v.waiter)
			}
			mine := make(chan struct{})
			v.waiter = mine
			v.fetching++
			h.mu.Unlock()
			h.told(ended)
			ended = nil
			t := time.NewTimer(wait)
			select {
			case <-fresh:
			case <-mine:
			case <-t.C:
			case <-ctx.Done():
			}
			t.Stop()
			h.mu.Lock()
			v.fetching--
			if v.waiter == mine {
				v.waiter = nil
			}
			v, err = h.mineLocked(id, viewer, agent)
		}
	}
	defer func() { h.told(ended) }()
	defer h.mu.Unlock()
	if err != nil {
		return Seen{}, err
	}
	// Waiting counted as fetching: the viewer was here all along.
	v.lastFetch = h.now()
	b := h.bodyLocked(v.Host)
	out := Seen{Viewing: *v}
	if b.screen != nil {
		out.CanControl = b.screen.CanControl
	}
	if b.frame.Seq > after && b.frame.Image != nil {
		f := b.frame
		out.Frame = &f
	}
	return out, nil
}

// Get is a viewer's viewing as it stands, without counting as a fetch.
func (h *Hub) Get(id, viewer, agent string) (Viewing, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, err := h.mineLocked(id, viewer, agent)
	if err != nil {
		return Viewing{}, err
	}
	return *v, nil
}

// Control turns a viewer's control of the screen on or off, and says whether
// it was on before, read under the same lock, so of two requests at once only
// the one that changed it sees a change.
func (h *Hub) Control(id, viewer, agent string, on bool) (was bool, _ Viewing, _ error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, err := h.mineLocked(id, viewer, agent)
	if err != nil {
		return false, Viewing{}, err
	}
	was = v.Control
	b := h.bodyLocked(v.Host)
	if on && (b.screen == nil || !b.screen.CanControl) {
		return was, Viewing{}, ErrCannotControl
	}
	if on && !v.Control {
		v.ControlSince = h.now()
	}
	if !on {
		v.events = nil
	}
	v.Control = on
	v.lastFetch = h.now()
	return was, *v, nil
}

// Send queues clicks and keys from a viewer in control, for the body to take
// with its next picture.
func (h *Hub) Send(id, viewer, agent string, events []Event) (int, error) {
	if len(events) == 0 || len(events) > MaxEventsPerSend {
		return 0, fmt.Errorf("send 1 to %d clicks and keys at a time", MaxEventsPerSend)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	v, err := h.mineLocked(id, viewer, agent)
	if err != nil {
		return 0, err
	}
	if !v.Control {
		return 0, ErrNotInControl
	}
	b := h.bodyLocked(v.Host)
	if b.frame.Seq == 0 {
		return 0, ErrNoPictureYet
	}
	for _, e := range events {
		if err := e.Check(b.frame.Width, b.frame.Height); err != nil {
			return 0, err
		}
	}
	if len(v.events)+len(events) > MaxQueuedEvents {
		return 0, ErrQueueFull
	}
	v.events = append(v.events, events...)
	v.lastFetch = h.now()
	return len(events), nil
}

// End closes a viewing at its viewer's request. why is one of the Ended codes.
func (h *Hub) End(id, viewer, agent, why string) (Viewing, error) {
	h.mu.Lock()
	v, err := h.mineLocked(id, viewer, agent)
	if err != nil {
		h.mu.Unlock()
		return Viewing{}, err
	}
	out := h.endLocked(v, why)
	h.mu.Unlock()
	h.told([]Viewing{out})
	return out, nil
}

// EndBody closes every viewing of a body: it stopped being a body, or another
// AI agent's. why is one of the Ended codes.
func (h *Hub) EndBody(host, why string) {
	h.mu.Lock()
	ended := h.endHostLocked(host, why)
	h.mu.Unlock()
	h.told(ended)
}

// WaitForViewer is a body waiting to be watched. It reports whether anybody
// is watching it, returning as soon as somebody starts or after wait.
func (h *Hub) WaitForViewer(ctx context.Context, host string, wait time.Duration) bool {
	h.mu.Lock()
	ended := h.sweepLocked()
	watched := h.watchedLocked(host)
	ch := h.bodyLocked(host).watched
	h.mu.Unlock()
	h.told(ended)
	if watched {
		return true
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.watchedLocked(host)
}

// Delivered is what a body is told after sending a picture.
type Delivered struct {
	// KeepGoing is false once nobody is watching: the body stops looking.
	KeepGoing bool
	// Control is whether somebody watching has taken control.
	Control bool
	// Events are the clicks and keys to act on, in order.
	Events []Event
}

// Post takes a picture from a body, or only its word that the screen has not
// changed when f has no image, and hands back what to act on. A picture is kept
// only while somebody is watching; otherwise it is dropped and the body is
// told to stop.
func (h *Hub) Post(host, agent string, f Frame) (Delivered, error) {
	if f.Image != nil && (len(f.Image) > MaxImage || f.Width <= 0 || f.Height <= 0 ||
		f.Width > MaxWidth || f.Height > MaxHeight) {
		return Delivered{}, fmt.Errorf("a picture is at most %d bytes and %dx%d", MaxImage, MaxWidth, MaxHeight)
	}
	h.mu.Lock()
	ended := h.sweepLocked()
	b := h.bodyLocked(host)
	var out Delivered
	if b.agent == agent && b.screen != nil {
		b.seenAt = h.now()
	}
	if b.agent != agent || !h.watchedLocked(host) {
		// Nobody watching: nothing is kept, so a picture never outlives the
		// viewing it was for.
		b.frame = Frame{}
		h.mu.Unlock()
		h.told(ended)
		return out, nil
	}
	out.KeepGoing = true
	if f.Image != nil {
		f.Seq = b.frame.Seq + 1
		f.At = h.now()
		b.frame = f
		close(b.fresh)
		b.fresh = make(chan struct{})
	}
	ids := make([]string, 0, len(h.viewings))
	for id, v := range h.viewings {
		if v.Host == host {
			ids = append(ids, id)
		}
	}
	// In the order the viewings were opened, so two people in control are
	// handled the same way every time.
	sort.Slice(ids, func(i, j int) bool { return h.viewings[ids[i]].Started.Before(h.viewings[ids[j]].Started) })
	for _, id := range ids {
		v := h.viewings[id]
		if v.Control {
			out.Control = true
			out.Events = append(out.Events, v.events...)
			v.events = nil
		}
	}
	h.mu.Unlock()
	h.told(ended)
	return out, nil
}

// Viewings is every open viewing, for whoever needs to list them.
func (h *Hub) Viewings() []Viewing {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Viewing, 0, len(h.viewings))
	for _, v := range h.viewings {
		out = append(out, *v)
	}
	return out
}

func (h *Hub) watchedLocked(host string) bool {
	for _, v := range h.viewings {
		if v.Host == host {
			return true
		}
	}
	return false
}

func (h *Hub) endLocked(v *Viewing, why string) Viewing {
	v.Ended, v.EndedBecause = h.now(), why
	delete(h.viewings, v.ID)
	v.events = nil
	if v.waiter != nil {
		close(v.waiter)
		v.waiter = nil
	}
	if len(h.ended) >= MaxRemembered {
		// The oldest is forgotten first: its viewer is then told there is
		// no such viewing rather than that it ended.
		oldest := ""
		for id, e := range h.ended {
			if oldest == "" || e.Ended.Before(h.ended[oldest].Ended) {
				oldest = id
			}
		}
		delete(h.ended, oldest)
	}
	h.ended[v.ID] = *v
	if !h.watchedLocked(v.Host) {
		// The last viewer left: the picture is forgotten.
		if b, ok := h.bodies[v.Host]; ok {
			b.frame = Frame{}
			close(b.fresh)
			b.fresh = make(chan struct{})
		}
	}
	return *v
}

func (h *Hub) endHostLocked(host, why string) []Viewing {
	var ended []Viewing
	for _, v := range h.viewings {
		if v.Host == host {
			ended = append(ended, h.endLocked(v, why))
		}
	}
	return ended
}

// sweepLocked ends viewings nobody has fetched for the hub's idle time.
func (h *Hub) sweepLocked() []Viewing {
	var ended []Viewing
	now := h.now()
	for id, e := range h.ended {
		if now.Sub(e.Ended) > RememberEnded {
			delete(h.ended, id)
		}
	}
	for key, at := range h.opens {
		if recent := pruneOpens(at, now); len(recent) == 0 {
			delete(h.opens, key)
		} else {
			h.opens[key] = recent
		}
	}
	for _, v := range h.viewings {
		if v.fetching == 0 && now.Sub(v.lastFetch) > h.idle() {
			ended = append(ended, h.endLocked(v, EndedIdle))
		}
	}
	return ended
}

// Sweep ends viewings nobody is fetching. The hub sweeps by itself while any
// viewing is open; this is for a caller that cannot wait for that.
func (h *Hub) Sweep() {
	h.mu.Lock()
	ended := h.sweepLocked()
	h.mu.Unlock()
	h.told(ended)
}

// startSweeperLocked runs a sweep every second while any viewing is open, so a
// viewing whose window closed ends, and is recorded as ended, even when
// nothing else calls the hub.
func (h *Hub) startSweeperLocked() {
	if h.sweeping {
		return
	}
	h.sweeping = true
	every := time.Second
	if i := h.idle() / 2; i < every {
		every = i
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			h.mu.Lock()
			ended := h.sweepLocked()
			done := len(h.viewings) == 0
			if done {
				h.sweeping = false
			}
			h.mu.Unlock()
			h.told(ended)
			if done {
				return
			}
		}
	}()
}

func (h *Hub) told(ended []Viewing) {
	if h.OnEnd == nil {
		return
	}
	for _, v := range ended {
		h.OnEnd(v)
	}
}

func newID() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "sv_" + base64.RawURLEncoding.EncodeToString(b)
}
