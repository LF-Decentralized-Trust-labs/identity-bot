package agenthost

import (
	"errors"
	"fmt"
	"image"
	"io"
	"sync"
	"testing"
	"time"

	"identity-agent-core/screenview"
)

// standIn is a display that can go away and come back. Each time it opens it
// is a new connection; one opened before it last went away answers EOF, as an
// X connection to a restarted display does.
type standIn struct {
	mu        sync.Mutex
	up        bool
	gen       int
	opens     int
	abandoned int
	closed    int
	released  int
}

type standInScreen struct {
	d   *standIn
	gen int
}

func (d *standIn) open() (Screen, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return nil, fmt.Errorf("%w: no display yet", ErrNoScreen)
	}
	d.opens++
	return &standInScreen{d: d, gen: d.gen}, nil
}

// restart takes the display away; it comes back with up.
func (d *standIn) restart()  { d.mu.Lock(); d.up = false; d.gen++; d.mu.Unlock() }
func (d *standIn) comeBack() { d.mu.Lock(); d.up = true; d.mu.Unlock() }
func (d *standIn) count(n *int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return *n
}

func (s *standInScreen) alive() error {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	if s.gen != s.d.gen {
		return io.EOF
	}
	return nil
}

func (s *standInScreen) Describe() (screenview.Screen, error) {
	if err := s.alive(); err != nil {
		return screenview.Screen{}, err
	}
	return screenview.Screen{Width: 800, Height: 600}, nil
}

func (s *standInScreen) Capture() (*image.RGBA, error) {
	if err := s.alive(); err != nil {
		return nil, err
	}
	return image.NewRGBA(image.Rect(0, 0, 800, 600)), nil
}

func (s *standInScreen) Apply(screenview.Event) error {
	if err := s.alive(); err != nil {
		return err
	}
	// A request the display refuses is not the display going away.
	return errors.New("the display refused that")
}

func (s *standInScreen) Release() error {
	s.d.mu.Lock()
	s.d.released++
	s.d.mu.Unlock()
	return s.alive()
}

func (s *standInScreen) Close() error { s.d.mu.Lock(); s.d.closed++; s.d.mu.Unlock(); return nil }
func (s *standInScreen) abandon()     { s.d.mu.Lock(); s.d.abandoned++; s.d.mu.Unlock() }

func waitFor(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(what)
	}
}

// A display that restarts is opened again, without restarting this program:
// while it is gone the screen says there is none for now, nothing is let go
// of on the connection that ended, and once it is back the screen is offered
// again and reads the new display.
func TestAScreenOpensAgainAfterItsDisplayRestarts(t *testing.T) {
	d := &standIn{up: true}
	s := newReopeningScreen(d.open, t.Logf, 10*time.Millisecond, 40*time.Millisecond)
	first, err := d.open()
	if err != nil {
		t.Fatal(err)
	}
	s.cur = first
	defer s.Close()

	if _, err := s.Describe(); err != nil {
		t.Fatalf("the screen before its display restarted: %v", err)
	}
	back := s.reopened()
	d.restart()
	if _, err := s.Capture(); !errors.Is(err, ErrScreenRestarting) || !errors.Is(err, ErrNoScreen) {
		t.Fatalf("a display that went away: %v, want ErrScreenRestarting", err)
	}
	if n := d.count(&d.abandoned); n != 1 {
		t.Fatalf("the ended connection was abandoned %d times, want 1", n)
	}
	if err := s.Release(); err != nil {
		t.Fatalf("letting go while the display is gone: %v", err)
	}
	if n := d.count(&d.released); n != 0 {
		t.Fatalf("something was let go of on a display that had gone (%d)", n)
	}
	// Still gone: several attempts fail, and the screen still says so.
	time.Sleep(100 * time.Millisecond)
	if _, err := s.Describe(); !errors.Is(err, ErrScreenRestarting) {
		t.Fatalf("while the display is gone: %v", err)
	}
	d.comeBack()
	waitFor(t, "the screen never said it opened again", back)
	if _, err := s.Describe(); err != nil {
		t.Fatalf("the screen after its display came back: %v", err)
	}
	if n := d.count(&d.opens); n != 2 {
		t.Fatalf("the display was opened %d times, want 2", n)
	}
	// A refused request is not the display going away.
	if err := s.Apply(screenview.Event{Type: "move"}); err == nil || errors.Is(err, ErrScreenRestarting) {
		t.Fatalf("a refused click: %v", err)
	}
	if _, err := s.Describe(); err != nil {
		t.Fatalf("a refused click closed the screen: %v", err)
	}
	if n := d.count(&d.opens); n != 2 {
		t.Fatalf("a refused click opened the display again (%d opens)", n)
	}
}

// Closing a screen whose display is gone stops opening it again: nothing is
// left trying in the background.
func TestClosingAScreenStopsOpeningItAgain(t *testing.T) {
	d := &standIn{up: true}
	s := newReopeningScreen(d.open, t.Logf, 5*time.Millisecond, 5*time.Millisecond)
	s.cur, _ = d.open()
	d.restart()
	if _, err := s.Describe(); !errors.Is(err, ErrScreenRestarting) {
		t.Fatalf("a display that went away: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	waitFor(t, "closing the screen did not stop opening it again", done)
	d.comeBack()
	time.Sleep(30 * time.Millisecond)
	if n := d.count(&d.opens); n != 1 {
		t.Fatalf("the display was opened %d times after the screen was closed", n-1)
	}
	if _, err := s.Describe(); !errors.Is(err, ErrScreenRestarting) {
		t.Fatalf("a closed screen: %v", err)
	}
}

// A display that is not up yet when the program starts is opened once it is;
// one that cannot be shown for another reason is refused at once.
func TestAScreenWaitsForADisplayNotUpYet(t *testing.T) {
	d := &standIn{}
	unreachable := func(err error) bool { return errors.Is(err, ErrNoScreen) }
	s, err := KeepScreenOpen(d.open, unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Describe(); !errors.Is(err, ErrScreenRestarting) {
		t.Fatalf("a display not up yet: %v", err)
	}
	back := s.reopened()
	d.comeBack()
	waitFor(t, "the display was never opened once it was up", back)
	if _, err := s.Describe(); err != nil {
		t.Fatal(err)
	}
	open, err := KeepScreenOpen(d.open, func(error) bool { return false })
	if err != nil {
		t.Fatalf("an open display: %v", err)
	}
	_ = open.Close()
	d.restart()
	if s, err := KeepScreenOpen(d.open, func(error) bool { return false }); err == nil || s != nil {
		t.Fatalf("a display that cannot be shown was not refused: %v", err)
	}
}

func TestOnlyAnEndedConnectionIsADisplayGone(t *testing.T) {
	for _, err := range []error{io.EOF, fmt.Errorf("reading: %w", io.ErrUnexpectedEOF)} {
		if !displayGone(err) {
			t.Errorf("%v is not taken as the display going away", err)
		}
	}
	if displayGone(errors.New("BadMatch")) {
		t.Error("a refused request is taken as the display going away")
	}
}
