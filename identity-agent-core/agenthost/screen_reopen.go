package agenthost

import (
	"errors"
	"fmt"
	"image"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"identity-agent-core/screenview"
)

// A display that goes away and comes back.
//
// The display a body shows can restart under it: an automatic security update
// restarts the display's service, or a person does. The connection to the old
// display is then over for good. The body closes it, says it has no screen for
// now, and opens the display again — after a second, then two, four and so on
// up to thirty, for as long as the program runs. A display that opens again
// is a new one: its keyboard is read afresh, nothing held down or lent on the
// old one is let go of or given back on it, and the screen is offered again
// at once.

// ErrScreenRestarting is a screen whose display went away and is being opened
// again. It is ErrNoScreen for now.
var ErrScreenRestarting = fmt.Errorf("%w for now: its display went away and is being opened again", ErrNoScreen)

// reopenFirst and reopenAtMost bound the wait between attempts to open a
// display again.
const (
	reopenFirst  = time.Second
	reopenAtMost = 30 * time.Second
)

// displayGone says err is the connection to a display ending, rather than a
// request the display refused: only opening the display again brings the
// screen back.
func displayGone(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// abandoner is a screen that can let go of a connection to a display that has
// gone, without trying to let go of anything on it.
type abandoner interface{ abandon() }

// reopener is a screen that says when it opened again, so the body offers it
// at once rather than at its next word.
type reopener interface{ reopened() <-chan struct{} }

// ReopeningScreen is a screen that opens its display again whenever the
// connection to it ends. While it is closed it says it has no screen
// (ErrScreenRestarting).
type ReopeningScreen struct {
	open        func() (Screen, error)
	logf        func(string, ...any)
	first, most time.Duration

	mu     sync.Mutex
	cur    Screen
	back   chan struct{}
	trying bool
	closed bool
	stop   chan struct{}
	wg     sync.WaitGroup
}

// KeepScreenOpen opens a screen with open, and opens it again whenever its
// display goes away. When the first attempt fails because the display cannot
// be reached, it keeps trying; any other failure is returned.
func KeepScreenOpen(open func() (Screen, error), unreachable func(error) bool) (*ReopeningScreen, error) {
	s := newReopeningScreen(open, nil, reopenFirst, reopenAtMost)
	scr, err := open()
	if err != nil {
		if unreachable == nil || !unreachable(err) {
			return nil, err
		}
		s.logf("[agent-host] the display cannot be opened yet (%v); trying again until it can", err)
		s.mu.Lock()
		s.startLocked()
		s.mu.Unlock()
		return s, nil
	}
	s.cur = scr
	return s, nil
}

func newReopeningScreen(open func() (Screen, error), logf func(string, ...any), first, most time.Duration) *ReopeningScreen {
	if logf == nil {
		logf = log.Printf
	}
	return &ReopeningScreen{open: open, logf: logf, first: first, most: most,
		back: make(chan struct{}), stop: make(chan struct{})}
}

// use runs f on the open screen. A connection that ended is closed, and the
// display opened again in the background.
func (s *ReopeningScreen) use(f func(Screen) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return ErrScreenRestarting
	}
	err := f(s.cur)
	if err != nil && displayGone(err) {
		s.logf("[agent-host] the display went away (%v); opening it again", err)
		if a, ok := s.cur.(abandoner); ok {
			a.abandon()
		} else {
			_ = s.cur.Close()
		}
		s.cur = nil
		s.startLocked()
		return fmt.Errorf("%w (%v)", ErrScreenRestarting, err)
	}
	return err
}

// startLocked starts opening the display again, unless that is under way.
func (s *ReopeningScreen) startLocked() {
	if s.trying || s.closed {
		return
	}
	s.trying = true
	s.wg.Add(1)
	go s.reopen()
}

// reopen tries to open the display until it opens or the screen is closed.
func (s *ReopeningScreen) reopen() {
	defer s.wg.Done()
	wait := s.first
	said := ""
	for {
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-s.stop:
			t.Stop()
			return
		}
		scr, err := s.open()
		if err == nil {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = scr.Close()
				return
			}
			s.cur, s.trying = scr, false
			close(s.back)
			s.back = make(chan struct{})
			s.mu.Unlock()
			s.logf("[agent-host] the display opened again; offering the screen again")
			return
		}
		// Said once for each different reason, not at every attempt.
		if msg := err.Error(); msg != said {
			s.logf("[agent-host] the display cannot be opened yet (%v); still trying", err)
			said = msg
		}
		if wait *= 2; wait > s.most {
			wait = s.most
		}
	}
}

// reopened is closed when the display next opens again.
func (s *ReopeningScreen) reopened() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.back
}

func (s *ReopeningScreen) Describe() (screenview.Screen, error) {
	var d screenview.Screen
	err := s.use(func(scr Screen) (err error) { d, err = scr.Describe(); return })
	return d, err
}

func (s *ReopeningScreen) Capture() (*image.RGBA, error) {
	var img *image.RGBA
	err := s.use(func(scr Screen) (err error) { img, err = scr.Capture(); return })
	return img, err
}

func (s *ReopeningScreen) Apply(e screenview.Event) error {
	return s.use(func(scr Screen) error { return scr.Apply(e) })
}

// Release lets go of what is held on the open display. A display that went
// away holds nothing of this program's, and a new one has had nothing
// pressed yet.
func (s *ReopeningScreen) Release() error {
	err := s.use(func(scr Screen) error { return scr.Release() })
	if errors.Is(err, ErrScreenRestarting) {
		return nil
	}
	return err
}

// Close closes the screen and stops opening it again.
func (s *ReopeningScreen) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	var err error
	if s.cur != nil {
		err = s.cur.Close()
		s.cur = nil
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}
