//go:build linux || freebsd || openbsd || netbsd

package agenthost

import (
	"errors"
	"fmt"
	"image"
	"os"
	"sync"
	"time"

	"identity-agent-core/screenview"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// The screen of a machine running an X display, read and driven over the X
// protocol itself: GetImage for the picture, and the XTEST extension for
// clicks and keys. No screenshot or input program is needed on the machine.

// OpenScreen opens the X display named, or $DISPLAY when display is empty.
// A machine with neither has no screen this program can show. A display on
// another machine, reached over the network, is refused unless allowNetwork
// says it was asked for (see checkDisplay).
func OpenScreen(display string, allowNetwork bool) (Screen, error) {
	if display == "" {
		display = os.Getenv("DISPLAY")
	}
	if display == "" {
		return nil, ErrNoScreen
	}
	if err := checkDisplay(display, allowNetwork); err != nil {
		return nil, err
	}
	// The display can restart under the body, or not be up yet when the body
	// starts: it is opened again whenever it goes (ReopeningScreen).
	scr, err := KeepScreenOpen(func() (Screen, error) { return openX11(display) },
		func(err error) bool { return errors.Is(err, errDisplayUnreachable) })
	if err != nil {
		return nil, err
	}
	return scr, nil
}

// errDisplayUnreachable is a display that could not be connected to: not up
// yet, or restarting.
var errDisplayUnreachable = errors.New("the display could not be reached")

// openX11 connects to an X display and reads what it is.
func openX11(display string) (Screen, error) {
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("%w: the display %s could not be opened: %w: %v", ErrNoScreen, display, errDisplayUnreachable, err)
	}
	setup := xproto.Setup(conn)
	root := setup.DefaultScreen(conn)
	s := &x11Screen{conn: conn, root: root.Root, minKey: setup.MinKeycode, maxKey: setup.MaxKeycode,
		buttons: map[byte]bool{}, keysDown: map[byte]bool{}}
	s.lender = newKeyLender(x11Keys{s}, nil)
	if err := s.checkFormat(setup, root); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrNoScreen, err)
	}
	// Without XTEST the screen can be shown and not driven.
	if xtest.Init(conn) == nil {
		if _, err := xtest.GetVersion(conn, 2, 2).Reply(); err == nil {
			s.canControl = true
		}
	}
	return s, nil
}

type x11Screen struct {
	mu         sync.Mutex
	conn       *xgb.Conn
	root       xproto.Window
	canControl bool
	minKey     xproto.Keycode
	maxKey     xproto.Keycode
	// kb is the keyboard's mapping as last read, or nil once it may have
	// changed: the display says so with a MappingNotify, which every program
	// is sent whether it asked or not.
	kb *keyboardMap
	// lender lends spare keys to characters no key types.
	lender *keyLender
	// giveBackAt is when a lent key is next due back, with a timer set for
	// it.
	giveBackAt time.Time
	// buttons and keysDown are what this program is holding down on the
	// display now, so they can be let go when control ends.
	buttons  map[byte]bool
	keysDown map[byte]bool
}

// x11Keys reads and writes the display's keyboard mapping for the lender.
type x11Keys struct{ s *x11Screen }

func (k x11Keys) readKey(code byte) (keyboardMap, error) {
	rep, err := xproto.GetKeyboardMapping(k.s.conn, xproto.Keycode(code), 1).Reply()
	if err != nil {
		return keyboardMap{}, err
	}
	return keyboardMap{Min: code, Per: int(rep.KeysymsPerKeycode), Syms: keysyms(rep.Keysyms)}, nil
}

func (k x11Keys) writeKey(code byte, per int, syms []uint32) error {
	out := make([]xproto.Keysym, len(syms))
	for i, s := range syms {
		out[i] = xproto.Keysym(s)
	}
	k.s.kb = nil
	return xproto.ChangeKeyboardMappingChecked(k.s.conn, 1, xproto.Keycode(code), byte(per), out).Check()
}

func keysyms(in []xproto.Keysym) []uint32 {
	out := make([]uint32, len(in))
	for i, s := range in {
		out[i] = uint32(s)
	}
	return out
}

// drain reads what the display sent unasked. A MappingNotify means the
// keyboard changed, so the copy is read again before it is used. Read on
// every call, because an X connection whose events nobody reads stops
// answering once enough have queued.
func (s *x11Screen) drain() {
	for {
		ev, err := s.conn.PollForEvent()
		if ev == nil && err == nil {
			return
		}
		if _, ok := ev.(xproto.MappingNotifyEvent); ok {
			s.kb = nil
		}
	}
}

// giveBackDue gives back the lent keys whose time is up, and sets a timer for
// the next, so a key is given back even when nothing else is typed.
func (s *x11Screen) giveBackDue() {
	next, err := s.lender.giveBackDue()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-host: a key lent to a character could not be given back: %v\n", err)
	}
	if next.IsZero() || (!s.giveBackAt.IsZero() && !next.Before(s.giveBackAt)) {
		return
	}
	s.giveBackAt = next
	time.AfterFunc(time.Until(next)+10*time.Millisecond, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.giveBackAt = time.Time{}
		if s.conn != nil {
			s.giveBackDue()
		}
	})
}

// checkFormat accepts the one pixel layout the picture is read in: 32 bits a
// pixel, blue in the lowest byte, red in the third, least significant byte
// first — what every common X server uses for a 24- or 32-bit display.
func (s *x11Screen) checkFormat(setup *xproto.SetupInfo, root *xproto.ScreenInfo) error {
	if setup.ImageByteOrder != xproto.ImageOrderLSBFirst {
		return fmt.Errorf("the display stores pixels most significant byte first, which is not supported")
	}
	bpp := 0
	for _, f := range setup.PixmapFormats {
		if f.Depth == root.RootDepth {
			bpp = int(f.BitsPerPixel)
		}
	}
	if bpp != 32 {
		return fmt.Errorf("the display has %d bits a pixel at depth %d; 32 is supported", bpp, root.RootDepth)
	}
	for _, d := range root.AllowedDepths {
		for _, v := range d.Visuals {
			if v.VisualId == root.RootVisual {
				if v.RedMask != 0xff0000 || v.GreenMask != 0xff00 || v.BlueMask != 0xff {
					return fmt.Errorf("the display's colours are laid out in a way that is not supported")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("the display's colour layout could not be read")
}

func (s *x11Screen) size() (int, int, error) {
	g, err := xproto.GetGeometry(s.conn, xproto.Drawable(s.root)).Reply()
	if err != nil {
		return 0, 0, err
	}
	return int(g.Width), int(g.Height), nil
}

func (s *x11Screen) Describe() (screenview.Screen, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drain()
	w, h, err := s.size()
	if err != nil {
		return screenview.Screen{}, err
	}
	return screenview.Screen{Width: w, Height: h, CanControl: s.canControl}, nil
}

func (s *x11Screen) Capture() (*image.RGBA, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drain()
	w, h, err := s.size()
	if err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// In bands, so no one reply is larger than the X server allows.
	band := (4 << 20) / (w * 4)
	if band < 1 {
		band = 1
	}
	for y := 0; y < h; y += band {
		bh := band
		if y+bh > h {
			bh = h - y
		}
		rep, err := xproto.GetImage(s.conn, xproto.ImageFormatZPixmap, xproto.Drawable(s.root),
			0, int16(y), uint16(w), uint16(bh), 0xffffffff).Reply()
		if err != nil {
			return nil, err
		}
		if len(rep.Data) < w*bh*4 {
			return nil, fmt.Errorf("the display sent %d bytes for %d pixels", len(rep.Data), w*bh)
		}
		o := img.PixOffset(0, y)
		for i := 0; i < w*bh; i++ {
			src := rep.Data[i*4 : i*4+4]
			dst := img.Pix[o+i*4 : o+i*4+4]
			dst[0], dst[1], dst[2], dst[3] = src[2], src[1], src[0], 0xff
		}
	}
	return img, nil
}

// fake passes one press, release or move to the display, keeping account of
// what is held down.
func (s *x11Screen) fake(kind byte, detail byte, x, y int16) error {
	if err := xtest.FakeInputChecked(s.conn, kind, detail, 0, s.root, x, y, 0).Check(); err != nil {
		return err
	}
	switch kind {
	case xproto.ButtonPress:
		s.buttons[detail] = true
	case xproto.ButtonRelease:
		delete(s.buttons, detail)
	case xproto.KeyPress:
		s.keysDown[detail] = true
	case xproto.KeyRelease:
		delete(s.keysDown, detail)
	}
	return nil
}

// Release lets go of every button and key this program is holding down, so a
// person who gave back control, or stopped watching, mid-drag or mid-shortcut
// leaves nothing held.
func (s *x11Screen) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canControl {
		return nil
	}
	var first error
	for b := range s.buttons {
		if err := s.fake(xproto.ButtonRelease, b, 0, 0); err != nil && first == nil {
			first = err
		}
	}
	for k := range s.keysDown {
		if err := s.fake(xproto.KeyRelease, k, 0, 0); err != nil && first == nil {
			first = err
		}
	}
	// A key that could not be let go is forgotten rather than tried forever.
	s.buttons, s.keysDown = map[byte]bool{}, map[byte]bool{}
	return first
}

func (s *x11Screen) Apply(e screenview.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canControl {
		return fmt.Errorf("this display cannot take clicks and keys")
	}
	s.drain()
	defer s.giveBackDue()
	x, y := int16(e.X), int16(e.Y)
	move := func() error { return s.fake(xproto.MotionNotify, 0, x, y) }
	press := func(button byte) error {
		if err := s.fake(xproto.ButtonPress, button, 0, 0); err != nil {
			return err
		}
		return s.fake(xproto.ButtonRelease, button, 0, 0)
	}
	switch e.Type {
	case "move":
		return move()
	case "click":
		if err := move(); err != nil {
			return err
		}
		return press(byte(e.Button))
	case "down", "up":
		if err := move(); err != nil {
			return err
		}
		kind := byte(xproto.ButtonPress)
		if e.Type == "up" {
			kind = xproto.ButtonRelease
		}
		return s.fake(kind, byte(e.Button), 0, 0)
	case "scroll":
		if err := move(); err != nil {
			return err
		}
		// X scrolls with buttons 4 (up) and 5 (down).
		button, n := byte(5), e.DY
		if n < 0 {
			button, n = 4, -n
		}
		for i := 0; i < n; i++ {
			if err := press(button); err != nil {
				return err
			}
		}
		return nil
	case "key":
		if sym, ok := screenview.Keys[e.Key]; ok {
			return s.typeKeysym(xproto.Keysym(sym), e.Mods)
		}
		return s.typeKeysym(runeKeysym(rune(e.Key[0])), e.Mods)
	case "text":
		for _, r := range e.Text {
			if err := s.typeKeysym(runeKeysym(r), e.Mods); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%q is not something a person can do on a screen", e.Type)
}

// runeKeysym is the keysym that types a character.
func runeKeysym(r rune) xproto.Keysym {
	switch {
	case r == '\n':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xff:
		return xproto.Keysym(r)
	}
	return xproto.Keysym(0x01000000 | uint32(r))
}

// keymap is the keyboard's whole mapping, every level of every key, read
// again whenever it may have changed.
func (s *x11Screen) keymap() (keyboardMap, error) {
	if s.kb != nil {
		return *s.kb, nil
	}
	n := byte(s.maxKey - s.minKey + 1)
	rep, err := xproto.GetKeyboardMapping(s.conn, s.minKey, n).Reply()
	if err != nil {
		return keyboardMap{}, err
	}
	kb := keyboardMap{Min: byte(s.minKey), Per: int(rep.KeysymsPerKeycode), Syms: keysyms(rep.Keysyms)}
	s.kb = &kb
	return kb, nil
}

// typeKeysym presses and releases the key for a keysym, holding the keys
// named and shift where the keysym needs it. A keysym no key types — a
// character not on this keyboard — is typed by lending it a key that types
// nothing at any level, as the X protocol allows; the key is given back
// exactly as it was a moment later (keyLender).
func (s *x11Screen) typeKeysym(sym xproto.Keysym, mods []string) error {
	kb, err := s.keymap()
	if err != nil {
		return err
	}
	type keyAt struct {
		code  xproto.Keycode
		shift bool
	}
	var k keyAt
	if code, shift, ok := kb.find(uint32(sym)); ok {
		k = keyAt{xproto.Keycode(code), shift}
		// A key lent a moment ago keeps its character while it is in use.
		s.lender.touch(code)
	} else {
		code, err := s.lender.borrow(uint32(sym), kb)
		if err != nil {
			return err
		}
		k = keyAt{code: xproto.Keycode(code)}
		if kb, err = s.keymap(); err != nil {
			return err
		}
	}
	var held []xproto.Keycode
	hold := func(sym xproto.Keysym) error {
		code, _, ok := kb.find(uint32(sym))
		if !ok {
			return fmt.Errorf("this keyboard has no key for a held key")
		}
		held = append(held, xproto.Keycode(code))
		return s.fake(xproto.KeyPress, code, 0, 0)
	}
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = s.fake(xproto.KeyRelease, byte(held[i]), 0, 0)
		}
	}()
	for _, m := range mods {
		if err := hold(xproto.Keysym(screenview.Mods[m])); err != nil {
			return err
		}
	}
	if k.shift {
		if err := hold(xproto.Keysym(screenview.Mods["shift"])); err != nil {
			return err
		}
	}
	if err := s.fake(xproto.KeyPress, byte(k.code), 0, 0); err != nil {
		return err
	}
	return s.fake(xproto.KeyRelease, byte(k.code), 0, 0)
}

// abandon closes the connection to a display that has gone. Nothing held
// down or lent on it is let go of or given back: the display that held them
// is gone, and the next one starts with nothing pressed and its own keyboard.
func (s *x11Screen) abandon() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return
	}
	// Close ends xgb's goroutines for this connection; they have already
	// stopped reading once the display went.
	s.conn.Close()
	s.conn = nil
	s.buttons, s.keysDown = map[byte]bool{}, map[byte]bool{}
	s.lender.forget()
	s.kb = nil
}

func (s *x11Screen) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	if s.canControl {
		for b := range s.buttons {
			_ = s.fake(xproto.ButtonRelease, b, 0, 0)
		}
		for k := range s.keysDown {
			_ = s.fake(xproto.KeyRelease, k, 0, 0)
		}
		_ = s.lender.giveBackAll()
	}
	s.conn.Close()
	s.conn = nil
	return nil
}
