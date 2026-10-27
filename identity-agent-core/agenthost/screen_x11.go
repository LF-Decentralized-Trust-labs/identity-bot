//go:build linux || freebsd || openbsd || netbsd

package agenthost

import (
	"fmt"
	"image"
	"os"
	"sync"

	"identity-agent-core/screenview"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// The screen of a machine running an X display, read and driven over the X
// protocol itself: GetImage for the picture, and the XTEST extension for
// clicks and keys. No screenshot or input program is needed on the machine.

// OpenScreen opens the X display named, or $DISPLAY when display is empty.
// A machine with neither has no screen this program can show.
func OpenScreen(display string) (Screen, error) {
	if display == "" {
		display = os.Getenv("DISPLAY")
	}
	if display == "" {
		return nil, ErrNoScreen
	}
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("%w: the display %s could not be opened: %v", ErrNoScreen, display, err)
	}
	setup := xproto.Setup(conn)
	root := setup.DefaultScreen(conn)
	s := &x11Screen{conn: conn, root: root.Root, minKey: setup.MinKeycode, maxKey: setup.MaxKeycode}
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
	// keys maps a keysym to the key that types it, and whether shift is
	// needed, read once.
	keys map[xproto.Keysym]keyAt
}

type keyAt struct {
	code  xproto.Keycode
	shift bool
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
	w, h, err := s.size()
	if err != nil {
		return screenview.Screen{}, err
	}
	return screenview.Screen{Width: w, Height: h, CanControl: s.canControl}, nil
}

func (s *x11Screen) Capture() (*image.RGBA, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *x11Screen) fake(kind byte, detail byte, x, y int16) error {
	return xtest.FakeInputChecked(s.conn, kind, detail, 0, s.root, x, y, 0).Check()
}

func (s *x11Screen) Apply(e screenview.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canControl {
		return fmt.Errorf("this display cannot take clicks and keys")
	}
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

func (s *x11Screen) keymap() (map[xproto.Keysym]keyAt, error) {
	if s.keys != nil {
		return s.keys, nil
	}
	n := byte(s.maxKey - s.minKey + 1)
	rep, err := xproto.GetKeyboardMapping(s.conn, s.minKey, n).Reply()
	if err != nil {
		return nil, err
	}
	per := int(rep.KeysymsPerKeycode)
	keys := map[xproto.Keysym]keyAt{}
	for i := 0; i < int(n); i++ {
		code := xproto.Keycode(int(s.minKey) + i)
		for j := 0; j < per && j < 2; j++ {
			sym := rep.Keysyms[i*per+j]
			if sym == 0 {
				continue
			}
			if _, ok := keys[sym]; !ok {
				keys[sym] = keyAt{code: code, shift: j == 1}
			}
		}
	}
	s.keys = keys
	return keys, nil
}

// typeKeysym presses and releases the key for a keysym, holding the keys
// named and shift where the keysym needs it. A keysym no key types — a
// character not on this keyboard — is typed by lending it a spare key for the
// moment, as the X protocol allows, and giving the key back after.
func (s *x11Screen) typeKeysym(sym xproto.Keysym, mods []string) error {
	keys, err := s.keymap()
	if err != nil {
		return err
	}
	k, ok := keys[sym]
	restore := func() error { return nil }
	if !ok {
		spare, found := s.spareKey(keys)
		if !found {
			return fmt.Errorf("no key on this keyboard can type that character")
		}
		if err := xproto.ChangeKeyboardMappingChecked(s.conn, 1, spare, 1, []xproto.Keysym{sym}).Check(); err != nil {
			return err
		}
		k = keyAt{code: spare}
		restore = func() error {
			return xproto.ChangeKeyboardMappingChecked(s.conn, 1, spare, 1, []xproto.Keysym{0}).Check()
		}
	}
	defer func() { _ = restore() }()
	var held []xproto.Keycode
	hold := func(sym xproto.Keysym) error {
		m, ok := keys[sym]
		if !ok {
			return fmt.Errorf("this keyboard has no key for a held key")
		}
		held = append(held, m.code)
		return s.fake(xproto.KeyPress, byte(m.code), 0, 0)
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

// spareKey is a key that types nothing, which can be lent a keysym.
func (s *x11Screen) spareKey(keys map[xproto.Keysym]keyAt) (xproto.Keycode, bool) {
	used := map[xproto.Keycode]bool{}
	for _, k := range keys {
		used[k.code] = true
	}
	for c := int(s.maxKey); c >= int(s.minKey); c-- {
		if !used[xproto.Keycode(c)] {
			return xproto.Keycode(c), true
		}
	}
	return 0, false
}

func (s *x11Screen) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.Close()
	return nil
}
