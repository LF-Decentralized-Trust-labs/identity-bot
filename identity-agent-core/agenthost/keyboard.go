package agenthost

import (
	"fmt"
	"time"
)

// Typing a character the machine's keyboard has no key for.
//
// The X protocol lets a program change what a key types. To type a character
// no key types, a body lends it a key that types nothing at all, presses it,
// and gives the key back afterwards. Kept apart from the X connection so the
// choosing and the giving back can be tested without a display.

// keyboardMap is a copy of a keyboard's mapping: for each key from Min, Per
// symbols, one for each level (plain, with shift, and the rest).
type keyboardMap struct {
	Min  byte
	Per  int
	Syms []uint32
}

// keyCount is how many keys the copy covers.
func (k keyboardMap) keyCount() int {
	if k.Per <= 0 {
		return 0
	}
	return len(k.Syms) / k.Per
}

// row is every symbol of one key, at every level.
func (k keyboardMap) row(code byte) []uint32 {
	i := int(code) - int(k.Min)
	if i < 0 || i >= k.keyCount() {
		return nil
	}
	return k.Syms[i*k.Per : (i+1)*k.Per]
}

// find is the key that types sym, plain or with shift.
func (k keyboardMap) find(sym uint32) (code byte, shift, ok bool) {
	for i := 0; i < k.keyCount(); i++ {
		for j := 0; j < k.Per && j < 2; j++ {
			if k.Syms[i*k.Per+j] == sym && sym != 0 {
				return byte(int(k.Min) + i), j == 1, true
			}
		}
	}
	return 0, false, false
}

// typesNothing is a key with no symbol at any level.
func typesNothing(row []uint32) bool {
	if len(row) == 0 {
		return false
	}
	for _, s := range row {
		if s != 0 {
			return false
		}
	}
	return true
}

// spare is the highest key that types nothing at any level and is not
// skipped: one no person and no layout uses, so lending it changes nothing
// anybody relies on.
func (k keyboardMap) spare(skip map[byte]bool) (byte, bool) {
	for i := k.keyCount() - 1; i >= 0; i-- {
		code := byte(int(k.Min) + i)
		if !skip[code] && typesNothing(k.row(code)) {
			return code, true
		}
	}
	return 0, false
}

// keyboardServer is what lending a key needs from the display: reading a
// key's whole mapping now, and writing one.
type keyboardServer interface {
	readKey(code byte) (keyboardMap, error)
	writeKey(code byte, per int, syms []uint32) error
}

// lendFor is how long a lent key keeps its character after it was last
// pressed. Programs on the display learn of a changed key only when they next
// read the keyboard, so a key given back at once can reach a program that has
// not caught up yet as a key that types nothing.
const lendFor = 300 * time.Millisecond

type loan struct {
	sym uint32
	// was is the key's whole mapping before it was lent, at every level, and
	// per how many levels it had: what is written back.
	was   []uint32
	per   int
	until time.Time
}

// keyLender lends spare keys to characters and gives them back.
type keyLender struct {
	srv  keyboardServer
	now  func() time.Time
	lent map[byte]*loan
}

func newKeyLender(srv keyboardServer, now func() time.Time) *keyLender {
	if now == nil {
		now = time.Now
	}
	return &keyLender{srv: srv, now: now, lent: map[byte]*loan{}}
}

// borrow is a key that types sym now: one already lent to it, or a spare one
// lent to it here. kb is the keyboard as last read, used to choose; the chosen
// key is read again before it is changed, and only a key that still types
// nothing at any level is used.
func (l *keyLender) borrow(sym uint32, kb keyboardMap) (byte, error) {
	for code, ln := range l.lent {
		if ln.sym == sym {
			ln.until = l.now().Add(lendFor)
			return code, nil
		}
	}
	skip := map[byte]bool{}
	for code := range l.lent {
		skip[code] = true
	}
	for {
		code, ok := kb.spare(skip)
		if !ok {
			if len(l.lent) == 0 {
				return 0, fmt.Errorf("no key on this keyboard can type that character")
			}
			// Every spare key is lent: the one lent longest ago is given back
			// early and used again.
			oldest := byte(0)
			var at time.Time
			for c, ln := range l.lent {
				if at.IsZero() || ln.until.Before(at) {
					oldest, at = c, ln.until
				}
			}
			if err := l.giveBack(oldest); err != nil {
				return 0, err
			}
			delete(skip, oldest)
			continue
		}
		now, err := l.srv.readKey(code)
		if err != nil {
			return 0, err
		}
		was := now.row(code)
		if !typesNothing(was) {
			// The copy was out of date: this key types something now.
			skip[code] = true
			continue
		}
		syms := make([]uint32, now.Per)
		syms[0] = sym
		if len(syms) > 1 {
			syms[1] = sym
		}
		if err := l.srv.writeKey(code, now.Per, syms); err != nil {
			return 0, err
		}
		l.lent[code] = &loan{sym: sym, was: append([]uint32(nil), was...), per: now.Per, until: l.now().Add(lendFor)}
		return code, nil
	}
}

// touch keeps a lent key lent for a while longer, when it is pressed again.
func (l *keyLender) touch(code byte) {
	if ln, ok := l.lent[code]; ok {
		ln.until = l.now().Add(lendFor)
	}
}

// giveBack writes back exactly what a lent key had.
func (l *keyLender) giveBack(code byte) error {
	ln, ok := l.lent[code]
	if !ok {
		return nil
	}
	delete(l.lent, code)
	return l.srv.writeKey(code, ln.per, ln.was)
}

// giveBackDue gives back every key whose time is up, and says when the next
// one is due, or zero when none is lent.
func (l *keyLender) giveBackDue() (time.Time, error) {
	var first error
	var next time.Time
	now := l.now()
	for code, ln := range l.lent {
		if !now.Before(ln.until) {
			if err := l.giveBack(code); err != nil && first == nil {
				first = err
			}
			continue
		}
		if next.IsZero() || ln.until.Before(next) {
			next = ln.until
		}
	}
	return next, first
}

// giveBackAll gives back every lent key now.
func (l *keyLender) giveBackAll() error {
	var first error
	for code := range l.lent {
		if err := l.giveBack(code); err != nil && first == nil {
			first = err
		}
	}
	return first
}
