package agenthost

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// aKeyboard is a display's keyboard in a test: four levels a key, and every
// read and write of it recorded.
type aKeyboard struct {
	kb     keyboardMap
	writes []byte
}

func newKeyboard(rows ...[]uint32) *aKeyboard {
	k := &aKeyboard{kb: keyboardMap{Min: 8, Per: 4}}
	for _, r := range rows {
		k.kb.Syms = append(k.kb.Syms, r...)
	}
	return k
}

func (k *aKeyboard) readKey(code byte) (keyboardMap, error) {
	row := k.kb.row(code)
	if row == nil {
		return keyboardMap{}, errors.New("no such key")
	}
	return keyboardMap{Min: code, Per: k.kb.Per, Syms: append([]uint32(nil), row...)}, nil
}

func (k *aKeyboard) writeKey(code byte, per int, syms []uint32) error {
	if per != k.kb.Per || len(syms) != per {
		return errors.New("written with the wrong number of levels")
	}
	copy(k.kb.row(code), syms)
	k.writes = append(k.writes, code)
	return nil
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// A key is lent only when it types nothing at any level — a key whose plain
// level is empty but which types something with AltGr is somebody's — and it
// is given back exactly as it was, after a moment.
func TestOnlyAKeyThatTypesNothingIsLentAndItIsGivenBackAsItWas(t *testing.T) {
	const euro = 0x20ac
	k := newKeyboard(
		[]uint32{'a', 'A', 0, 0},       // 8
		[]uint32{0, 0, 0, 0},           // 9: types nothing
		[]uint32{0, 0, 0x00e9, 0x00c9}, // 10: types é with AltGr
	)
	c := &fakeClock{t: time.Unix(1000, 0)}
	l := newKeyLender(k, c.now)
	code, err := l.borrow(euro, k.kb)
	if err != nil {
		t.Fatal(err)
	}
	if code != 9 {
		t.Fatalf("key %d was lent; only key 9 types nothing at every level", code)
	}
	if got := k.kb.row(9); got[0] != euro {
		t.Fatalf("the lent key does not type the character: %v", got)
	}
	// Typed again soon after: the same key, kept lent.
	c.t = c.t.Add(lendFor / 2)
	if again, _ := l.borrow(euro, k.kb); again != 9 || len(k.writes) != 1 {
		t.Fatalf("the same character was lent another key (%d) or the key rewritten (%d writes)", again, len(k.writes))
	}
	// Not yet due: kept, so a program still reading the old keyboard gets it.
	c.t = c.t.Add(lendFor / 2)
	if _, err := l.giveBackDue(); err != nil || k.kb.row(9)[0] != euro {
		t.Fatalf("the key was given back before its time: %v %v", k.kb.row(9), err)
	}
	c.t = c.t.Add(lendFor)
	next, err := l.giveBackDue()
	if err != nil || !next.IsZero() {
		t.Fatalf("giving back: next %v, %v", next, err)
	}
	if got := k.kb.row(9); !reflect.DeepEqual(got, []uint32{0, 0, 0, 0}) {
		t.Fatalf("the key was not given back as it was: %v", got)
	}
	if got := k.kb.row(10); !reflect.DeepEqual(got, []uint32{0, 0, 0x00e9, 0x00c9}) {
		t.Fatalf("a key that types something with AltGr was changed: %v", got)
	}
}

// The keyboard as last read can be out of date: the chosen key is read again
// before it is changed, and passed over when it types something now.
func TestAKeyIsReadAgainBeforeItIsLent(t *testing.T) {
	k := newKeyboard([]uint32{0, 0, 0, 0}, []uint32{0, 0, 0, 0})
	stale := keyboardMap{Min: 8, Per: 4, Syms: append([]uint32(nil), k.kb.Syms...)}
	// Since it was read, somebody's layout gave key 9 a character.
	copy(k.kb.row(9), []uint32{'q', 'Q', 0, 0})
	l := newKeyLender(k, nil)
	code, err := l.borrow(0x20ac, stale)
	if err != nil {
		t.Fatal(err)
	}
	if code != 8 {
		t.Fatalf("key %d was lent; key 9 types q now", code)
	}
	if got := k.kb.row(9); !reflect.DeepEqual(got, []uint32{'q', 'Q', 0, 0}) {
		t.Fatalf("a key in use was overwritten: %v", got)
	}
}

// With every spare key lent, the one lent longest ago is given back early and
// used; with none at all, the character cannot be typed.
func TestWhenEverySpareKeyIsLent(t *testing.T) {
	k := newKeyboard([]uint32{0, 0, 0, 0})
	c := &fakeClock{t: time.Unix(1000, 0)}
	l := newKeyLender(k, c.now)
	if _, err := l.borrow(0x20ac, k.kb); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Millisecond)
	code, err := l.borrow(0x00a3, k.kb)
	if err != nil || code != 8 || k.kb.row(8)[0] != 0x00a3 {
		t.Fatalf("the one spare key was not reused: %d %v %v", code, k.kb.row(8), err)
	}
	if err := l.giveBackAll(); err != nil || !typesNothing(k.kb.row(8)) {
		t.Fatalf("giving back every key: %v %v", k.kb.row(8), err)
	}
	full := newKeyboard([]uint32{'a', 0, 0, 0})
	if _, err := newKeyLender(full, nil).borrow(0x20ac, full.kb); err == nil {
		t.Fatal("a key that types something was lent")
	}
}

// A display on another machine is told apart from one on this machine.
func TestADisplayOverTheNetworkIsRefusedUnlessAskedFor(t *testing.T) {
	for d, network := range map[string]bool{
		":0": false, ":1.0": false, "unix:0": false, "/tmp/.X11-unix/X0": false, "host/unix:0": false,
		"office:0": true, "10.0.0.5:1": true, "office/tcp:0": true, "[::1]:0": true,
	} {
		if got := isNetworkDisplay(d); got != network {
			t.Errorf("%q: over the network %v, want %v", d, got, network)
		}
	}
	if err := checkDisplay("office:0", false); !errors.Is(err, ErrNetworkDisplay) {
		t.Fatalf("a display over the network was opened without being asked for: %v", err)
	}
	if err := checkDisplay("office:0", true); err != nil {
		t.Fatalf("a display over the network was refused when asked for: %v", err)
	}
	if err := checkDisplay(":0", false); err != nil {
		t.Fatalf("this machine's display was refused: %v", err)
	}
}

// Keys lent on a display that has gone are forgotten, not given back on it:
// the next display starts with nothing lent.
func TestLentKeysAreForgottenWhenTheirDisplayGoes(t *testing.T) {
	srv := newKeyboard([]uint32{'a', 'A', 0, 0}, []uint32{0, 0, 0, 0})
	l := newKeyLender(srv, nil)
	if _, err := l.borrow(0x20ac, srv.kb); err != nil {
		t.Fatal(err)
	}
	writes := len(srv.writes)
	l.forget()
	if len(l.lent) != 0 {
		t.Fatalf("%d keys still lent after their display went", len(l.lent))
	}
	if err := l.giveBackAll(); err != nil || len(srv.writes) != writes {
		t.Fatalf("a forgotten key was given back on a display that had gone (%v)", err)
	}
}
