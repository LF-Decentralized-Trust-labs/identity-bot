package anchored

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTheFloorsAreKeptAndNeverLowered(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	dir := t.TempDir()
	store := FileFloors{Path: filepath.Join(dir, "floors.json")}
	c := &Checker{Pin: p.pin(), Store: store}

	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err != nil {
		t.Fatal(err)
	}
	fl, _ := store.Load()
	if fl.ListSequence != 7 || !fl.HasKeyHistory || fl.KeyHistorySN != int(p.last.SN) {
		t.Fatalf("recorded %+v", fl)
	}
	if fi, _ := os.Stat(store.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// a stale bundle put back is refused by what is held, though it is as good as the day it was made
	old := p.bundle()
	oldTip := p.tip()
	published(p, 8)
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(old, p.answers(oldTip, 2), now); !errors.Is(err, ErrBehind) {
		t.Fatalf("an old bundle after a newer one: %v", err)
	}
	// the same bundle again is fine
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err != nil {
		t.Fatal(err)
	}
}

func TestADamagedFloorsFileRefusesEverything(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	path := filepath.Join(t.TempDir(), "floors.json")
	for _, body := range []string{"", "garbage", `{"list_sequence":-1}`, `{"list_sequence":1,"extra":1}`, `{"has_key_history":true}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c := &Checker{Pin: p.pin(), Store: FileFloors{Path: path}}
		if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err == nil {
			t.Fatalf("a damaged floors file (%q) was read as empty", body)
		}
	}
}

func TestTheFloorsNeverFallBelowTheSnapshotTheBuildShippedWith(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	held := tipAt(p, 1)
	published(p, 8)
	// the store is empty (deleted), but the build's snapshot already stood at list 8
	snap := Floors{ListSequence: 8, ListDigest: "x", HasKeyHistory: true, KeyHistorySN: held.SN, KeyHistorySAID: held.SAID}
	c := &Checker{Pin: p.pin(), Store: FileFloors{Path: filepath.Join(t.TempDir(), "f")}, Snapshot: snap}
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err == nil {
		t.Fatal("a list of the snapshot's own sequence with other content was accepted")
	}
	snap.ListSequence = 9
	c.Snapshot = snap
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err == nil {
		t.Fatal("a list below the snapshot's sequence was accepted")
	}
}

func TestPinnedFromTheBuild(t *testing.T) {
	if _, err := Pinned(); !errors.Is(err, ErrNoPin) {
		t.Fatalf("a build with no pin: %v", err)
	}
	p := onekey(t)
	published(p, 7)
	pin, err := ParsePin(p.aid, base64RawURL(p.icp), p.registry, p.schema)
	if err != nil || pin.Publisher != p.aid {
		t.Fatalf("%v", err)
	}
	if _, err := ParsePin(p.aid, base64RawURL(onekey(t).icp), p.registry, p.schema); err == nil {
		t.Fatal("an inception of another identity was pinned for this one")
	}
}
