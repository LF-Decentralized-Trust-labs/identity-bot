package anchored

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/measurementlist"
)

// A device takes "now" as the later of its own clock and the newest
// published_at it has accepted (design section 4), because a host controls a
// sealed box's clock.

func TestAClockSetBackDoesNotReviveAListThatHasExpired(t *testing.T) {
	p := onekey(t)
	published(p, 7) // published t0, expires t0 + 60 days
	day := 24 * time.Hour

	// a device that has accepted a list published on day 70 and is then told it
	// is day 1 again
	held := Floors{NewestPublishedAt: t0.Add(70 * day).Unix()}
	_, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), held, t0.Add(day))
	if !errors.Is(err, measurementlist.ErrExpired) {
		t.Fatalf("an expired list was accepted on a clock set back: %v", err)
	}
	// the same clock without that history is what the floor is there to stop
	if _, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{}, t0.Add(day)); err != nil {
		t.Fatalf("the list is good on an honest clock: %v", err)
	}
	// a floor earlier than the clock changes nothing
	if _, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{NewestPublishedAt: t0.Unix()}, t0.Add(day)); err != nil {
		t.Fatalf("an older floor refused a good list: %v", err)
	}
}

func TestAClockSetBackDoesNotReopenAnEntrysClosedWindow(t *testing.T) {
	p := onekey(t)
	p.foundRegistry()
	day := 24 * time.Hour
	imgs := `{"individual":[{"image":"individual-v1","measurement":"` + meas(7) + `","computed_from":{"ovmf_sha256":"` +
		meas(1)[:64] + `","vcpus":1,"cpu_model":"EPYC-v4","cmdline_sha256":"` + meas(2)[:64] + `"},"valid_from":"2026-11-01T00:00:00Z","valid_until":"2026-12-01T00:00:00Z"}]}`
	p.issue(listSpec{sequence: 7, publishedAt: t0, expires: t0.Add(90 * day), images: imgs})
	inWindow := t0.Add(2 * day)
	res, err := Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{}, inWindow)
	if err != nil || len(res.List.Measurements("individual")) != 1 {
		t.Fatalf("inside its window: %v", err)
	}
	// the device has accepted a list published after the window closed
	res, err = Verify(p.bundle(), p.pin(), p.answers(p.tip(), 2), Floors{NewestPublishedAt: t0.Add(40 * day).Unix()}, inWindow)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.List.Measurements("individual")); n != 0 {
		t.Fatalf("an entry whose window the device has seen close was accepted again (%d)", n)
	}
}

func TestTheNewestPublishedAtIsKeptAndNeverLowered(t *testing.T) {
	p := onekey(t)
	p.foundRegistry()
	day := 24 * time.Hour
	p.issue(listSpec{sequence: 8, publishedAt: t0.Add(5 * day), expires: t0.Add(65 * day), images: defaultImages(meas(8))})
	store := FileFloors{Path: filepath.Join(t.TempDir(), "floors.json")}
	c := &Checker{Pin: p.pin(), Store: store}
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), t0.Add(6*day)); err != nil {
		t.Fatal(err)
	}
	fl, err := store.Load()
	if err != nil || fl.NewestPublishedAt != t0.Add(5*day).Unix() {
		t.Fatalf("recorded %+v (%v)", fl, err)
	}
	// Merge never lowers it, in either order
	for _, m := range []struct{ a, b Floors }{{fl, Floors{}}, {Floors{}, fl}, {fl, Floors{NewestPublishedAt: 1}}} {
		got, err := Merge(m.a, m.b)
		if err != nil || got.NewestPublishedAt != fl.NewestPublishedAt {
			t.Fatalf("merged to %+v (%v)", got, err)
		}
	}
	// a snapshot's higher value rises into the store
	got, _ := Merge(fl, Floors{NewestPublishedAt: fl.NewestPublishedAt + 100})
	if got.NewestPublishedAt != fl.NewestPublishedAt+100 {
		t.Fatal("a higher floor did not rise")
	}
	// the clock set back to before the list was even published: the floor is
	// what the list is judged against, so it still reads as published
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), t0); err != nil {
		t.Fatalf("a device that has accepted this list refused it on a clock set back: %v", err)
	}
}

func TestAFloorsFileFromBeforeThePublishedAtFloorStillReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floors.json")
	if err := os.WriteFile(path, []byte(`{"list_sequence":3,"list_digest":"x","has_key_history":false,"key_history_sn":0,"key_history_said":""}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fl, err := FileFloors{Path: path}.Load()
	if err != nil || fl.ListSequence != 3 || fl.NewestPublishedAt != 0 {
		t.Fatalf("%+v %v", fl, err)
	}
	if err := os.WriteFile(path, []byte(`{"list_sequence":3,"newest_published_at":-5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileFloors{Path: path}).Load(); err == nil {
		t.Fatal("a negative published_at floor was read")
	}
}
