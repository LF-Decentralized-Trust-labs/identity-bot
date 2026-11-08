package trail

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"identity-agent-core/limits"
)

// rangedApp answers a read with only the entries of the range asked for, as a
// real app does, so paging is seen to ask for less.
type rangedApp struct {
	*app
	asked [][2]string
}

func (r *rangedApp) Read(ctx context.Context, c, first, last string) ([]Stored, error) {
	r.asked = append(r.asked, [2]string{first, last})
	all, err := r.app.Read(ctx, c, "", "")
	if err != nil {
		return nil, err
	}
	var out []Stored
	in := first == ""
	for _, s := range all {
		if s.EntryID == first {
			in = true
		}
		if in {
			out = append(out, s)
		}
		if last != "" && s.EntryID == last {
			break
		}
	}
	return out, nil
}

func pagedFixture(t *testing.T, readBytes int) (*fixture, *rangedApp) {
	f := newFixture(t)
	ra := &rangedApp{app: f.app}
	f.tr.backend = ra
	l := limits.Defaults()
	l.ReadBytes = readBytes
	f.tr.lim = l
	for i := 0; i < 5; i++ {
		f.write(f.say(alice, "message", bot, fmt.Sprintf("%02d-%s", i, strings.Repeat("x", 97)), nil)) // 100 bytes of words
	}
	return f, ra
}

// What the app returns past one read's size is refused, not passed on.
func TestAReadLongerThanOneReadMayCarryIsRefused(t *testing.T) {
	f, _ := pagedFixture(t, 250)
	if _, err := f.read(alice); err == nil || err.Error() != ReasonTooLarge {
		t.Fatalf("got %v", err)
	}
}

// A long range is read in pages: every entry once, in order, each page checked
// against the trail, none larger than a read may carry.
func TestALongRangeIsReadInPages(t *testing.T) {
	f, ra := pagedFixture(t, 250)
	var got []string
	first := ""
	pages := 0
	for {
		page, next, err := f.tr.ReadPage(context.Background(), alice, "c1", first, "")
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		size := 0
		for _, p := range page {
			got = append(got, string(p.Words))
			size += len(p.Words) + len(p.Salt)
		}
		if size > 250 {
			t.Fatalf("a page of %d bytes", size)
		}
		if next == "" {
			break
		}
		first = next
		if pages > 10 {
			t.Fatal("never ends")
		}
	}
	if len(got) != 5 || !strings.HasPrefix(got[0], "00-") || !strings.HasPrefix(got[4], "04-") {
		t.Fatalf("got %d entries: %v", len(got), got)
	}
	if pages < 2 || len(ra.asked) < pages {
		t.Fatalf("%d pages, app asked %v", pages, ra.asked)
	}
}

// A range that fits is one page with nothing after it; one entry too big for a
// read is refused, not looped on.
func TestAFittingRangeIsOnePageAndAnOversizedEntryIsRefused(t *testing.T) {
	f, _ := pagedFixture(t, 1<<20)
	page, next, err := f.tr.ReadPage(context.Background(), alice, "c1", "", "")
	if err != nil || len(page) != 5 || next != "" {
		t.Fatalf("%d %q %v", len(page), next, err)
	}
	f.tr.lim.ReadBytes = 50
	if _, _, err := f.tr.ReadPage(context.Background(), alice, "c1", "", ""); err == nil || err.Error() != ReasonTooLarge {
		t.Fatalf("got %v", err)
	}
	if _, _, err := f.tr.ReadPage(context.Background(), bob, "c1", "", ""); err == nil || err.Error() != ReasonMayNotRead {
		t.Fatalf("someone who may not read got %v", err)
	}
}

// An entry whose message the delivery queue gave up on is marked after it, once,
// and stays committed and readable.
func TestAnEntryNotDeliveredIsMarkedOnceAndStaysKept(t *testing.T) {
	f := newFixture(t)
	r := f.write(f.say(alice, "message", bot, "hello", nil))
	if err := f.tr.MarkNotDelivered("c1", r.EntryID, "the recipient was not reachable for 7 days"); err != nil {
		t.Fatal(err)
	}
	es := f.tr.Entries("c1")
	if es[0].State() != Committed || es[0].NotDelivered == nil || es[0].NotDelivered.Reason == "" {
		t.Fatalf("%+v", es[0])
	}
	if len(f.tr.Committed("c1")) != 1 {
		t.Fatal("a not-delivered entry stopped being readable")
	}
	if err := f.tr.MarkNotDelivered("c1", r.EntryID, "again"); err == nil {
		t.Fatal("an entry was marked twice")
	}
	if err := f.tr.MarkNotDelivered("c1", "e99", "x"); err == nil {
		t.Fatal("an entry that is not there was marked")
	}
	// A refused or not-kept entry was never delivered, so there is nothing to mark.
	f.app.refuse = true
	nk := f.write(f.say(alice, "message", bot, "x", nil))
	if nk.State == Committed {
		t.Fatal("setup")
	}
	if err := f.tr.MarkNotDelivered("c1", nk.EntryID, "x"); err == nil {
		t.Fatal("an entry that was not kept was marked not delivered")
	}
}
