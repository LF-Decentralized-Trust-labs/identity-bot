package ratewindow

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestAHitFallsOutOfTheWindowAfterItsSpan(t *testing.T) {
	c := &clock{time.Unix(1_000_000, 0)}
	w := New(2, time.Hour, 0, c.now)
	if !w.Allow("a") || !w.Allow("a") || w.Allow("a") {
		t.Fatal("want two hits allowed and the third refused")
	}
	c.advance(59 * time.Minute)
	if w.Allow("a") {
		t.Fatal("hits an hour old less a minute must still count")
	}
	c.advance(2 * time.Minute)
	if got := w.Count("a"); got != 0 {
		t.Fatalf("hits past the span still count: %d", got)
	}
	if !w.Allow("a") {
		t.Fatal("a hit was refused after the window slid past the old ones")
	}
}

func TestWouldCountsAndRemembersNothing(t *testing.T) {
	w := New(1, time.Minute, 10, nil)
	if !w.Would("x") || w.Remembers("x") || w.Keys() != 0 {
		t.Fatal("Would must not remember a key")
	}
	w.Allow("x")
	if w.Would("x") {
		t.Fatal("Would let a hit through that Allow would refuse")
	}
}

func TestRecordCountsPastTheLimit(t *testing.T) {
	w := New(1, time.Minute, 0, nil)
	w.Record("p")
	w.Record("p")
	if got := w.Count("p"); got != 2 {
		t.Fatalf("want 2 recorded hits, got %d", got)
	}
}

func TestTheTableIsBoundedAndForgetsExpiredKeys(t *testing.T) {
	c := &clock{time.Unix(1_000_000, 0)}
	w := New(5, time.Minute, 100, c.now)
	for i := 0; i < 200; i++ {
		w.Allow(fmt.Sprint("k", i))
	}
	if w.Keys() != 100 {
		t.Fatalf("want the table held at its bound of 100, got %d", w.Keys())
	}
	if w.Allow("newcomer") || w.Would("newcomer") || w.Record("newcomer") {
		t.Fatal("a table full of live keys admitted a newcomer")
	}
	c.advance(2 * time.Minute)
	if !w.Would("newcomer") || !w.Allow("newcomer") {
		t.Fatal("a table full of expired keys locked a newcomer out")
	}
	if w.Keys() != 1 {
		t.Fatalf("expired keys were not forgotten: %d held", w.Keys())
	}
}
