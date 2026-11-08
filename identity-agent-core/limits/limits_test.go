package limits

import (
	"testing"
	"time"
)

// A phone scales its capacity to a tenth and nothing else.
func TestAPhoneScalesOnlyCapacity(t *testing.T) {
	d, p := Defaults(), Defaults().ForPhone()
	if p.ForwardTimeout != d.ForwardTimeout || p.ForwardTimeout != 10*time.Second {
		t.Fatalf("the forwarding timeout changed on a phone: %v", p.ForwardTimeout)
	}
	if p.BackoffStart != d.BackoffStart || p.BackoffMax != d.BackoffMax || p.ReadBytes != d.ReadBytes ||
		p.MessagesPerPersonPerHour != d.MessagesPerPersonPerHour || p.MaxTurns != d.MaxTurns || p.QueueMaxAge != d.QueueMaxAge {
		t.Fatal("a non-capacity limit changed on a phone")
	}
	if p.QueueMessages != 1000 || p.QueueBytes != d.QueueBytes/10 || p.EntriesPerConversation != 10_000 ||
		p.RatePerSecond != 2 || p.RateBurst != 10 {
		t.Fatalf("capacity did not scale to a tenth: %+v", p)
	}
}

func TestBackoffDoublesToItsCapWithJitter(t *testing.T) {
	l := Defaults()
	if l.Backoff(0, 0) != 2*time.Second || l.Backoff(1, 0) != 4*time.Second || l.Backoff(20, 0) != 5*time.Minute {
		t.Fatal("backoff is not 2s doubling to 5m")
	}
	if j := l.Backoff(20, 0.999); j >= 5*time.Minute || j < 225*time.Second {
		t.Fatalf("jitter out of range: %v", j)
	}
}

func TestAnAppIsHeldToItsRateWithBursts(t *testing.T) {
	now := time.Unix(0, 0)
	r := NewRate(Defaults(), func() time.Time { return now })
	n := 0
	for r.Allow("app") {
		n++
	}
	if n != 100 {
		t.Fatalf("burst was %d", n)
	}
	if !r.Allow("other") {
		t.Fatal("one app's burst limited another")
	}
	now = now.Add(time.Second)
	n = 0
	for r.Allow("app") {
		n++
	}
	if n != 20 {
		t.Fatalf("refilled %d in a second", n)
	}
}

// An app that keeps asking past its rate is told to wait longer each time, up
// to the backoff's ceiling, and is let in again, with the count cleared, once it
// has waited.
func TestAnAppOverItsRateIsToldToBackOff(t *testing.T) {
	l := Defaults()
	l.RatePerSecond, l.RateBurst = 1, 1
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	r := NewRate(l, func() time.Time { return now })
	if ok, _ := r.Try("app", 0); !ok {
		t.Fatal("the first request was refused")
	}
	var last time.Duration
	for i := 0; i < 12; i++ {
		ok, wait := r.Try("app", 0)
		if ok || wait < last || wait > l.BackoffMax {
			t.Fatalf("refusal %d: ok=%v wait=%v after %v", i, ok, wait, last)
		}
		last = wait
	}
	if last != l.BackoffMax {
		t.Fatalf("the wait never reached the ceiling: %v", last)
	}
	if ok, _ := r.Try("other", 0); !ok {
		t.Fatal("one app's rate held another back")
	}
	now = now.Add(2 * time.Second)
	if ok, _ := r.Try("app", 0); !ok {
		t.Fatal("the app was not let in after it waited")
	}
	if ok, wait := r.Try("app", 0); ok || wait > l.BackoffStart+time.Second {
		t.Fatalf("the count was not cleared: ok=%v wait=%v", ok, wait)
	}
}
