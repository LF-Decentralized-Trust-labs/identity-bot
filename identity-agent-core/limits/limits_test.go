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
