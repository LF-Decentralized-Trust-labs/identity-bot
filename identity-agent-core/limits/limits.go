// Package limits holds the numbers that protect an Identity Agent from an app
// it forwards to, and the delivery queue from filling up. They are starting
// defaults, each a probe that testing will revise, so they live in one place.
//
// An Identity Agent on a phone's secure chip scales only its capacity (ForPhone).
// Its timeouts and backoff stay the same: a phone's network is slower, not
// faster.
package limits

import (
	"sync"
	"time"
)

// Limits is every number that bounds an app's reach into the Identity Agent.
type Limits struct {
	// ForwardTimeout is how long a forwarded call to an app may take.
	ForwardTimeout time.Duration
	// ReadBytes is the most one read returns; a longer range is read in pages.
	ReadBytes int
	// RatePerSecond and RateBurst hold each app to a request rate.
	RatePerSecond float64
	RateBurst     int
	// BackoffStart doubles up to BackoffMax for a sender told to retry.
	BackoffStart time.Duration
	BackoffMax   time.Duration
	// EntriesPerConversation bounds one conversation's record.
	EntriesPerConversation int
	// MessagesPerPersonPerHour bounds what one person may write in an hour.
	MessagesPerPersonPerHour int
	// MaxTurns is how many asks, replies and failures may follow one person's
	// message.
	MaxTurns int

	// The delivery queue: sealed messages held for a recipient that is briefly
	// offline.
	QueueMessages int
	QueueBytes    int64
	QueueMaxAge   time.Duration
	// QueueSharePercent is the most of the queue one conversation, and one
	// sender, may hold, so one busy pair cannot crowd out everyone else.
	QueueSharePercent int
}

// Defaults are the starting values.
func Defaults() Limits {
	return Limits{
		ForwardTimeout: 10 * time.Second,
		ReadBytes:      4 << 20,
		RatePerSecond:  20, RateBurst: 100,
		BackoffStart: 2 * time.Second, BackoffMax: 5 * time.Minute,
		EntriesPerConversation: 100_000, MessagesPerPersonPerHour: 600,
		MaxTurns:      40,
		QueueMessages: 10_000, QueueBytes: 256 << 20, QueueMaxAge: 7 * 24 * time.Hour,
		QueueSharePercent: 10,
	}
}

// ForPhone scales the capacity limits to a tenth: the queue sizes, the entries
// per conversation and the request rate. Timeouts, backoff, the size of a read
// and the per-person and turn limits are unchanged.
func (l Limits) ForPhone() Limits {
	l.QueueMessages = atLeastOne(l.QueueMessages / 10)
	l.QueueBytes = max(1, l.QueueBytes/10)
	l.EntriesPerConversation = atLeastOne(l.EntriesPerConversation / 10)
	l.RatePerSecond = l.RatePerSecond / 10
	l.RateBurst = atLeastOne(l.RateBurst / 10)
	return l
}

func atLeastOne(n int) int { return max(1, n) }

// Backoff is how long a sender told to retry waits before attempt n (0 first):
// BackoffStart doubling to BackoffMax. jitter in [0,1) takes up to a quarter
// off, so a crowd of senders does not retry together; the result never
// exceeds BackoffMax.
func (l Limits) Backoff(attempt int, jitter float64) time.Duration {
	d := l.BackoffStart
	for i := 0; i < attempt && d < l.BackoffMax; i++ {
		d *= 2
	}
	if d > l.BackoffMax {
		d = l.BackoffMax
	}
	return d - time.Duration(float64(d)*0.25*jitter)
}

// Rate holds each app to RatePerSecond with bursts to RateBurst.
type Rate struct {
	l   Limits
	now func() time.Time
	mu  sync.Mutex
	b   map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
	// refused is how many requests in a row were turned away; it sets how long
	// the app is told to wait, and clears when one is taken.
	refused int
}

// NewRate makes a limiter; now may be nil.
func NewRate(l Limits, now func() time.Time) *Rate {
	if now == nil {
		now = time.Now
	}
	return &Rate{l: l, now: now, b: map[string]*bucket{}}
}

// Try takes one request for the app. When the app is over its rate it says how
// long to wait before the next try: the backoff for as many refusals in a row,
// but never less than the time the bucket needs to hold one request again.
// jitter is in [0,1).
func (r *Rate) Try(app string, jitter float64) (ok bool, wait time.Duration) {
	if r.Allow(app) {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.b[app]
	wait = r.l.Backoff(b.refused, jitter)
	b.refused++
	if need := time.Duration((1 - b.tokens) / r.l.RatePerSecond * float64(time.Second)); need > wait {
		wait = need
	}
	return false, wait
}

// Allow takes one request for the app, or says it is over its rate. A batched
// call (the agent list, or each agent's machines in one) is one request.
func (r *Rate) Allow(app string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.now()
	b := r.b[app]
	if b == nil {
		b = &bucket{tokens: float64(r.l.RateBurst), at: t}
		r.b[app] = b
	}
	b.tokens = min(float64(r.l.RateBurst), b.tokens+t.Sub(b.at).Seconds()*r.l.RatePerSecond)
	b.at = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	b.refused = 0
	return true
}
