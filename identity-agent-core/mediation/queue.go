// Package mediation is the delivery queue of an Identity Agent: DIDComm
// mediation, the job of carrying messages between identities. When a
// recipient's host is briefly offline it holds an already committed message,
// sealed to the recipient, until the message is delivered and kept.
//
// It is transport only. What it holds is sealed bytes it cannot read, never the
// words of a conversation an app keeps; once a message is delivered and kept
// the sealed copy is deleted. It is bounded in size and age, with a share per
// conversation and per sender, and it refuses a new message at the bound: an
// accepted message is never dropped to make room.
package mediation

import (
	"errors"
	"sort"
	"sync"
	"time"

	"identity-agent-core/limits"
)

// Plain reasons, in the words a sender is shown.
const (
	ReasonFull         = "the delivery queue is full"
	ReasonConversation = "this conversation holds its share of the delivery queue"
	ReasonSender       = "this sender holds its share of the delivery queue"
	ReasonExpired      = "the recipient was not reachable for 7 days"
	ReasonDuplicate    = "that message is already queued"
)

// Refusal is why Enqueue turned a message away.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// ErrNothingHeld is returned for an id the queue does not hold.
var ErrNothingHeld = errors.New("the queue holds no such message")

// Message is a committed message sealed to its recipient. The queue never
// opens Sealed.
type Message struct {
	ID           string
	Conversation string
	Sender       string
	Recipient    string
	Sealed       []byte
}

type held struct {
	Message
	queued    time.Time
	delivered bool
	kept      bool
}

// Expired is a message refused back to its sender after the queue held it for
// its whole age. Its sealed copy is already deleted.
type Expired struct {
	ID, Conversation, Sender, Recipient string
	Reason                              string
}

// Queue holds sealed messages.
type Queue struct {
	l   limits.Limits
	now func() time.Time

	mu    sync.Mutex
	byID  map[string]*held
	bytes int64
	byCv  map[string]*share
	bySn  map[string]*share
}

type share struct {
	n     int
	bytes int64
}

// New makes an empty queue held to l; now may be nil.
func New(l limits.Limits, now func() time.Time) *Queue {
	if now == nil {
		now = time.Now
	}
	return &Queue{l: l, now: now, byID: map[string]*held{}, byCv: map[string]*share{}, bySn: map[string]*share{}}
}

// Enqueue holds a message, or refuses it with the reason. A refusal changes
// nothing that is already held.
func (q *Queue) Enqueue(m Message) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.byID[m.ID]; ok {
		return &Refusal{ReasonDuplicate}
	}
	n := int64(len(m.Sealed))
	if len(q.byID)+1 > q.l.QueueMessages || q.bytes+n > q.l.QueueBytes {
		return &Refusal{ReasonFull}
	}
	if q.over(q.byCv[m.Conversation], n) {
		return &Refusal{ReasonConversation}
	}
	if q.over(q.bySn[m.Sender], n) {
		return &Refusal{ReasonSender}
	}
	q.byID[m.ID] = &held{Message: m, queued: q.now()}
	q.bytes += n
	add(q.byCv, m.Conversation, n)
	add(q.bySn, m.Sender, n)
	return nil
}

// over says whether taking n more bytes would put a holder past its share.
func (q *Queue) over(s *share, n int64) bool {
	var have int
	var bytes int64
	if s != nil {
		have, bytes = s.n, s.bytes
	}
	maxN := max(1, q.l.QueueMessages*q.l.QueueSharePercent/100)
	maxB := max(1, q.l.QueueBytes*int64(q.l.QueueSharePercent)/100)
	return have+1 > maxN || bytes+n > maxB
}

func add(m map[string]*share, k string, n int64) {
	s := m[k]
	if s == nil {
		s = &share{}
		m[k] = s
	}
	s.n++
	s.bytes += n
}

func drop(m map[string]*share, k string, n int64) {
	if s := m[k]; s != nil {
		s.n--
		s.bytes -= n
		if s.n == 0 {
			delete(m, k)
		}
	}
}

// Held is the messages waiting for a recipient, oldest first.
func (q *Queue) Held(recipient string) []Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	var hs []*held
	for _, h := range q.byID {
		if h.Recipient == recipient && !h.delivered {
			hs = append(hs, h)
		}
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].queued.Before(hs[j].queued) })
	out := make([]Message, len(hs))
	for i, h := range hs {
		out[i] = h.Message
	}
	return out
}

// Len is how many messages are held, and Bytes how many sealed bytes.
func (q *Queue) Len() int     { q.mu.Lock(); defer q.mu.Unlock(); return len(q.byID) }
func (q *Queue) Bytes() int64 { q.mu.Lock(); defer q.mu.Unlock(); return q.bytes }

// Delivered says the recipient has the message. The sealed copy is deleted as
// soon as it is also kept.
func (q *Queue) Delivered(id string) error { return q.mark(id, func(h *held) { h.delivered = true }) }

// Kept says the message's entry is committed. The sealed copy is deleted as
// soon as it is also delivered.
func (q *Queue) Kept(id string) error { return q.mark(id, func(h *held) { h.kept = true }) }

func (q *Queue) mark(id string, f func(*held)) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := q.byID[id]
	if h == nil {
		return ErrNothingHeld
	}
	f(h)
	if h.delivered && h.kept {
		q.remove(h)
	}
	return nil
}

// Discard deletes the sealed copy of a message that will not be delivered, as
// when its entry was not kept.
func (q *Queue) Discard(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := q.byID[id]
	if h == nil {
		return ErrNothingHeld
	}
	q.remove(h)
	return nil
}

func (q *Queue) remove(h *held) {
	n := int64(len(h.Sealed))
	delete(q.byID, h.ID)
	q.bytes -= n
	drop(q.byCv, h.Conversation, n)
	drop(q.bySn, h.Sender, n)
	h.Sealed = nil
}

// Expire deletes every sealed copy held for its whole age and returns what to
// tell each sender: the message is refused back to them.
func (q *Queue) Expire() []Expired {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Expired
	for _, h := range q.byID {
		if q.now().Sub(h.queued) >= q.l.QueueMaxAge {
			out = append(out, Expired{ID: h.ID, Conversation: h.Conversation, Sender: h.Sender, Recipient: h.Recipient, Reason: ReasonExpired})
			q.remove(h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
