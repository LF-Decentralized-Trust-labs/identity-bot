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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
	"time"

	"identity-agent-core/internal/atomicfile"
	"identity-agent-core/limits"
)

// Plain reasons, in the words a sender is shown.
const (
	ReasonFull         = "the delivery queue is full"
	ReasonConversation = "this conversation holds its share of the delivery queue"
	ReasonSender       = "this sender holds its share of the delivery queue"
	ReasonExpired      = "the recipient was not reachable for 7 days"
	ReasonDuplicate    = "that message is already queued"
	ReasonNotSaved     = "the delivery queue could not be saved, so the message was not accepted"
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

	// path is where the queue is kept across a restart; empty keeps it in
	// memory only.
	path string

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
	l = l.WithDefaults()
	if now == nil {
		now = time.Now
	}
	return &Queue{l: l, now: now, byID: map[string]*held{}, byCv: map[string]*share{}, bySn: map[string]*share{}}
}

// stored is the queue as it is written: every message held, with the state of
// its delivery. The sealed bytes are the only content, and the queue cannot
// open them.
type stored struct {
	Version  int          `json:"version"`
	Messages []storedItem `json:"messages"`
}

type storedItem struct {
	ID           string    `json:"id"`
	Conversation string    `json:"conversation"`
	Sender       string    `json:"sender"`
	Recipient    string    `json:"recipient"`
	Sealed       []byte    `json:"sealed"`
	Queued       time.Time `json:"queued"`
	Delivered    bool      `json:"delivered,omitempty"`
	Kept         bool      `json:"kept,omitempty"`
}

// Open makes a queue held to l that is kept in the file at path (written whole
// and atomically, as the Identity Agent's other secret files are) and reads
// back what it held when it last stopped. A file that is not there is an empty
// queue. One that cannot be read is an error, never an empty queue: dropping
// accepted messages without saying so is what the queue promises not to do.
// Messages that outlived their age while the process was down are still held
// until Expire refuses them back to their senders.
func Open(path string, l limits.Limits, now func() time.Time) (*Queue, error) {
	q := New(l, now)
	q.path = path
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return q, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the delivery queue could not be read: %w", err)
	}
	var st stored
	if err := json.Unmarshal(b, &st); err != nil || st.Version != 1 {
		return nil, fmt.Errorf("the delivery queue file %s is damaged or from a newer version; it was left as it is", path)
	}
	for _, it := range st.Messages {
		if _, dup := q.byID[it.ID]; dup || it.ID == "" {
			return nil, fmt.Errorf("the delivery queue file %s is damaged; it was left as it is", path)
		}
		h := &held{Message: Message{ID: it.ID, Conversation: it.Conversation, Sender: it.Sender,
			Recipient: it.Recipient, Sealed: it.Sealed}, queued: it.Queued, delivered: it.Delivered, kept: it.Kept}
		n := int64(len(h.Sealed))
		q.byID[h.ID] = h
		q.bytes += n
		add(q.byCv, h.Conversation, n)
		add(q.bySn, h.Sender, n)
	}
	return q, nil
}

// save writes the queue, if it is kept anywhere. The caller holds q.mu.
func (q *Queue) save() error { return q.saveAs(nil) }

// saveAs writes the queue as it would be after a change that has not been made
// to memory yet: view is given each message's stored form and may change it or
// return false to leave it out. A change is saved first and made in memory only
// once the save has succeeded, so memory and disk never disagree.
func (q *Queue) saveAs(view func(*storedItem) bool) error {
	if q.path == "" {
		return nil
	}
	st := stored{Version: 1, Messages: make([]storedItem, 0, len(q.byID))}
	for _, h := range q.byID {
		it := storedItem{ID: h.ID, Conversation: h.Conversation, Sender: h.Sender,
			Recipient: h.Recipient, Sealed: h.Sealed, Queued: h.queued, Delivered: h.delivered, Kept: h.kept}
		if view != nil && !view(&it) {
			continue
		}
		st.Messages = append(st.Messages, it)
	}
	sort.Slice(st.Messages, func(i, j int) bool { return st.Messages[i].ID < st.Messages[j].ID })
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicfile.Write(q.path, b, 0o600)
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
	h := &held{Message: m, queued: q.now()}
	q.byID[m.ID] = h
	q.bytes += n
	add(q.byCv, m.Conversation, n)
	add(q.bySn, m.Sender, n)
	// A message is accepted only once it is on disk: one the sender was told was
	// queued must survive a restart.
	if err := q.save(); err != nil {
		q.unhold(h)
		return &Refusal{ReasonNotSaved}
	}
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
func (q *Queue) Delivered(id string) error { return q.mark(id, true, false) }

// Kept says the message's entry is committed. The sealed copy is deleted as
// soon as it is also delivered.
func (q *Queue) Kept(id string) error { return q.mark(id, false, true) }

func (q *Queue) mark(id string, delivered, kept bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := q.byID[id]
	if h == nil {
		return ErrNothingHeld
	}
	d, k := h.delivered || delivered, h.kept || kept
	err := q.saveAs(func(it *storedItem) bool {
		if it.ID == id {
			it.Delivered, it.Kept = d, k
			return !(d && k)
		}
		return true
	})
	if err != nil {
		return err
	}
	h.delivered, h.kept = d, k
	if d && k {
		q.unhold(h)
	}
	return nil
}

// Discard deletes the sealed copy of a message that will not be delivered, as
// when its entry was not kept. If the queue cannot be saved the message is
// still held, in memory as on disk.
func (q *Queue) Discard(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	h := q.byID[id]
	if h == nil {
		return ErrNothingHeld
	}
	if err := q.saveAs(func(it *storedItem) bool { return it.ID != id }); err != nil {
		return err
	}
	q.unhold(h)
	return nil
}

func (q *Queue) unhold(h *held) {
	n := int64(len(h.Sealed))
	delete(q.byID, h.ID)
	q.bytes -= n
	drop(q.byCv, h.Conversation, n)
	drop(q.bySn, h.Sender, n)
	h.Sealed = nil
}

// Due is the messages held for their whole age, which Expire would refuse back
// to their senders, without changing anything.
func (q *Queue) Due() []Expired {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.due()
}

func (q *Queue) due() []Expired {
	var out []Expired
	now := q.now()
	for _, h := range q.byID {
		if now.Sub(h.queued) >= q.l.QueueMaxAge {
			out = append(out, Expired{ID: h.ID, Conversation: h.Conversation, Sender: h.Sender, Recipient: h.Recipient, Reason: ReasonExpired})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Expire deletes every sealed copy held for its whole age and returns what to
// tell each sender: the message is refused back to them. The deletion is saved
// before it is made, so if the save fails nothing is deleted and nothing is
// returned to tell: a sender is told once, for a message that is gone from disk
// as well as from memory, and the next Expire finds the same messages again.
func (q *Queue) Expire() ([]Expired, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.due()
	if len(out) == 0 {
		return nil, nil
	}
	gone := make(map[string]bool, len(out))
	for _, e := range out {
		gone[e.ID] = true
	}
	if err := q.saveAs(func(it *storedItem) bool { return !gone[it.ID] }); err != nil {
		return nil, err
	}
	for id := range gone {
		q.unhold(q.byID[id])
	}
	return out, nil
}
