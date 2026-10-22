// Package conversation keeps the conversations an Identity Agent's AI agents
// have: every entry in order, chained by hash, and the queue of what each AI
// agent's body has yet to collect.
//
// An entry and the deliveries it causes are written in one transaction, so the
// record and the queue can never disagree: nothing is queued that is not in
// the record, and nothing in the record was silently never queued.
//
// What is kept here is the proof — each entry as the Identity Agent signed it,
// its hash, and the hash before it. The words are kept by a ContentStore, which
// the organisation chooses: on this Identity Agent, or somewhere else. The
// entries carry the words' digest, so wherever the words are, they are checked
// against the record rather than trusted.
package conversation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"

	_ "modernc.org/sqlite"
)

// Limits on one conversation, so two AI agents cannot talk forever on
// somebody's bill. The Identity Agent enforces them; a body cannot.
const (
	// MaxTurns is how many asks, replies and failure notices one conversation
	// may hold. Asks stop at it; an answer to an ask already made never does.
	MaxTurns = 40
	// MaxDepth is how far a chain of asks may go: a person asks A (depth 0),
	// A asks B (1), B asks C (2), C asks D (3), and no further.
	MaxDepth = 3
	// IdleClose is how long a conversation stays open with nothing said.
	IdleClose = 30 * time.Minute
)

// ErrNotFound means there is no such conversation or message.
var ErrNotFound = errors.New("no such conversation or message")

// ErrAlreadyAnswered means the ask already has its answer from this party. An
// ask is answered once — otherwise one body could make another's brain run
// again and again, on somebody's bill.
var ErrAlreadyAnswered = errors.New("that ask has already been answered")

// Conversation is one conversation's header.
type Conversation struct {
	ID string `json:"id"`
	// OpenedBy is the party that opened it — always a person in this version.
	OpenedBy string `json:"opened_by"`
	// FirstAgent is the AI agent the person spoke to.
	FirstAgent string    `json:"first_agent"`
	Turns      int       `json:"turns"`
	Seq        int       `json:"seq"`
	HeadHash   string    `json:"head_hash"`
	CreatedAt  time.Time `json:"created_at"`
	LastAt     time.Time `json:"last_at"`
}

// Open reports whether the conversation still accepts messages.
func (c Conversation) Open(now time.Time) bool { return now.Sub(c.LastAt) < IdleClose }

// Entry is one entry, as kept.
type Entry = agentmessage.Entry

// ContentStore keeps the words of each entry, wherever the organisation
// chooses. The record holds their digest, so a store that changes or loses
// them is caught, never believed.
type ContentStore interface {
	// Kind names the store, for the setting and the record.
	Kind() string
	// Put keeps body and returns where it is.
	Put(ctx context.Context, body []byte) (ref string, err error)
	// Get returns what Put kept.
	Get(ctx context.Context, ref string) ([]byte, error)
}

// Store keeps conversations in one database file.
type Store struct {
	db       *sql.DB
	contents ContentStore

	mu sync.Mutex // one writer, so a conversation's sequence cannot fork

	waitMu  sync.Mutex
	waiters map[string][]chan struct{}
}

// OpenStore opens the conversations kept in dir, keeping words on this
// Identity Agent.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "conversations.db")+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	// One connection: SQLite has one writer anyway, and a single connection
	// keeps a read made inside a transaction from seeing another's half-write.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("the conversation record could not be prepared: %w", err)
	}
	s := &Store{db: db, waiters: map[string][]chan struct{}{}}
	s.contents = &OnThisIdentityAgent{db: db}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Contents is the store the words are kept in.
func (s *Store) Contents() ContentStore { return s.contents }

const schema = `
CREATE TABLE IF NOT EXISTS conversations (
	id TEXT PRIMARY KEY,
	opened_by TEXT NOT NULL,
	first_agent TEXT NOT NULL,
	turns INTEGER NOT NULL DEFAULT 0,
	seq INTEGER NOT NULL DEFAULT 0,
	head_hash TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	last_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
	conversation TEXT NOT NULL,
	seq INTEGER NOT NULL,
	message_id TEXT NOT NULL UNIQUE,
	kind TEXT NOT NULL,
	from_party TEXT NOT NULL,
	to_party TEXT NOT NULL,
	in_reply_to TEXT NOT NULL DEFAULT '',
	depth INTEGER NOT NULL DEFAULT 0,
	body_hash TEXT NOT NULL,
	content_ref TEXT NOT NULL,
	envelope TEXT NOT NULL,
	hash TEXT NOT NULL,
	created_at TEXT NOT NULL,
	PRIMARY KEY (conversation, seq)
);
CREATE TABLE IF NOT EXISTS parties (
	conversation TEXT NOT NULL,
	party TEXT NOT NULL,
	PRIMARY KEY (conversation, party)
);
CREATE TABLE IF NOT EXISTS deliveries (
	message_id TEXT NOT NULL,
	recipient TEXT NOT NULL,
	state TEXT NOT NULL,
	queued_at TEXT NOT NULL,
	delivered_at TEXT NOT NULL DEFAULT '',
	receipt TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (message_id, recipient)
);
CREATE INDEX IF NOT EXISTS deliveries_waiting ON deliveries (recipient, state);
CREATE UNIQUE INDEX IF NOT EXISTS one_answer_per_ask ON entries (in_reply_to, from_party)
	WHERE kind IN ('reply', 'failure');
CREATE TABLE IF NOT EXISTS contents (
	ref TEXT PRIMARY KEY,
	body BLOB NOT NULL
);
`

// NewID is a fresh identifier for a conversation or message, chosen by the
// Identity Agent and never by a body.
func NewID(prefix string) string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Build makes the countersigned entry once its place is known: the sequence
// number and the hash of the entry before it.
type Build func(seq int, prevHash string) (*didcomm.Envelope, agentmessage.Record, error)

// Check decides, inside Append's transaction, whether an entry may be added
// to the conversation as it stands — so limits on turns, and whether it is
// still open, cannot be raced past by two senders at once.
type Check func(c Conversation) error

// Append adds an entry to a conversation, opening it first when opening is
// given, and queues it for deliverTo — all in one transaction. Asks, replies
// and failures count as turns. A receipt neither counts nor keeps the
// conversation open: it says something arrived, not that anything was said.
func (s *Store) Append(ctx context.Context, convID string, opening *Conversation, body []byte, deliverTo []string, check Check, build Build) (Entry, error) {
	ref, err := s.contents.Put(ctx, body)
	if err != nil {
		return Entry{}, fmt.Errorf("the words could not be kept: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	if opening != nil {
		if _, err := tx.Exec(`INSERT INTO conversations (id, opened_by, first_agent, created_at, last_at) VALUES (?, ?, ?, ?, ?)`,
			convID, opening.OpenedBy, opening.FirstAgent, stamp(now), stamp(now)); err != nil {
			return Entry{}, fmt.Errorf("the conversation could not be opened: %w", err)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO parties VALUES (?, ?)`, convID, opening.OpenedBy); err != nil {
			return Entry{}, err
		}
	}
	var c Conversation
	var created, last string
	if err := tx.QueryRow(`SELECT id, opened_by, first_agent, turns, seq, head_hash, created_at, last_at FROM conversations WHERE id = ?`, convID).
		Scan(&c.ID, &c.OpenedBy, &c.FirstAgent, &c.Turns, &c.Seq, &c.HeadHash, &created, &last); err != nil {
		return Entry{}, ErrNotFound
	}
	c.CreatedAt, c.LastAt = unstamp(created), unstamp(last)
	if check != nil {
		if err := check(c); err != nil {
			return Entry{}, err
		}
	}
	seq, head := c.Seq, c.HeadHash
	env, rec, err := build(seq+1, head)
	if err != nil {
		return Entry{}, err
	}
	if rec.Seq != seq+1 || rec.PrevHash != head || rec.Conversation != convID {
		return Entry{}, errors.New("the entry was built for a different place in the conversation")
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Conversation: convID, Seq: rec.Seq, MessageID: rec.MessageID, Kind: rec.Kind,
		From: rec.From, To: rec.To, InReplyTo: rec.InReplyTo, Depth: rec.Depth,
		BodyHash: rec.BodyHash, ContentRef: ref, Envelope: env,
		Hash: agentmessage.Hash(env), CreatedAt: now,
	}
	if _, err := tx.Exec(`INSERT INTO entries (conversation, seq, message_id, kind, from_party, to_party, in_reply_to,
		depth, body_hash, content_ref, envelope, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Conversation, e.Seq, e.MessageID, e.Kind, e.From, e.To, e.InReplyTo, e.Depth,
		e.BodyHash, e.ContentRef, string(envJSON), e.Hash, stamp(now)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "in_reply_to") {
			return Entry{}, ErrAlreadyAnswered
		}
		return Entry{}, fmt.Errorf("the entry could not be recorded: %w", err)
	}
	turn, lastAt := 1, stamp(now)
	if e.Kind == agentmessage.KindReceipt {
		turn, lastAt = 0, last
		if opening != nil {
			lastAt = stamp(now)
		}
	}
	if _, err := tx.Exec(`UPDATE conversations SET seq = ?, head_hash = ?, turns = turns + ?, last_at = ? WHERE id = ?`,
		e.Seq, e.Hash, turn, lastAt, convID); err != nil {
		return Entry{}, err
	}
	for _, p := range []string{e.From, e.To} {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO parties VALUES (?, ?)`, convID, p); err != nil {
			return Entry{}, err
		}
	}
	for _, r := range deliverTo {
		if _, err := tx.Exec(`INSERT INTO deliveries (message_id, recipient, state, queued_at) VALUES (?, ?, 'queued', ?)`,
			e.MessageID, r, stamp(now)); err != nil {
			return Entry{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, err
	}
	for _, r := range deliverTo {
		s.wake(r)
	}
	s.wake(convID)
	return e, nil
}

// Get returns a conversation's header.
func (s *Store) Get(id string) (Conversation, error) {
	var c Conversation
	var created, last string
	err := s.db.QueryRow(`SELECT id, opened_by, first_agent, turns, seq, head_hash, created_at, last_at FROM conversations WHERE id = ?`, id).
		Scan(&c.ID, &c.OpenedBy, &c.FirstAgent, &c.Turns, &c.Seq, &c.HeadHash, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	c.CreatedAt, c.LastAt = unstamp(created), unstamp(last)
	return c, err
}

// List returns the conversations a party is in, newest first.
func (s *Store) List(party string, limit int) ([]Conversation, error) {
	rows, err := s.db.Query(`SELECT c.id FROM conversations c JOIN parties p ON p.conversation = c.id
		WHERE p.party = ? ORDER BY c.last_at DESC LIMIT ?`, party, limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []Conversation{}
	for _, id := range ids {
		c, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ChangedSince returns every conversation with an entry after t.
func (s *Store) ChangedSince(t time.Time) ([]Conversation, error) {
	// Compared as times, not as text: a stamp with no fraction of a second
	// sorts after one with a fraction in the same second.
	rows, err := s.db.Query(`SELECT id, last_at FROM conversations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id, last string
		if err := rows.Scan(&id, &last); err != nil {
			rows.Close()
			return nil, err
		}
		if unstamp(last).After(t) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []Conversation{}
	for _, id := range ids {
		c, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// EntryAt returns a conversation's entry at seq.
func (s *Store) EntryAt(conv string, seq int) (Entry, error) {
	e, err := scanEntry(s.db.QueryRow(`SELECT `+entryColumns+` FROM entries WHERE conversation = ? AND seq = ?`, conv, seq))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// IsParty reports whether party has been brought into a conversation: it
// opened it, sent in it, or was sent to in it.
func (s *Store) IsParty(conv, party string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM parties WHERE conversation = ? AND party = ?`, conv, party).Scan(&n)
	return n > 0
}

const entryColumns = `conversation, seq, message_id, kind, from_party, to_party, in_reply_to, depth, body_hash, content_ref, envelope, hash, created_at`

func scanEntry(row interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	var env, created string
	if err := row.Scan(&e.Conversation, &e.Seq, &e.MessageID, &e.Kind, &e.From, &e.To, &e.InReplyTo, &e.Depth,
		&e.BodyHash, &e.ContentRef, &env, &e.Hash, &created); err != nil {
		return e, err
	}
	e.CreatedAt = unstamp(created)
	e.Envelope = &didcomm.Envelope{}
	if err := json.Unmarshal([]byte(env), e.Envelope); err != nil {
		return e, fmt.Errorf("entry %s is unreadable: %w", e.MessageID, err)
	}
	return e, nil
}

// Entries returns a conversation's entries after seq, in order.
func (s *Store) Entries(conv string, after int) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT `+entryColumns+` FROM entries WHERE conversation = ? AND seq > ? ORDER BY seq`, conv, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Message returns one entry by its message id.
func (s *Store) Message(id string) (Entry, error) {
	e, err := scanEntry(s.db.QueryRow(`SELECT `+entryColumns+` FROM entries WHERE message_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// Waiting returns what recipient has yet to acknowledge, oldest first.
// Delivery is at least once: an entry stays waiting until its receipt
// arrives, and a body sees it again if it asks again before then.
func (s *Store) Waiting(recipient string, limit int) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT e.conversation, e.seq, e.message_id, e.kind, e.from_party, e.to_party, e.in_reply_to,
		e.depth, e.body_hash, e.content_ref, e.envelope, e.hash, e.created_at
		FROM deliveries d JOIN entries e ON e.message_id = d.message_id
		WHERE d.recipient = ? AND d.state = 'queued' ORDER BY d.queued_at, e.seq LIMIT ?`, recipient, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Delivered marks a message received by recipient, citing the receipt entry.
// It reports whether the message was waiting for that recipient at all.
func (s *Store) Delivered(messageID, recipient, receipt string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE deliveries SET state = 'delivered', delivered_at = ?, receipt = ?
		WHERE message_id = ? AND recipient = ? AND state = 'queued'`, stamp(time.Now().UTC()), receipt, messageID, recipient)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// IsWaiting reports whether a message is queued for recipient and not yet
// acknowledged.
func (s *Store) IsWaiting(messageID, recipient string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM deliveries WHERE message_id = ? AND recipient = ? AND state = 'queued'`,
		messageID, recipient).Scan(&n)
	return n > 0
}

// Answered reports whether party has already answered an ask.
func (s *Store) Answered(askID, party string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM entries WHERE in_reply_to = ? AND from_party = ? AND kind IN ('reply', 'failure')`,
		askID, party).Scan(&n)
	return n > 0
}

// WasQueuedFor reports whether a message was ever queued for recipient.
func (s *Store) WasQueuedFor(messageID, recipient string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM deliveries WHERE message_id = ? AND recipient = ?`, messageID, recipient).Scan(&n)
	return n > 0
}

// Subscribe registers interest in key — a recipient, or a conversation —
// and returns a channel that receives when something is added for it, and a
// function to withdraw. Subscribe before reading, then wait: something added
// between the read and the wait still wakes the waiter.
func (s *Store) Subscribe(key string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.waitMu.Lock()
	s.waiters[key] = append(s.waiters[key], ch)
	s.waitMu.Unlock()
	return ch, func() {
		s.waitMu.Lock()
		defer s.waitMu.Unlock()
		list := s.waiters[key]
		for i, c := range list {
			if c == ch {
				s.waiters[key] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(s.waiters[key]) == 0 {
			delete(s.waiters, key)
		}
	}
}

func (s *Store) wake(key string) {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	for _, ch := range s.waiters[key] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// OnThisIdentityAgent keeps the words in the conversation record's own
// database: the default, and the only store built so far. Another location
// keeps the same interface and receives only words encrypted here first.
type OnThisIdentityAgent struct{ db *sql.DB }

// KindOnThisIdentityAgent names the default store.
const KindOnThisIdentityAgent = "on_this_identity_agent"

// Kind names the store.
func (o *OnThisIdentityAgent) Kind() string { return KindOnThisIdentityAgent }

// Put keeps body under its own digest. Nothing outside this Identity Agent sees
// the address, so addressing by the words' digest reveals nothing here.
func (o *OnThisIdentityAgent) Put(ctx context.Context, body []byte) (string, error) {
	ref := "local:" + agentmessage.HashBody(body)
	_, err := o.db.ExecContext(ctx, `INSERT OR IGNORE INTO contents (ref, body) VALUES (?, ?)`, ref, body)
	return ref, err
}

// Get returns the words kept under ref.
func (o *OnThisIdentityAgent) Get(ctx context.Context, ref string) ([]byte, error) {
	var b []byte
	err := o.db.QueryRowContext(ctx, `SELECT body FROM contents WHERE ref = ?`, ref).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func unstamp(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
