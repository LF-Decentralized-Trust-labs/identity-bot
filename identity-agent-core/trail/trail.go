// Package trail is what the Identity Agent keeps about a conversation an app
// holds the words of: who said what, in what order, signed, and whether the
// app kept it. It keeps no words, no salts and no previews (ADR-068).
package trail

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentmessage"
)

// State is where an entry stands.
type State string

const (
	// Pending: allowed, forwarded to the app, not yet confirmed.
	Pending State = "pending"
	// Committed: the app confirmed it kept the words that match the fingerprint.
	// Only a committed entry is delivered or read.
	Committed State = "committed"
	// NotKept: the app refused, answered with another fingerprint, or did not
	// answer in time. The sender is told; a retry is a new entry.
	NotKept State = "not-kept"
	// Refused: the Identity Agent refused the write before forwarding anything.
	// The entry records who tried, when and why, and never any words.
	Refused State = "refused"
)

// Outcome is how a pending entry ended. It is not part of the chain: the
// chain commits to what was signed and allowed, and the outcome follows.
type Outcome struct {
	State  State  `json:"state"` // Committed or NotKept
	Reason string `json:"reason,omitempty"`
	Time   string `json:"time"`
}

// Entry is one line of a conversation's trail.
type Entry struct {
	// Seq counts from 1 in the order entries joined the trail, refusals
	// included. ID is "e" and the decimal Seq; the app keeps the words under it.
	Seq int    `json:"seq"`
	ID  string `json:"id"`
	// Prev is the chain hash of the entry before it, empty for the first.
	Prev     string `json:"prev"`
	Recorded string `json:"recorded"`
	// Refusal is why the write was refused. Set at birth, so inside the chain.
	Refusal string `json:"refusal,omitempty"`
	// CiphertextHash is, for a private agent's entry, the fingerprint over its
	// ciphertext (the same value as the statement's fingerprint).
	CiphertextHash string `json:"ciphertext_hash,omitempty"`
	// Statement is what the author signed, with the key that signed it. It
	// holds the fingerprint of the words, never the words.
	Statement agentmessage.PersonStatement `json:"statement"`
	Verkey    string                       `json:"verkey"`
	Signature string                       `json:"signature"`
	Outcome   *Outcome                     `json:"outcome,omitempty"`
}

// Author is who the entry is from.
func (e Entry) Author() string { return e.Statement.From }

// State is where the entry stands.
func (e Entry) State() State {
	switch {
	case e.Refusal != "":
		return Refused
	case e.Outcome == nil:
		return Pending
	default:
		return e.Outcome.State
	}
}

// ChainHash is the hash the next entry carries as its Prev. It covers
// everything but the outcome, so an outcome can follow without breaking the
// chain, and a refusal's reason cannot be changed after the fact.
func (e Entry) ChainHash() string {
	pre := strings.Join([]string{
		"IA-TRAIL-ENTRY-V1",
		strconv.Itoa(e.Seq), e.ID, e.Prev, e.Recorded, e.Refusal, e.CiphertextHash,
		e.Verkey, e.Signature, agentmessage.HashBody(e.Statement.Bytes()),
	}, "\n")
	return agentmessage.HashBody([]byte(pre))
}

// EntryID is the id of the nth entry of a conversation.
func EntryID(seq int) string { return "e" + strconv.Itoa(seq) }

// Roster is what the Identity Agent knows from its own records, never from the
// app: who a key speaks for, and who may use whom.
type Roster interface {
	// KeySpeaksFor says whether the key (signer identifier and verkey) was
	// approved to act as the person.
	KeySpeaksFor(person, signer, verkey string) bool
	IsAIAgent(id string) bool
	// MayUseAgent says whether the person's reach includes the AI agent.
	MayUseAgent(person, agent string) bool
	// AgentGrantAllows says whether the AI agent's own grant lets the person
	// address it. Reach and grant must both allow (an @agent, M83 addition 3).
	AgentGrantAllows(agent, person string) bool
	ActiveEmployee(person string) bool
	IsSigner(person string) bool
}

// HandOff is a change of owner, recorded with who made it.
type HandOff struct {
	From  string `json:"from"`
	To    string `json:"to"`
	By    string `json:"by"`
	Entry string `json:"entry"`
}

type conversation struct {
	mu       sync.Mutex
	id       string
	opener   string
	owner    string
	closed   bool
	standing bool
	handOffs []HandOff
	entries  []Entry
	// byMessage finds the first entry for a sender's message id.
	byMessage map[string]int
	// refusedReuse finds an id-reuse refusal by the digest of its statement.
	refusedReuse map[string]int
	nonces       map[string]bool
}

// Trail holds the conversations.
type Trail struct {
	mu      sync.Mutex
	convs   map[string]*conversation
	agent   string
	roster  Roster
	backend Backend
	timeout time.Duration
	now     func() time.Time
	record  func(Governance)
}

// DefaultTimeout is how long a forwarded call to the app may take (a probe).
const DefaultTimeout = 10 * time.Second

// Options adjust a Trail; the zero value is the defaults.
type Options struct {
	// Agent is the Identity Agent that holds these conversations. A statement
	// names it, so one made for another Identity Agent's conversation of the
	// same id is refused (ADR-067).
	Agent          string
	ForwardTimeout time.Duration
	Now            func() time.Time
	// Record receives what every read leaves in the governance record.
	Record func(Governance)
}

// New makes an empty Trail.
func New(roster Roster, backend Backend, o Options) *Trail {
	t := &Trail{convs: map[string]*conversation{}, agent: o.Agent, roster: roster, backend: backend,
		timeout: o.ForwardTimeout, now: o.Now, record: o.Record}
	if t.timeout == 0 {
		t.timeout = DefaultTimeout
	}
	if t.now == nil {
		t.now = time.Now
	}
	return t
}

// Open starts a conversation. Whoever opens it owns it.
func (t *Trail) Open(id, opener string, standing bool) error {
	if id == "" || opener == "" || strings.ContainsAny(id+opener, "\r\n") {
		return errors.New("a conversation needs an id and an opener")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.convs[id]; ok {
		return fmt.Errorf("conversation %s already exists", id)
	}
	t.convs[id] = &conversation{id: id, opener: opener, owner: opener, standing: standing,
		byMessage: map[string]int{}, refusedReuse: map[string]int{}, nonces: map[string]bool{}}
	return nil
}

func (t *Trail) get(id string) *conversation {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.convs[id]
}

// Owner is who owns the conversation now.
func (t *Trail) Owner(id string) (string, bool) {
	c := t.get(id)
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.owner, true
}

// Closed says whether the conversation is closed.
func (t *Trail) Closed(id string) bool {
	c := t.get(id)
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// HandOffs lists every hand-off, with who made it.
func (t *Trail) HandOffs(id string) []HandOff {
	c := t.get(id)
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]HandOff(nil), c.handOffs...)
}

// Entries is a copy of the whole trail, in order.
func (t *Trail) Entries(id string) []Entry {
	c := t.get(id)
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return copyEntries(c.entries)
}

// Committed is the entries that may be delivered or read, in order. A pending,
// not-kept or refused entry is never in it.
func (t *Trail) Committed(id string) []Entry {
	var out []Entry
	for _, e := range t.Entries(id) {
		if e.State() == Committed {
			out = append(out, e)
		}
	}
	return out
}

// Head is the chain hash of the latest entry, which the Identity Agent records
// in its key history. Empty for an empty trail.
func (t *Trail) Head(id string) string {
	es := t.Entries(id)
	if len(es) == 0 {
		return ""
	}
	return es[len(es)-1].ChainHash()
}

func copyEntries(in []Entry) []Entry {
	out := make([]Entry, len(in))
	for i, e := range in {
		if e.Outcome != nil {
			o := *e.Outcome
			e.Outcome = &o
		}
		out[i] = e
	}
	return out
}
