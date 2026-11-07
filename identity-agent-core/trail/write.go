package trail

import (
	"context"
	"errors"
	"time"

	"identity-agent-core/agentmessage"
)

// Backend is the app that keeps the words. The trail forwards an allowed write
// to it and commits only what it confirms.
type Backend interface {
	// Reachable returns ErrUnreachable when the app cannot be reached at all,
	// so the write is refused before anything is kept.
	Reachable(ctx context.Context) error
	// Keep stores the words and salt under the entry's id and returns the
	// fingerprint of what it stored.
	Keep(ctx context.Context, f Forward) (Receipt, error)
	// Discard drops the words of an entry the trail did not keep.
	Discard(ctx context.Context, conversation, entryID string) error
}

// ErrUnreachable is what Backend.Reachable returns when the app is down.
var ErrUnreachable = errors.New("unreachable")

// Forward is the one place words leave the trail's hands: to the app, which
// keeps them. The trail itself keeps none of it.
type Forward struct {
	Conversation string
	EntryID      string
	MessageID    string
	Author       string
	Kind         string
	Salt         []byte
	Words        []byte
}

// Receipt is the app's confirmation.
type Receipt struct {
	Fingerprint string
}

// Plain reasons, in the words a sender is shown.
const (
	ReasonUnreachable   = "AI Chat is not reachable right now"
	ReasonIDUsed        = "id already used"
	ReasonWordsMismatch = "the words do not match the fingerprint that was signed"
	ReasonNoConv        = "there is no such conversation"
	ReasonClosed        = "the conversation is closed"
	ReasonNotOwner      = "only the conversation's owner may do that"
	ReasonNotKept       = "the app did not keep it"
	ReasonNoConfirm     = "the app's confirmation did not match what was sent"
	ReasonTimeout       = "the app did not answer in time"
	ReasonNonceUsed     = "that nonce was already used"
)

// Write is what a sender asks to be kept.
type Write struct {
	Statement agentmessage.PersonStatement
	Verkey    string
	Signature string
	// Salt and Words are carried to the app and kept by neither the trail nor
	// the governance record. For a private agent's entry, Words is the
	// ciphertext and Private is set.
	Salt    []byte
	Words   []byte
	Private bool
}

// Result is what happened to a write.
type Result struct {
	EntryID string
	State   State
	// Reason is why a write was refused or not kept.
	Reason string
	// Replayed is true when the same id and statement returned an earlier result.
	Replayed bool
}

// Rejected is an attempt that proves no author: a malformed statement, a bad
// signature or a key that does not speak for the person. Nobody can be
// recorded as having tried, so nothing joins the trail; the caller's
// governance record says it happened.
type Rejected struct{ Reason string }

func (r *Rejected) Error() string { return "rejected: " + r.Reason }

// Write checks a write against the trail and, if it is allowed, keeps it:
// pending, forwarded, and committed once the app confirms the fingerprint.
func (t *Trail) Write(ctx context.Context, w Write) (Result, error) {
	s := w.Statement
	if err := agentmessage.VerifyPerson(s, w.Verkey, w.Signature); err != nil {
		return Result{}, &Rejected{err.Error()}
	}
	if s.Agent != t.agent {
		return Result{}, &Rejected{"the statement is for another Identity Agent"}
	}
	if !t.roster.KeySpeaksFor(s.From, s.Signer, w.Verkey) {
		return Result{}, &Rejected{"the key does not speak for " + s.From}
	}
	c := t.get(s.Conversation)
	if c == nil {
		return Result{}, &Rejected{ReasonNoConv}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// An id seen before: the same statement returns the earlier result, any
	// difference is refused. This comes before the rules so a retry after a
	// lost reply gets its answer even if the conversation has moved on.
	key := s.From + "\n" + s.MessageID
	if i, ok := c.byMessage[key]; ok {
		prior := c.entries[i]
		if sameStatement(prior, w) {
			return resultOf(prior, true), nil
		}
		digest := agentmessage.HashBody(append(s.Bytes(), w.Signature...))
		if j, seen := c.refusedReuse[digest]; seen {
			return resultOf(c.entries[j], true), nil
		}
		e := t.append(c, w, ReasonIDUsed)
		c.refusedReuse[digest] = e.Seq - 1
		return resultOf(e, false), nil
	}

	if c.nonces[s.From+"\n"+s.Nonce] {
		return resultOf(t.appendRefusal(c, w, ReasonNonceUsed), false), nil
	}
	if reason := t.decide(c, w); reason != "" {
		return resultOf(t.appendRefusal(c, w, reason), false), nil
	}
	if t.backend == nil {
		return resultOf(t.appendRefusal(c, w, ReasonUnreachable), false), nil
	}
	if err := t.backend.Reachable(ctx); err != nil {
		return resultOf(t.appendRefusal(c, w, ReasonUnreachable), false), nil
	}

	// Allowed. The entry joins the trail pending, then the app keeps the words.
	e := t.append(c, w, "")
	c.indexAllowed(e)
	i := e.Seq - 1
	fctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	rc, err := t.backend.Keep(fctx, Forward{
		Conversation: s.Conversation, EntryID: e.ID, MessageID: s.MessageID,
		Author: s.From, Kind: s.Kind, Salt: w.Salt, Words: w.Words,
	})
	switch {
	case err != nil && fctx.Err() != nil:
		t.notKept(ctx, c, i, ReasonTimeout)
	case err != nil:
		t.notKept(ctx, c, i, ReasonNotKept)
	case rc.Fingerprint != s.Fingerprint:
		t.notKept(ctx, c, i, ReasonNoConfirm)
	default:
		t.commit(c, i)
	}
	return resultOf(c.entries[i], false), nil
}

// ExpirePending marks every entry still pending after the forwarding timeout
// as not kept, as when the process stopped before the app answered. It
// returns how many it marked.
func (t *Trail) ExpirePending(ctx context.Context, conversation string) int {
	c := t.get(conversation)
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for i := range c.entries {
		e := c.entries[i]
		if e.State() != Pending {
			continue
		}
		rec, err := time.Parse(time.RFC3339, e.Recorded)
		if err == nil && t.now().Sub(rec) < t.timeout {
			continue
		}
		t.notKept(ctx, c, i, ReasonTimeout)
		n++
	}
	return n
}

func sameStatement(prior Entry, w Write) bool {
	return string(prior.Statement.Bytes()) == string(w.Statement.Bytes()) && prior.Signature == w.Signature
}

func resultOf(e Entry, replayed bool) Result {
	r := Result{EntryID: e.ID, State: e.State(), Replayed: replayed}
	switch {
	case e.Refusal != "":
		r.Reason = e.Refusal
	case e.Outcome != nil:
		r.Reason = e.Outcome.Reason
	}
	return r
}

// append adds an entry. A non-empty refusal makes it a wordless refusal.
func (t *Trail) append(c *conversation, w Write, refusal string) Entry {
	e := Entry{
		Seq: len(c.entries) + 1, Recorded: t.now().UTC().Format(time.RFC3339),
		Refusal: refusal, Statement: w.Statement, Verkey: w.Verkey, Signature: w.Signature,
	}
	e.ID = EntryID(e.Seq)
	if w.Private {
		e.CiphertextHash = w.Statement.Fingerprint
	}
	if n := len(c.entries); n > 0 {
		e.Prev = c.entries[n-1].ChainHash()
	}
	c.entries = append(c.entries, e)
	return e
}

// appendRefusal records a refusal and takes the sender's message id and nonce,
// so a retry of the same statement returns the same refusal.
func (t *Trail) appendRefusal(c *conversation, w Write, reason string) Entry {
	e := t.append(c, w, reason)
	c.byMessage[w.Statement.From+"\n"+w.Statement.MessageID] = e.Seq - 1
	c.nonces[w.Statement.From+"\n"+w.Statement.Nonce] = true
	return e
}

func (t *Trail) notKept(ctx context.Context, c *conversation, i int, reason string) {
	c.entries[i].Outcome = &Outcome{State: NotKept, Reason: reason, Time: t.now().UTC().Format(time.RFC3339)}
	if t.backend != nil {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), t.timeout)
		defer cancel()
		_ = t.backend.Discard(dctx, c.id, c.entries[i].ID)
	}
}

// commit marks the entry committed and applies what it did to the conversation.
func (t *Trail) commit(c *conversation, i int) {
	e := c.entries[i]
	c.entries[i].Outcome = &Outcome{State: Committed, Time: t.now().UTC().Format(time.RFC3339)}
	switch e.Statement.Kind {
	case agentmessage.PersonKindHandOff:
		c.handOffs = append(c.handOffs, HandOff{From: c.owner, To: e.Statement.To, By: e.Statement.From, Entry: e.ID})
		c.owner = e.Statement.To
	case agentmessage.PersonKindClose:
		c.closed = true
	case agentmessage.PersonKindReopen:
		c.closed = false
	}
}

// indexAllowed records the id and nonce of an allowed write.
func (c *conversation) indexAllowed(e Entry) {
	c.byMessage[e.Statement.From+"\n"+e.Statement.MessageID] = e.Seq - 1
	c.nonces[e.Statement.From+"\n"+e.Statement.Nonce] = true
}

// decide applies every rule from the trail and the roster alone: nothing the
// app sends is used. It returns the refusal reason, or "" if allowed.
func (t *Trail) decide(c *conversation, w Write) string {
	s := w.Statement
	r := t.roster
	if err := agentmessage.CheckFingerprint(s.FingerprintVersion, w.Salt, w.Words, s.Fingerprint, false); err != nil {
		return ReasonWordsMismatch
	}
	if s.InReplyTo != "" {
		if e, ok := c.byID(s.InReplyTo); !ok || e.State() != Committed {
			return "the message it answers is not in this conversation"
		}
	}
	isOwner := s.From == c.owner
	switch s.Kind {
	case agentmessage.PersonKindClose, agentmessage.PersonKindReopen:
		if !isOwner {
			return ReasonNotOwner
		}
		if s.Kind == agentmessage.PersonKindClose && c.closed {
			return ReasonClosed
		}
		if s.Kind == agentmessage.PersonKindReopen && !c.closed {
			return "the conversation is not closed"
		}
		return ""
	}
	if c.closed {
		return ReasonClosed
	}
	switch s.Kind {
	case agentmessage.PersonKindMessage, agentmessage.PersonKindAsk:
		if !isOwner {
			return ReasonNotOwner
		}
		if !r.IsAIAgent(s.To) {
			return "a message is addressed to an AI agent"
		}
		if !r.MayUseAgent(s.From, s.To) || !r.AgentGrantAllows(s.To, s.From) {
			return "you may not use that AI agent"
		}
	case agentmessage.PersonKindHandOff:
		if !isOwner && !r.IsSigner(s.From) {
			return ReasonNotOwner
		}
		if s.To == c.owner {
			return "it is already theirs"
		}
		return t.newOwnerOK(s.From, s.To)
	case agentmessage.PersonKindSplit:
		if !isOwner {
			return ReasonNotOwner
		}
		if reason := t.newOwnerOK(s.From, s.To); reason != "" {
			return reason
		}
		first, ok1 := c.byID(s.RangeFirst)
		last, ok2 := c.byID(s.RangeLast)
		if !ok1 || !ok2 || first.State() != Committed || last.State() != Committed || first.Seq > last.Seq {
			return "a split carries a range of this conversation's kept entries"
		}
	}
	return ""
}

// newOwnerOK is the check a hand-off and a split's owner both pass: an AI
// agent the writer may use, or an active employee. The writer is a person, so
// an agent-to-agent hand-off cannot arise here.
func (t *Trail) newOwnerOK(by, to string) string {
	switch {
	case t.roster.IsAIAgent(to):
		if !t.roster.MayUseAgent(by, to) || !t.roster.AgentGrantAllows(to, by) {
			return "you may not use that AI agent"
		}
	case t.roster.ActiveEmployee(to):
	default:
		return "the new owner is neither an AI agent you may use nor an active employee"
	}
	return ""
}

func (c *conversation) byID(id string) (Entry, bool) {
	for _, e := range c.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
