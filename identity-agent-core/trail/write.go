package trail

import (
	"context"
	"errors"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
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
	ReasonUnreachable   = "the app is not reachable right now"
	ReasonIDUsed        = "id already used"
	ReasonWordsMismatch = "the words do not match the fingerprint that was signed"
	ReasonNoConv        = "there is no such conversation"
	ReasonClosed        = "the conversation is closed"
	ReasonNotOwner      = "only the conversation's owner may do that"
	ReasonNotKept       = "the app did not keep it"
	ReasonNoConfirm     = "the app's confirmation did not match what was sent"
	ReasonTimeout       = "the app did not answer in time"
	ReasonNonceUsed     = "that nonce was already used"
	ReasonStale         = "the statement was not signed within 5 minutes of now"
	ReasonTurnLimit     = "the limit on turns after one message has been reached"
	ReasonEntryLimit    = "the conversation holds the most entries it may"
	ReasonRateLimit     = "the limit on messages an hour for this person has been reached"
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

// CheckAuthor is the one check that a person's statement is the person's: it is
// well formed, its signature holds under the key it names, it is for this
// Identity Agent, and the Identity Agent's own records say that key speaks for
// the person. Write runs it first, and anything that admits a person's words
// before they reach Write (an app speaking for a person, whose request is
// refused at the door) runs this same function, so there is not a second
// reader of what makes a statement a person's. The failure is a *Rejected.
func CheckAuthor(w Write, agent string, keys KeyRoster) error {
	s := w.Statement
	if err := agentmessage.VerifyPerson(s, w.Verkey, w.Signature); err != nil {
		return &Rejected{err.Error()}
	}
	if s.Agent != agent {
		return &Rejected{"the statement is for another Identity Agent"}
	}
	if keys == nil || !keys.KeySpeaksFor(s.From, s.Signer, w.Verkey) {
		return &Rejected{"the key does not speak for " + s.From}
	}
	return nil
}

// CheckFresh holds a statement to the rule the verifier holds every person's
// entry to: signed within authorisation.Skew of now.
func CheckFresh(s agentmessage.PersonStatement, now time.Time) error {
	signed, err := time.Parse(time.RFC3339, s.Time)
	if err != nil {
		return &Rejected{ReasonStale}
	}
	if d := now.Sub(signed); d > authorisation.Skew || -d > authorisation.Skew {
		return &Rejected{ReasonStale}
	}
	return nil
}

// Write checks a write against the trail and, if it is allowed, keeps it:
// pending, forwarded, and committed once the app confirms the fingerprint.
func (t *Trail) Write(ctx context.Context, w Write) (Result, error) {
	s := w.Statement
	if err := CheckAuthor(w, t.agent, t.roster); err != nil {
		return Result{}, err
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
		if err := t.checkTime(s); err != nil {
			return Result{}, err
		}
		e, err := t.add(c, w, ReasonIDUsed)
		if err != nil {
			return Result{}, err
		}
		c.refusedReuse[digest] = len(c.entries) - 1
		// A refusal uses up its author's nonce as well as its id, which is how
		// conversationbundle.Verify reads every refusal.
		c.nonces[s.From+"\n"+s.Nonce] = true
		return resultOf(e, false), nil
	}

	if err := t.checkTime(s); err != nil {
		return Result{}, err
	}
	refuse := func(reason string) (Result, error) {
		e, err := t.addRefusal(c, w, reason)
		if err != nil {
			return Result{}, err
		}
		return resultOf(e, false), nil
	}
	if c.nonces[s.From+"\n"+s.Nonce] {
		return refuse(ReasonNonceUsed)
	}
	if reason := t.decide(c, w); reason != "" {
		return refuse(reason)
	}
	if reason := t.overLimit(c, s); reason != "" {
		return refuse(reason)
	}
	if t.backend == nil {
		return refuse(ReasonUnreachable)
	}
	if err := t.backend.Reachable(ctx); err != nil {
		return refuse(ReasonUnreachable)
	}

	// Allowed. The entry joins the chain pending, then the app keeps the words.
	e, err := t.add(c, w, "")
	if err != nil {
		return Result{}, err
	}
	c.indexAllowed(e)
	t.countAllowed(c, s)
	i := len(c.entries) - 1
	fctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	rc, err := t.backend.Keep(fctx, Forward{
		Conversation: s.Conversation, EntryID: e.ID, MessageID: s.MessageID,
		Author: s.From, Kind: s.Kind, Salt: w.Salt, Words: w.Words,
	})
	switch {
	case err != nil && fctx.Err() != nil:
		err = t.notKept(ctx, c, i, ReasonTimeout)
	case err != nil:
		err = t.notKept(ctx, c, i, ReasonNotKept)
	case rc.Fingerprint != s.Fingerprint:
		err = t.notKept(ctx, c, i, ReasonNoConfirm)
	default:
		err = t.commit(c, i)
	}
	if err != nil {
		return Result{}, err
	}
	return resultOf(c.entries[i], false), nil
}

// checkTime holds a statement to the rule the verifier holds every person's
// entry to: signed within authorisation.Skew of when the Identity Agent takes
// it. One that is not proves no timely author, so nothing joins the chain.
func (t *Trail) checkTime(s agentmessage.PersonStatement) error { return CheckFresh(s, t.now()) }

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
		if t.notKept(ctx, c, i, ReasonTimeout) == nil {
			n++
		}
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

// add writes a person's entry into the chain: a record carrying their
// statement and signature, countersigned, after the entry before it. A
// non-empty refusal makes it a wordless refusal.
func (t *Trail) add(c *conversation, w Write, refusal string) (Entry, error) {
	st := w.Statement
	seq := len(c.chain) + 1
	rec := agentmessage.Record{
		MessageID: EntryID(seq), Kind: st.Kind, From: agentmessage.Person(st.From), To: st.To,
		InReplyTo: st.InReplyTo, BodyHash: st.Fingerprint, Depth: 0,
		PersonProof: &agentmessage.PersonProof{Statement: st, Verkey: w.Verkey, Signature: w.Signature},
		Refusal:     refusal,
	}
	if w.Private {
		rec.CiphertextHash = st.Fingerprint
	}
	ce, err := t.countersign(c, rec)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Seq: seq, ID: EntryID(seq), Recorded: ce.CreatedAt.Format(time.RFC3339Nano), Refusal: refusal,
		CiphertextHash: rec.CiphertextHash, Statement: st, Verkey: w.Verkey, Signature: w.Signature,
	}
	c.entries = append(c.entries, e)
	return e, nil
}

// countersign stamps a record as the next entry of the chain, countersigns it
// as the Identity Agent and appends it.
func (t *Trail) countersign(c *conversation, rec agentmessage.Record) (agentmessage.Entry, error) {
	at := t.now().UTC()
	rec.Conversation, rec.Seq, rec.PrevHash = c.id, len(c.chain)+1, c.head()
	rec.IATime = at.Format(time.RFC3339Nano)
	rec.OpenedBy = agentmessage.Person(c.opener)
	env, err := t.sign(rec)
	if err != nil {
		return agentmessage.Entry{}, err
	}
	ce := agentmessage.Entry{
		Conversation: c.id, Seq: rec.Seq, MessageID: rec.MessageID, Kind: rec.Kind, From: rec.From, To: rec.To,
		InReplyTo: rec.InReplyTo, Depth: rec.Depth, BodyHash: rec.BodyHash, ContentRef: rec.MessageID,
		Envelope: env, Hash: agentmessage.Hash(env), CreatedAt: at,
	}
	c.chain = append(c.chain, ce)
	return ce, nil
}

// addRefusal records a refusal and takes the sender's message id and nonce,
// so a retry of the same statement returns the same refusal.
func (t *Trail) addRefusal(c *conversation, w Write, reason string) (Entry, error) {
	e, err := t.add(c, w, reason)
	if err != nil {
		return Entry{}, err
	}
	c.byMessage[w.Statement.From+"\n"+w.Statement.MessageID] = len(c.entries) - 1
	c.nonces[w.Statement.From+"\n"+w.Statement.Nonce] = true
	return e, nil
}

// outcome writes how an entry ended into the chain, after it, and then updates
// the view.
func (t *Trail) outcome(c *conversation, i int, state, reason string) error {
	e := c.entries[i]
	rec := agentmessage.Record{
		MessageID: EntryID(len(c.chain) + 1), Kind: agentmessage.KindOutcome, From: t.agent, InReplyTo: e.ID,
		BodyHash: agentmessage.HashBody(nil),
		Outcome:  &agentmessage.Outcome{Entry: e.ID, State: state, Reason: reason},
	}
	ce, err := t.countersign(c, rec)
	if err != nil {
		return err
	}
	c.entries[i].Outcome = &Outcome{State: State(state), Reason: reason, Time: ce.CreatedAt.Format(time.RFC3339Nano)}
	return nil
}

func (t *Trail) notKept(ctx context.Context, c *conversation, i int, reason string) error {
	err := t.outcome(c, i, agentmessage.OutcomeNotKept, reason)
	if t.backend != nil {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), t.timeout)
		defer cancel()
		_ = t.backend.Discard(dctx, c.id, c.entries[i].ID)
	}
	return err
}

// MarkNotDelivered records, after a committed entry, that its message was not
// delivered: the delivery queue held the sealed copy for its whole age and
// refused it back to its sender. The entry stays committed and readable. Only
// a committed entry can be marked, and only once.
func (t *Trail) MarkNotDelivered(conversation, entryID, reason string) error {
	c := t.get(conversation)
	if c == nil {
		return errors.New(ReasonNoConv)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.entries {
		e := c.entries[i]
		if e.ID != entryID {
			continue
		}
		if e.State() != Committed || e.NotDelivered != nil {
			return errors.New("only a kept entry that has not been marked can be marked not delivered")
		}
		return t.noteNotDelivered(c, i, reason)
	}
	return errors.New("there is no such entry")
}

func (t *Trail) noteNotDelivered(c *conversation, i int, reason string) error {
	e := c.entries[i]
	rec := agentmessage.Record{
		MessageID: EntryID(len(c.chain) + 1), Kind: agentmessage.KindOutcome, From: t.agent, InReplyTo: e.ID,
		BodyHash: agentmessage.HashBody(nil),
		Outcome:  &agentmessage.Outcome{Entry: e.ID, State: agentmessage.OutcomeNotDelivered, Reason: reason},
	}
	ce, err := t.countersign(c, rec)
	if err != nil {
		return err
	}
	c.entries[i].NotDelivered = &Outcome{State: State(agentmessage.OutcomeNotDelivered), Reason: reason, Time: ce.CreatedAt.Format(time.RFC3339Nano)}
	return nil
}

// commit marks the entry committed and applies what it did to the conversation.
func (t *Trail) commit(c *conversation, i int) error {
	if err := t.outcome(c, i, agentmessage.OutcomeCommitted, ""); err != nil {
		return err
	}
	e := c.entries[i]
	switch e.Statement.Kind {
	case agentmessage.PersonKindHandOff:
		c.handOffs = append(c.handOffs, HandOff{From: c.owner, To: e.Statement.To, By: e.Statement.From, Entry: e.ID})
		c.owner = e.Statement.To
	case agentmessage.PersonKindClose:
		c.closed = true
	case agentmessage.PersonKindReopen:
		c.closed = false
	}
	return nil
}

// indexAllowed records the id and nonce of an allowed write.
func (c *conversation) indexAllowed(e Entry) {
	c.byMessage[e.Statement.From+"\n"+e.Statement.MessageID] = len(c.entries) - 1
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

// startsTurn says whether a person's entry of this kind sets an AI agent
// working, which is what the turn limit and the hourly limit count.
func startsTurn(kind string) bool {
	return kind == agentmessage.PersonKindMessage || kind == agentmessage.PersonKindAsk
}

// overLimit applies the limits that protect the Identity Agent: the entries one
// conversation may hold, and the messages one person may write in an hour. A
// refusal names the limit. It runs after the rules, before anything is forwarded.
func (t *Trail) overLimit(c *conversation, s agentmessage.PersonStatement) string {
	if len(c.chain) >= t.lim.EntriesPerConversation {
		return ReasonEntryLimit
	}
	if startsTurn(s.Kind) && t.sent.Count(s.From) >= t.lim.MessagesPerPersonPerHour {
		return ReasonRateLimit
	}
	return ""
}

// countAllowed takes an allowed write into the limits: a message starts a new
// turn count, and counts toward its author's hour.
func (t *Trail) countAllowed(c *conversation, s agentmessage.PersonStatement) {
	if !startsTurn(s.Kind) {
		return
	}
	c.turns = 0
	t.sent.Record(s.From)
}
