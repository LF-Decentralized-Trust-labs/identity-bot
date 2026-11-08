package trail

import (
	"context"
	"errors"
	"fmt"

	"identity-agent-core/agentmessage"
)

// Reader is the app's side of a read: the words and salt it holds under the
// entry ids of a range. What it returns is never trusted; Read checks every
// part against the trail before passing any of it on.
type Reader interface {
	Read(ctx context.Context, conversation, first, last string) ([]Stored, error)
}

// Stored is what the app returns for one entry. For a private agent's entry,
// Words is the ciphertext.
type Stored struct {
	EntryID string
	Salt    []byte
	Words   []byte
}

// Passed is an entry's words, checked against the trail, ready to pass on.
type Passed struct {
	Entry Entry
	Salt  []byte
	Words []byte
}

// Plain reasons for a read.
const (
	ReasonMismatch   = "the stored conversation does not match its record"
	ReasonMayNotRead = "you may not read this conversation"
	ReasonBadRange   = "that range is not in this conversation"
	ReasonNoReader   = "the app cannot be read"
	ReasonTooLarge   = "the app returned more than one read may carry"
)

// How a read ended, as the governance record names it.
const (
	ReadPassed   = "passed"
	ReadRefused  = "refused"
	ReadMismatch = "mismatch"
)

// Governance is what a read leaves in the governance record: who asked, which
// range, and what became of it. It holds no words.
type Governance struct {
	Person       string
	Conversation string
	First, Last  string // the range asked for; empty is the whole trail
	Outcome      string
	Reason       string
	Passed       int
	// Dropped counts words the app returned for entries that are pending or
	// not kept. That is normal, and never a mismatch.
	Dropped int
}

// MayRead says who may read a conversation, from the trail and the roster
// alone: whoever opened it, its current owner, and a signer. A former owner
// loses access when they hand it on, and nobody else is admitted by having
// written, been addressed or been named in a hand-off (M83-ARCH §4, §8).
func (t *Trail) MayRead(conversation, person string) bool {
	c := t.get(conversation)
	if c == nil || person == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return t.mayRead(c, person)
}

func (t *Trail) mayRead(c *conversation, person string) bool {
	return person == c.opener || person == c.owner || t.roster.IsSigner(person)
}

// Read serves a range of a conversation for person. The Identity Agent decides
// whether they may read it, asks the app for exactly that range, and checks
// what comes back entry by entry against its trail before passing it on:
//
//   - words for an entry that is pending or not kept are dropped, never counted
//     as tampering (the normal case straight after a write);
//   - words that do not hash to the trail's fingerprint, an entry the trail
//     does not have, one out of order or repeated, or a committed entry the app
//     left out, refuse the whole read.
//
// first and last are entry ids of a person's entries; empty means from the
// start or to the end. An AI agent's entries are not served by Read (ADR-068):
// words the app returns for one are refused as an entry the trail lacks, and
// a range bounded by one is refused.
func (t *Trail) Read(ctx context.Context, person, conversation, first, last string) ([]Passed, error) {
	g := Governance{Person: person, Conversation: conversation, First: first, Last: last}
	out, err := t.read(ctx, &g, person, conversation, first, last)
	if t.record != nil {
		t.record(g)
	}
	return out, err
}

func (t *Trail) read(ctx context.Context, g *Governance, person, conversation, first, last string) ([]Passed, error) {
	refuse := func(outcome, reason string) ([]Passed, error) {
		g.Outcome, g.Reason = outcome, reason
		return nil, errors.New(reason)
	}
	c := t.get(conversation)
	if c == nil || !t.MayRead(conversation, person) {
		return refuse(ReadRefused, ReasonMayNotRead)
	}
	rd, ok := t.backend.(Reader)
	if !ok {
		return refuse(ReadRefused, ReasonNoReader)
	}

	// What the app should return: the committed entries of the range.
	entries := t.Entries(conversation)
	lo, hi, rangeOK := 0, len(entries)-1, true
	if first != "" {
		lo, rangeOK = indexOfID(entries, first)
	}
	if rangeOK && last != "" {
		hi, rangeOK = indexOfID(entries, last)
	}
	if !rangeOK || lo > hi {
		return refuse(ReadRefused, ReasonBadRange)
	}
	var want []Entry
	for _, e := range entries[lo : hi+1] {
		if e.State() == Committed {
			want = append(want, e)
		}
	}

	rctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	got, err := rd.Read(rctx, conversation, first, last)
	if err != nil {
		return refuse(ReadRefused, ReasonTimeoutOrDown(rctx))
	}

	// A read carries at most limits.ReadBytes of words; more than that from the
	// app is refused before any of it is looked at or passed on.
	total := 0
	for _, s := range got {
		total += len(s.Words) + len(s.Salt)
	}
	if total > t.lim.ReadBytes {
		return refuse(ReadRefused, ReasonTooLarge)
	}

	byID := map[string]Entry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	var out []Passed
	next, seen := 0, map[string]bool{}
	for _, s := range got {
		e, known := byID[s.EntryID]
		switch {
		case !known || seen[s.EntryID]:
			return refuse(ReadMismatch, ReasonMismatch)
		case e.State() != Committed:
			seen[s.EntryID] = true
			g.Dropped++
			continue
		}
		seen[s.EntryID] = true
		// Committed: it must be the next one the range expects, and its words
		// must hash to the trail's fingerprint (a private agent's entry, to its
		// ciphertext_hash).
		if next >= len(want) || want[next].ID != e.ID {
			return refuse(ReadMismatch, ReasonMismatch)
		}
		expect := e.Statement.Fingerprint
		if e.CiphertextHash != "" {
			expect = e.CiphertextHash
		}
		if err := agentmessage.CheckFingerprint(e.Statement.FingerprintVersion, s.Salt, s.Words, expect, true); err != nil {
			return refuse(ReadMismatch, ReasonMismatch)
		}
		out = append(out, Passed{Entry: e, Salt: s.Salt, Words: s.Words})
		next++
	}
	if next != len(want) {
		return refuse(ReadMismatch, ReasonMismatch)
	}
	g.Outcome, g.Passed = ReadPassed, len(out)
	return out, nil
}

// ReasonTimeoutOrDown says why the app gave no answer.
func ReasonTimeoutOrDown(ctx context.Context) string {
	if ctx.Err() != nil {
		return ReasonTimeout
	}
	return ReasonUnreachable
}

func indexOfID(es []Entry, id string) (int, bool) {
	for i, e := range es {
		if e.ID == id {
			return i, true
		}
	}
	return 0, false
}

// TurnStarter is the person whose message started the turn that entry belongs
// to: follow what each entry answers back to a person's own entry that answers
// nothing. An onward ask uses that person's reach, never the asking agent's.
func (t *Trail) TurnStarter(conversation, entry string) (string, error) {
	c := t.get(conversation)
	if c == nil {
		return "", errors.New(ReasonNoConv)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID(entry)
	for hops := 0; ok && e.State() == Committed && hops <= len(c.entries); hops++ {
		if e.Statement.InReplyTo == "" {
			if t.roster.IsAIAgent(e.Statement.From) {
				break
			}
			return e.Statement.From, nil
		}
		e, ok = c.byID(e.Statement.InReplyTo)
	}
	return "", fmt.Errorf("no person started the turn that %s is part of", entry)
}

// MayAddress is the @agent check: whether an agent may be addressed, in the
// turn that entry belongs to, by the reach of the person who started it. Both
// halves must allow it, the agent's own grant and that person's reach.
func (t *Trail) MayAddress(conversation, entry, agent string) (bool, error) {
	person, err := t.TurnStarter(conversation, entry)
	if err != nil {
		return false, err
	}
	return t.addressable(person, agent), nil
}

func (t *Trail) addressable(person, agent string) bool {
	return t.roster.IsAIAgent(agent) && t.roster.MayUseAgent(person, agent) && t.roster.AgentGrantAllows(agent, person)
}

// ReadPage serves the committed entries of a conversation from first (empty is
// the start) up to last (empty is the end), but no more than one read may
// carry: when the range is longer, it asks the app for fewer entries until
// what comes back fits, and returns next, the id of the first entry not yet
// served, to read from. An empty next means the range is served to its end.
// Every page is checked against the trail exactly as Read checks it. A single
// entry that does not fit in one read is refused.
func (t *Trail) ReadPage(ctx context.Context, person, conversation, first, last string) (page []Passed, next string, err error) {
	entries := t.Entries(conversation)
	lo, hi := 0, len(entries)-1
	if first != "" {
		var ok bool
		if lo, ok = indexOfID(entries, first); !ok {
			_, err = t.Read(ctx, person, conversation, first, last) // refused and recorded
			return nil, "", err
		}
	}
	if last != "" {
		var ok bool
		if hi, ok = indexOfID(entries, last); !ok {
			_, err = t.Read(ctx, person, conversation, first, last)
			return nil, "", err
		}
	}
	for n := hi - lo + 1; n >= 1; n = n / 2 {
		end := entries[lo+n-1].ID
		if lo+n-1 == hi && last == "" {
			end = ""
		}
		page, err = t.Read(ctx, person, conversation, first, end)
		if err == nil {
			if lo+n-1 < hi {
				next = entries[lo+n].ID
			}
			return page, next, nil
		}
		if err.Error() != ReasonTooLarge || n == 1 {
			return nil, "", err
		}
	}
	// An empty or backwards range: Read refuses it, or serves nothing, and records it.
	page, err = t.Read(ctx, person, conversation, first, last)
	return page, "", err
}
