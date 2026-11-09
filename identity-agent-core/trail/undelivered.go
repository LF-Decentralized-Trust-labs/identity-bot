package trail

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"identity-agent-core/agentmessage"
	"identity-agent-core/mediation"
)

// QueueID is the id a kept entry's sealed message is queued under: one id per
// entry, whichever conversation it is in, so two conversations that both have an
// "e1" do not collide in the one delivery queue.
func QueueID(conversation, entry string) string { return conversation + "/" + entry }

// Keeps says whether this trail keeps the conversation.
func (t *Trail) Keeps(conversation string) bool { return t.get(conversation) != nil }

// RefuseExpired joins the delivery queue's expiry to the record: for each of the
// named messages the queue has held for its whole age, it marks the entry the
// message carried not delivered, and only then deletes the sealed copy and
// returns the message so its sender can be told. With no ids it takes every
// message that is due.
//
// The order is the point. Marking first and deleting after means a failure in
// between loses nothing: the next pass finds the copy again, finds the entry
// already marked, and deletes the copy. Each sender is told, and each entry
// marked, once. An entry that is gone, or was already marked, has nothing left to
// mark and its copy is deleted. A message whose conversation or entry is not
// kept here is left held and named in the error, so a copy past its age is never
// deleted ahead of the record that explains it.
func (t *Trail) RefuseExpired(q *mediation.Queue, ids ...string) ([]mediation.Expired, error) {
	var told []mediation.Expired
	var errs []error
	for _, d := range q.Due() {
		if len(ids) > 0 && !slices.Contains(ids, d.ID) {
			continue
		}
		entry := strings.TrimPrefix(d.ID, d.Conversation+"/")
		if err := t.markNotDeliveredIfNot(d.Conversation, entry, d.Reason); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
			continue
		}
		if err := q.Discard(d.ID); err != nil {
			if errors.Is(err, mediation.ErrNothingHeld) {
				continue
			}
			errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
			continue
		}
		told = append(told, d)
	}
	return told, errors.Join(errs...)
}

// markNotDeliveredIfNot marks the entry unless it is gone or already marked. A
// conversation this trail does not keep is an error, not a success: the message
// is some other record's to mark.
func (t *Trail) markNotDeliveredIfNot(conversation, entryID, reason string) error {
	c := t.get(conversation)
	if c == nil {
		return errors.New("this trail does not keep that conversation")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.entries {
		e := c.entries[i]
		if e.ID != entryID {
			continue
		}
		if e.NotDelivered != nil {
			return nil
		}
		if e.State() != Committed {
			return errors.New("the entry is not kept yet, so it cannot be marked not delivered")
		}
		return t.noteNotDelivered(c, i, reason)
	}
	return t.markAnAgentsEntry(c, entryID, reason)
}

// markAnAgentsEntry marks an entry of an AI agent, which the chain holds and
// c.entries does not. An id the chain does not hold is gone and has nothing to
// mark; an entry already marked is left as it is.
func (t *Trail) markAnAgentsEntry(c *conversation, entryID, reason string) error {
	var held bool
	for _, ce := range c.chain {
		if agentmessage.EntryID(ce.Seq) == entryID {
			held = true
		}
		rec, err := agentmessage.Read(ce.Envelope)
		if err == nil && rec.Outcome != nil && rec.Outcome.Entry == entryID && rec.Outcome.State == agentmessage.OutcomeNotDelivered {
			return nil
		}
	}
	if !held {
		return nil
	}
	rec := agentmessage.Record{
		MessageID: EntryID(len(c.chain) + 1), Kind: agentmessage.KindOutcome, From: t.agent, InReplyTo: entryID,
		BodyHash: agentmessage.HashBody(nil),
		Outcome:  &agentmessage.Outcome{Entry: entryID, State: agentmessage.OutcomeNotDelivered, Reason: reason},
	}
	_, err := t.countersign(c, rec)
	return err
}
