package trail

import (
	"errors"
	"fmt"
	"strings"

	"identity-agent-core/mediation"
)

// QueueID is the id a kept entry's sealed message is queued under: one id per
// entry, whichever conversation it is in, so two conversations that both have an
// "e1" do not collide in the one delivery queue.
func QueueID(conversation, entry string) string { return conversation + "/" + entry }

// RefuseExpired joins the delivery queue's expiry to the record: for every
// message the queue has held for its whole age, it marks the entry the message
// carried not delivered, and only then deletes the sealed copy and returns the
// message so its sender can be told.
//
// The order is the point. Marking first and deleting after means a failure in
// between loses nothing: the next pass finds the copy again, finds the entry
// already marked, and deletes the copy. Each sender is told, and each entry
// marked, once. An entry that is gone, or was already marked, has nothing left to
// mark and its copy is deleted. A message whose entry is not yet kept is left
// held and named in the error, so a copy past its age is never deleted ahead of
// the record that explains it.
func (t *Trail) RefuseExpired(q *mediation.Queue) ([]mediation.Expired, error) {
	var told []mediation.Expired
	var errs []error
	for _, d := range q.Due() {
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

// markNotDeliveredIfNot marks the entry unless it is gone or already marked.
func (t *Trail) markNotDeliveredIfNot(conversation, entryID, reason string) error {
	c := t.get(conversation)
	if c == nil {
		return nil
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
	return nil
}
