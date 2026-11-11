package conversationbundle

import (
	"fmt"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// CopyOutcome is what checking an app's copy of a conversation's entries
// against the head and count the Identity Agent reports shows (ADR-068,
// contracts/trail).
type CopyOutcome string

const (
	// CopyMatches: the copy is the committed chain, the same entries in the
	// same order, ending at the head.
	CopyMatches CopyOutcome = "matches"
	// CopyRemovedFromTheEnd: fewer entries than the count.
	CopyRemovedFromTheEnd CopyOutcome = "removed from the end"
	// CopyRemovedOrReordered: a place with no entry, or one that does not
	// follow from the entry before it.
	CopyRemovedOrReordered CopyOutcome = "removed or reordered inside"
	// CopySubstituted: the right count, ending at another entry than the head.
	CopySubstituted CopyOutcome = "substituted"
)

// CheckCopy checks the chain of the entries an app hands over against the
// count and head the Identity Agent reports for the conversation. The chain is
// what is checked here: the countersignatures and what each entry says are
// Verify's, over the same entries.
//
// Entries beyond count are uncommitted and are left out, never read as part of
// the conversation. Then, in order: exactly count entries, entry i at place i
// and in this conversation; each entry's prev_hash is the hash of the one
// before it (empty for the first); and the last entry's hash is head. With
// count 0 the copy must be empty and head empty. The error says which entry
// and why; the outcome is empty when the copy is unreadable.
func CheckCopy(conversation string, entries []*didcomm.Envelope, count int, head string) (CopyOutcome, error) {
	if count < 0 {
		return "", fmt.Errorf("a count of %d", count)
	}
	prev := ""
	committed := 0
	for i, env := range entries {
		rec, err := agentmessage.Read(env)
		if err != nil {
			return "", fmt.Errorf("entry %d: %w", i+1, err)
		}
		if rec.Seq > count {
			continue // uncommitted
		}
		if rec.Conversation != conversation {
			return CopyRemovedOrReordered, fmt.Errorf("entry %d belongs to conversation %s", i+1, rec.Conversation)
		}
		if rec.Seq != committed+1 {
			return CopyRemovedOrReordered, fmt.Errorf("entry %d says it is entry %d, so an entry is missing or out of place", i+1, rec.Seq)
		}
		if rec.PrevHash != prev {
			return CopyRemovedOrReordered, fmt.Errorf("entry %d does not follow from the entry before it", rec.Seq)
		}
		prev = agentmessage.Hash(env)
		committed++
	}
	switch {
	case committed < count:
		return CopyRemovedFromTheEnd, fmt.Errorf("the copy holds %d of the %d committed entries", committed, count)
	case prev != head:
		return CopySubstituted, fmt.Errorf("the copy ends at an entry that is not the head")
	}
	return CopyMatches, nil
}
