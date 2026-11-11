package conversationbundle

import (
	"fmt"
	"sort"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// CopyOutcome is what checking an app's copy of a conversation's entries
// against the head and count the Identity Agent reports shows (ADR-068,
// contracts/trail).
type CopyOutcome string

const (
	// CopyMatches: the copy holds the committed chain, one entry for every
	// place, ending at the head.
	CopyMatches CopyOutcome = "matches"
	// CopyRemovedFromTheEnd: fewer entries than the count, with none missing
	// from inside.
	CopyRemovedFromTheEnd CopyOutcome = "removed from the end"
	// CopyRemovedOrReordered: a place with no entry, an entry of another
	// conversation or at the wrong place, or one that does not follow from the
	// entry before it. An entry inside the chain replaced by another one shows
	// here too, because the entry after it no longer follows from it.
	CopyRemovedOrReordered CopyOutcome = "removed or reordered inside"
	// CopySubstituted: every place is held and chained, but no chain ends at the
	// head.
	CopySubstituted CopyOutcome = "substituted"
	// CopyNotCountersigned: the chain matches, but an entry's countersignature
	// does not hold (only when a check of it is given).
	CopyNotCountersigned CopyOutcome = "not countersigned"
)

// CopyResult is what CheckCopy found. Committed is the chain, in order, when
// the outcome is CopyMatches and empty otherwise.
type CopyResult struct {
	Outcome   CopyOutcome
	Committed []*didcomm.Envelope
	// Beyond are the entries past the count: not committed, never read as part
	// of the conversation.
	Beyond []*didcomm.Envelope
	// Ignored are entries held at a place inside the count that are not the
	// committed one: a write that lost the race for its place and has not yet
	// been discarded. They never make a copy fail, and are reported so that
	// nobody reads a copy as holding one entry per place when it holds more.
	Ignored []*didcomm.Envelope
	// SignaturesChecked says the check of countersignatures was asked of every
	// committed entry.
	SignaturesChecked bool
}

// CheckSignature, if given to CheckCopy, is asked to check one entry's
// countersignature (it needs the keys of whoever countersigned). The chain and
// the head are checked whether or not it is given; the result says whether it
// was.
type CheckSignature func(env *didcomm.Envelope) error

// CheckCopy checks the entries an app hands over against the count and head the
// Identity Agent reports for the conversation. This is the one copy of the
// check: the open format's verifier (Verify) uses it, and an add-on that keeps
// conversations calls it rather than carrying its own.
//
// A copy may hold more than one entry for a place: every entry is kept by the
// app before it is committed, so two writes racing for one place are both held
// until the one that lost is discarded by its hash. The committed entry is the
// one chosen from the head back: the one whose hash is the head, then at each
// place the one whose hash the entry after it names as its prev_hash. It is never
// chosen by its position in the copy or by which was kept first, so the copy may
// come in any order. Two entries that are the same entry (one hash) are one.
//
// Entries beyond count are uncommitted and left out. Then, for the places 1 to
// count: every place holds an entry, in this conversation and saying it is that
// place's; the first follows from nothing (empty prev_hash) and each of the
// others from an entry held at the place before it; and a chain of these ends
// at head. With count 0 the copy holds nothing inside the count and head is
// empty. The error says which entry and why; the outcome is empty when the copy
// is unreadable.
func CheckCopy(conversation string, entries []*didcomm.Envelope, count int, head string, sig CheckSignature) (CopyResult, error) {
	if count < 0 {
		return CopyResult{}, fmt.Errorf("a count of %d", count)
	}
	type held struct {
		env  *didcomm.Envelope
		rec  agentmessage.Record
		hash string
	}
	at := map[int][]held{}
	var res CopyResult
	for i, env := range entries {
		rec, err := agentmessage.Read(env)
		if err != nil {
			return CopyResult{}, fmt.Errorf("entry %d: %w", i+1, err)
		}
		switch {
		case rec.Conversation != conversation:
			return CopyResult{Outcome: CopyRemovedOrReordered}, fmt.Errorf("entry %d belongs to conversation %s", i+1, rec.Conversation)
		case rec.Seq < 1:
			return CopyResult{Outcome: CopyRemovedOrReordered}, fmt.Errorf("entry %d names no place", i+1)
		case rec.Seq > count:
			res.Beyond = append(res.Beyond, env)
		default:
			at[rec.Seq] = append(at[rec.Seq], held{env, rec, agentmessage.Hash(env)})
		}
	}
	sort.SliceStable(res.Beyond, func(i, j int) bool {
		a, _ := agentmessage.Read(res.Beyond[i])
		b, _ := agentmessage.Read(res.Beyond[j])
		return a.Seq < b.Seq
	})
	fail := func(o CopyOutcome, format string, args ...any) (CopyResult, error) {
		return CopyResult{Outcome: o, Beyond: res.Beyond}, fmt.Errorf(format, args...)
	}
	// reach[i] is the entries at place i that follow from an entry reached at
	// place i-1.
	reach := make([][]held, count+1)
	reached := map[string]bool{"": true}
	missing := 0
	for i := 1; i <= count; i++ {
		if len(at[i]) == 0 {
			if missing == 0 {
				missing = i
			}
			continue
		}
		if missing != 0 {
			return fail(CopyRemovedOrReordered, "entry %d is missing from inside the trail", missing)
		}
		next := map[string]bool{}
		for _, h := range at[i] {
			if reached[h.rec.PrevHash] {
				reach[i] = append(reach[i], h)
				next[h.hash] = true
			}
		}
		if len(reach[i]) == 0 {
			return fail(CopyRemovedOrReordered, "entry %d does not follow from entry %d", i, i-1)
		}
		reached = next
	}
	if missing != 0 {
		return fail(CopyRemovedFromTheEnd, "the copy holds %d of the %d committed entries", missing-1, count)
	}
	if count == 0 {
		if head != "" {
			return fail(CopySubstituted, "the Identity Agent holds a head for a conversation with no committed entries")
		}
		return CopyResult{Outcome: CopyMatches, Beyond: res.Beyond}, nil
	}
	// The committed chain, from the head back.
	want := head
	chosen := make([]held, count+1)
	for i := count; i >= 1; i-- {
		found := false
		for _, h := range reach[i] {
			if h.hash == want {
				chosen[i], found = h, true
				break
			}
		}
		if !found {
			return fail(CopySubstituted, "the copy ends at an entry that is not the head")
		}
		want = chosen[i].rec.PrevHash
	}
	for i := 1; i <= count; i++ {
		res.Committed = append(res.Committed, chosen[i].env)
		for _, h := range at[i] {
			if h.hash != chosen[i].hash {
				res.Ignored = append(res.Ignored, h.env)
			}
		}
	}
	if sig != nil {
		for i, env := range res.Committed {
			if err := sig(env); err != nil {
				return fail(CopyNotCountersigned, "entry %d is not countersigned: %v", i+1, err)
			}
		}
		res.SignaturesChecked = true
	}
	res.Outcome = CopyMatches
	return res, nil
}
