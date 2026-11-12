package watcher

import "bytes"

// What a repeat contact's log is judged against: the signed log this agent last
// accepted for the identity, kept because a digest cannot say whether two logs
// that differ at one place are duplicity or a recovery rotation replacing the
// interactions after the last establishment event. The events can: the
// presented log's events are admitted to the kept one with keri-go's Admit
// (judgeWatcherLog, the classifier the standing watchers' logs go through), so
// there is one rule for what a fork is.
type seenVerdict int

const (
	// seenSame: the presented log is the kept one, or a part of it (an older
	// sighting), or a branch the kept log has superseded by recovery. Nothing
	// new, and nothing refused.
	seenSame seenVerdict = iota
	// seenMoved: the presented log goes on from the kept one, or replaces its
	// later interactions by a recovery rotation. Not duplicity; it becomes the
	// kept log.
	seenMoved
	// seenFork: two events at one place, each validly signed. Duplicity.
	seenFork
	// seenUnprovable: the two cannot be settled by their events (a delegated
	// rotation at a taken place, a log this agent holds that does not read).
	seenUnprovable
)

// judgeAgainstSeen judges a presented log that verified against the one kept.
// merged is the log to keep when the verdict is seenMoved.
func judgeAgainstSeen(aid string, seen, presented [][]byte) (v seenVerdict, p proof, merged [][]byte) {
	if isPrefix(presented, seen) {
		return seenSame, proof{}, nil
	}
	p = judgeWatcherLog(aid, seen, &WatcherLog{Messages: presented})
	switch p.Kind {
	case proofFork:
		return seenFork, p, nil
	case proofAhead, proofSuperseded:
		return seenMoved, p, p.LatestMessages
	case proofWatcherBehind:
		return seenSame, p, nil // the kept log holds the recovery that retires this branch
	default:
		return seenUnprovable, p, nil
	}
}

// isPrefix is whether short is the first events of long, byte for byte.
func isPrefix(short, long [][]byte) bool {
	if len(short) > len(long) {
		return false
	}
	for i := range short {
		if !bytes.Equal(short[i], long[i]) {
			return false
		}
	}
	return true
}
