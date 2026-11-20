package drivers

import (
	keri "github.com/grapeid/keri-go"
)

// What an event is to a verified log that holds a different event at its
// place: the one judgement of "two events at one place" (ADR-075).
//
// It lives here, beside the one log validator, because it is arithmetic over
// signed bytes already in hand, and more than one reader needs it: a watcher's
// answer is judged by it, and so is any other pair of copies of one log. A
// second copy of this rule could only disagree with the first about whether an
// identity signed two histories.

// TakenPlace is what JudgeAtTakenPlace found.
type TakenPlace int

const (
	// TakenUnverified is an event that does not verify against the key state
	// before its place. It is evidence of nothing about the identity: anybody
	// can write bytes.
	TakenUnverified TakenPlace = iota
	// TakenDelegated is a delegated rotation at a place already held. Whether
	// it may replace the held event turns on its delegator's log, so it is not
	// by itself duplicity.
	TakenDelegated
	// TakenRetired is an event the log's own recovery rotation at that place
	// replaces: one history and its repair.
	TakenRetired
	// TakenFork is two validly signed events at one place, neither a recovery
	// of the other: duplicity, proven by the two events.
	TakenFork
)

// JudgeAtTakenPlace judges message, an event of the identity whose verified log
// is log, at a place where the log holds a different event and refused to
// admit this one (keri.FaultPlaceTaken). messages are the log's signed
// messages by place, and ev is message parsed. The error says why an event
// that is TakenUnverified does not verify.
func JudgeAtTakenPlace(log *keri.SignedKELResult, messages [][]byte, ev *keri.Event, message []byte) (TakenPlace, error) {
	if ev.Ilk == "drt" {
		return TakenDelegated, nil
	}
	var before *keri.KeyState
	if ev.SN > 0 {
		before = log.StateAt(ev.SN - 1)
	}
	if _, err := keri.VerifyEvent(before, message); err != nil {
		return TakenUnverified, err
	}
	// The event may be what a recovery rotation the log holds at this place
	// retires: a recovery rotation replaces the interactions after the last
	// establishment event, and an interaction the retired key signed there is
	// not a second history (keripy does not call it duplicity either).
	if ev.SN < uint64(len(messages)) && RecoveryRetires(messages[:ev.SN], message, messages[ev.SN]) {
		return TakenRetired, nil
	}
	return TakenFork, nil
}

// RecoveryRetires says whether recovery, applied to the log made of prefix and
// the event retired, replaces retired: the recovery rotation sits at the same
// place and KERI's rule lets it supersede an interaction there. Both are signed
// messages and are verified here, so nothing is taken on the caller's word.
func RecoveryRetires(prefix [][]byte, retired, recovery []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	branch := append(append([][]byte(nil), prefix...), retired)
	log, err := keri.ValidateSignedKEL(branch)
	if err != nil {
		return false
	}
	adm, err := log.Admit(recovery)
	return err == nil && adm.Supersedes > 0
}
