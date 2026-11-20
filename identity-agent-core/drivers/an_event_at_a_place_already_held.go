package drivers

import (
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// What an event is to a verified log that holds a different event at its
// place: the judgement of "two events at one place" (ADR-075).
//
// It lives here, beside the one log validator, because it is arithmetic over
// signed bytes already in hand, and more than one reader needs it.
//
// What is shared today, and what is not yet:
//
//   - JudgeAtTakenPlace judges the event against the one log it arrived for.
//     A watcher's answer is judged by it (watcher.judgeWatcherLog), and so is
//     everything below.
//   - JudgeCopiesAtTakenPlace judges the same event with the other copy in
//     hand as well, and adds one check: a recovery rotation counts as a repair
//     only if the copy it retires would itself admit it. A branch that goes on
//     to an establishment event cannot be retired, so that pair is a fork.
//     The two-log ownership check uses it.
//   - The watcher does not make that second check. Shown [icp, rot] against a
//     watcher holding [icp, ixn, rot], it calls the watcher behind; shown the
//     two the other way round, it finds the fork. Bringing the watcher to
//     JudgeCopiesAtTakenPlace changes what a running Identity Agent decides
//     about a contact, so it is left for a change of its own.

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
	// TakenUnsettled is a pair JudgeCopiesAtTakenPlace could call neither a
	// repair nor a fork. JudgeAtTakenPlace never returns it.
	TakenUnsettled
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

// JudgeCopiesAtTakenPlace is JudgeAtTakenPlace where the event comes from
// another verified copy of the same log, other, whose signed messages by place
// are otherMessages. It differs in one case. Where log holds a recovery
// rotation at the place, the event is TakenRetired only if other would admit
// that rotation as a recovery: it replaces interactions, and never an
// establishment event further along the branch it retires. Where other refuses
// it as a second event at a taken place, the controller signed both branches
// and the pair is TakenFork. Anything else is TakenUnsettled, with the reason.
func JudgeCopiesAtTakenPlace(log *keri.SignedKELResult, messages [][]byte, other *keri.SignedKELResult, otherMessages [][]byte, ev *keri.Event, message []byte) (TakenPlace, error) {
	found, err := JudgeAtTakenPlace(log, messages, ev, message)
	if found != TakenRetired {
		return found, err
	}
	recovery := messages[ev.SN]
	back, err := other.Admit(recovery)
	if err == nil && back.Supersedes > 0 {
		return TakenRetired, nil
	}
	var refusal *keri.ValidationError
	if errors.As(err, &refusal) && refusal.Has(keri.FaultPlaceTaken) {
		raw, perr := keri.EventOfMessage(recovery)
		if perr != nil {
			return TakenUnsettled, perr
		}
		held, perr := keri.ParseEvent(raw)
		if perr != nil {
			return TakenUnsettled, perr
		}
		if found, _ := JudgeAtTakenPlace(other, otherMessages, held, recovery); found == TakenFork {
			return TakenFork, nil
		}
	}
	return TakenUnsettled, fmt.Errorf("the recovery rotation at place %d and the event the other copy holds there cannot be settled", ev.SN)
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
