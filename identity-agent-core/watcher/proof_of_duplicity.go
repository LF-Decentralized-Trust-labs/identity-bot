package watcher

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// A contact is refused on proof of duplicity, never on a count of watchers.
//
// A standing watcher answers a digest. When its digest differs from the log a
// contact presented, the digest alone cannot say who is wrong: the presenter may
// have forked its log, or the watcher may be broken or lying. So the watcher is
// asked for its copy of the log with the controller signatures, and this file
// judges the two with keri-go, which is also what a witness uses (see
// witness/an_event_is_admitted_to_the_log_it_follows.go):
//
//   - the watcher's log must itself verify (self-certifying inception, every
//     event signed by the key state in force); one that does not is the
//     watcher's fault, not the contact's;
//   - each event of it that the presented log does not hold is admitted to the
//     presented log with SignedKELResult.Admit, which applies KERI's rule that a
//     recovery rotation replaces only the interactions after the last
//     establishment event;
//   - a different event at a place the presented log holds, correctly signed
//     under the state before that place, is two histories signed by the one
//     controller: duplicity, proven by the two events, whoever hands them over.
//
// One watcher's evidence is enough, because a watcher cannot forge a controller
// signature. Nothing here counts watchers.

// proofKind is what judging a watcher's log against the presented log found.
type proofKind int

const (
	// proofUnprovable is a disagreement that cannot be settled: the presented
	// log came without its signed bytes, or does not verify, or the watcher
	// would not hand its log over, or the disagreement turns on a delegator's
	// log (a delegated rotation at a taken place, which keri-go refuses and says
	// is not by itself duplicity). Shown to the owner, blocks nothing.
	proofUnprovable proofKind = iota
	// proofFork is two events at one place, each validly signed: duplicity.
	proofFork
	// proofWatcherFaulty is a watcher whose answer does not hold up, shown by its
	// own log: it does not verify, or an event of it does not verify against the
	// state before it.
	proofWatcherFaulty
	// proofAhead is a watcher holding validly signed later events the presented
	// log lacks. The presenter showed a stale key state.
	proofAhead
	// proofSuperseded is a recovery rotation settling a place the two logs hold
	// differently: not duplicity. When the watcher's log carries the rotation the
	// presented log is stale (adopted, as for proofAhead); when the presented log
	// carries it the watcher is merely behind.
	proofSuperseded
	// proofWatcherBehind is a watcher that holds an older branch the presented log
	// supersedes by recovery.
	proofWatcherBehind
)

func (k proofKind) String() string {
	return [...]string{"unprovable", "duplicity", "faulty", "ahead", "superseded", "behind"}[k]
}

// WatcherLog is the log a watcher served for an identity: its own copy as signed
// messages, and any other events it kept at places it already held something
// else at, so it can hand over the conflicting branch it saw and not only the
// first one.
type WatcherLog struct {
	Messages [][]byte
	// Records are the same events as the records the watcher served, one per
	// message, so an adopted log can be handed on in the shape callers hold.
	Records []map[string]interface{}
	Rival   [][]byte
}

// Evidence is what an alert rests on.
type Evidence struct {
	Kind string `json:"kind"` // "duplicity" or "watcher"
	// Identifier is the identity the two events belong to; Reverify refuses
	// events of any other.
	Identifier  string `json:"identifier,omitempty"`
	SequenceNum int    `json:"sequence_number"`
	// HeldMessage and RivalMessage are the two signed events at the contested
	// place, each as an event with its attached signatures (base64). Anyone can
	// verify either with keri.VerifyEvent against the state before the place.
	HeldMessage  string `json:"held_message_b64,omitempty"`
	RivalMessage string `json:"rival_message_b64,omitempty"`
	// PriorMessages is the signed log up to the place before the contested one
	// (base64, one message per event), which is what the key state the two
	// events are checked against is made of. With it an alert can be
	// re-verified from what it stores alone, whatever happens to the kept log.
	PriorMessages []string `json:"prior_messages_b64,omitempty"`
	// Watcher is the standing watcher the rival event came from, or the one flagged.
	Watcher string `json:"watcher,omitempty"`
	// Why says, for a watcher alert, how its answer did not hold up.
	Why string `json:"why,omitempty"`
}

// Reverify checks a duplicity alert's evidence from what it stores and nothing
// else: the prior log verifies, and both events at the contested place verify
// against the state it leaves, and are two different events. Anyone can run it.
func (e Evidence) Reverify() error {
	if e.Kind != "duplicity" {
		return errors.New("only duplicity evidence holds two signed events")
	}
	if e.HeldMessage == "" || e.RivalMessage == "" {
		return errors.New("the evidence does not hold both events")
	}
	var before *keri.KeyState
	var prior [][]byte
	if e.SequenceNum > 0 {
		for _, p := range e.PriorMessages {
			m, err := base64.StdEncoding.DecodeString(p)
			if err != nil {
				return fmt.Errorf("a prior event does not decode: %w", err)
			}
			prior = append(prior, m)
		}
		if len(prior) != e.SequenceNum {
			return fmt.Errorf("the log before place %d is not stored with the evidence", e.SequenceNum)
		}
		log, err := keri.ValidateSignedKEL(prior)
		if err != nil {
			return fmt.Errorf("the log before the contested place does not verify: %w", err)
		}
		before = log.State()
	}
	var said [2]string
	var msgs [2][]byte
	for i, b64 := range []string{e.HeldMessage, e.RivalMessage} {
		m, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("an event does not decode: %w", err)
		}
		msgs[i] = m
		v, err := keri.VerifyEvent(before, m)
		if err != nil {
			return fmt.Errorf("an event at place %d does not verify: %w", e.SequenceNum, err)
		}
		ev, err := keri.ParseEvent(m)
		if err != nil || int(ev.SN) != e.SequenceNum {
			return errors.New("an event is not at the contested place")
		}
		_ = v
		if e.Identifier == "" || ev.Identifier != e.Identifier {
			return errors.New("an event is not of the identity the evidence is about")
		}
		said[i] = ev.SAID
	}
	if said[0] == said[1] {
		return errors.New("the two events are the same event")
	}
	// A recovery rotation replaces an interaction at its place, in either
	// direction: the pair is then one history and its repair, not a fork.
	if e.SequenceNum > 0 {
		if recoveryRetires(prior, msgs[0], msgs[1]) || recoveryRetires(prior, msgs[1], msgs[0]) {
			return errors.New("one event is a recovery rotation replacing the other, which is not duplicity")
		}
	}
	return nil
}

func (e Evidence) json() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// proof is the outcome of judging one watcher's log.
type proof struct {
	Kind     proofKind
	Reason   string
	Evidence *Evidence
	// Latest is, for proofAhead and proofSuperseded, the verified log with the
	// watcher's later events admitted, and LatestMessages its signed messages.
	Latest         *keri.SignedKELResult
	LatestMessages [][]byte
	LatestRecords  []map[string]interface{}
	// AlsoFaulty is set when the watcher's answer held a rival that does not
	// verify beside one that does: the verdict stands on the valid one, and the
	// watcher is flagged for the other.
	AlsoFaulty string
}

// judgeWatcherLog is the classifier. presented are the presented log's signed
// messages, in order.
func judgeWatcherLog(aid string, presented [][]byte, theirs *WatcherLog) proof {
	cur, err := keri.ValidateSignedKEL(presented)
	if err != nil {
		return proof{Kind: proofUnprovable, Reason: "the presented log does not verify: " + err.Error()}
	}
	if cur.Identifier != aid {
		return proof{Kind: proofUnprovable, Reason: "the presented log is for another identity"}
	}
	if len(theirs.Messages) == 0 {
		return proof{Kind: proofUnprovable, Reason: "it gave a digest but showed no log for it, so nothing can be proven either way"}
	}
	theirLog, err := keri.ValidateSignedKEL(theirs.Messages)
	if err != nil {
		return proof{Kind: proofWatcherFaulty, Reason: "its log does not verify: " + err.Error()}
	}
	if theirLog.Identifier != aid {
		return proof{Kind: proofWatcherFaulty, Reason: "its log is for another identity"}
	}

	msgs := append([][]byte(nil), presented...) // the messages of cur, by place
	moved, superseding := false, false

	// conflict judges an event at a place cur holds something else at.
	conflict := func(ev *keri.Event, message []byte) (*proof, bool) {
		if ev.Ilk == "drt" {
			p := proof{Kind: proofUnprovable, Reason: "a delegated rotation at a place already held: " +
				"whether it may replace the held event turns on its delegator's log, which is not by itself duplicity"}
			return &p, true
		}
		var before *keri.KeyState
		if ev.SN > 0 {
			before = cur.StateAt(ev.SN - 1)
		}
		if _, err := keri.VerifyEvent(before, message); err != nil {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log at place " +
				fmt.Sprint(ev.SN) + " does not verify against the state before it: " + err.Error()}, true
		}
		// The rival may be what a recovery rotation the presented log holds at this
		// place retires: a recovery rotation replaces the interactions after the last
		// establishment event, and an interaction the retired key signed there is
		// not a second history, whether the watcher holds it in its log or kept it
		// as a rival (keripy does not call it duplicity either). The case where the
		// watcher's log carries the rotation is the admission above, which supersedes.
		if int(ev.SN) < len(msgs) && recoveryRetires(msgs[:ev.SN], message, msgs[ev.SN]) {
			return &proof{Kind: proofWatcherBehind, Reason: "the presented log holds a recovery rotation " +
				"at place " + fmt.Sprint(ev.SN) + " that supersedes what the watcher holds"}, true
		}
		prior := make([]string, 0, ev.SN)
		for _, m := range msgs[:ev.SN] {
			prior = append(prior, base64.StdEncoding.EncodeToString(m))
		}
		return &proof{Kind: proofFork, Reason: fmt.Sprintf("two validly signed events at place %d", ev.SN),
			Evidence: &Evidence{
				Kind: "duplicity", Identifier: aid, SequenceNum: int(ev.SN),
				HeldMessage:   base64.StdEncoding.EncodeToString(msgs[ev.SN]),
				RivalMessage:  base64.StdEncoding.EncodeToString(message),
				PriorMessages: prior,
			}}, true
	}

	// admit takes one event of the watcher's into cur. It returns a proof when
	// that settles the matter.
	admit := func(message []byte, rival bool) *proof {
		ev, err := keri.ParseEvent(message)
		if err != nil {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log does not parse"}
		}
		if ev.Identifier != aid {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log belongs to another identity"}
		}
		if held := cur.StateAt(ev.SN); held != nil && held.Digest() == ev.SAID {
			return nil // the same event
		}
		adm, err := cur.Admit(message)
		var ve *keri.ValidationError
		switch {
		case err == nil:
			if rival {
				return nil // a second branch of the watcher's does not move this log
			}
			if adm.Supersedes > 0 {
				superseding = true
			}
			msgs = append(msgs[:len(msgs)-adm.Supersedes], message)
			cur, moved = adm.Log, true
			return nil
		case errors.As(err, &ve) && ve.Has(keri.FaultPlaceTaken):
			p, _ := conflict(ev, message)
			return p
		case errors.As(err, &ve) && ve.Has(keri.FaultSequenceSkip) && rival:
			return nil // a branch beyond what the presented log holds says nothing about it
		default:
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log is refused by the presented log's own rules: " + err.Error()}
		}
	}

	// A recovery rotation of the presented log over the watcher's older branch
	// settles the whole branch: the events after it are the retired ones.
	settle := func(p *proof) (proof, bool) {
		if p == nil {
			return proof{}, false
		}
		return *p, true
	}
	for _, m := range theirs.Messages {
		if p, done := settle(admit(m, false)); done {
			return p
		}
	}
	// Every rival is examined. One that does not verify flags the watcher and is
	// set aside; it does not hide a valid one behind it.
	alsoFaulty := ""
	for _, m := range theirs.Rival {
		p, done := settle(admit(m, true))
		if !done {
			continue
		}
		if p.Kind == proofWatcherFaulty {
			if alsoFaulty == "" {
				alsoFaulty = p.Reason
			}
			continue
		}
		p.AlsoFaulty = alsoFaulty
		return p
	}
	switch {
	case superseding:
		return proof{Kind: proofSuperseded, Reason: "a recovery rotation the watcher holds replaces the presented log's later interactions",
			Latest: cur, LatestMessages: msgs, AlsoFaulty: alsoFaulty}
	case moved:
		return proof{Kind: proofAhead, Reason: "the watcher holds later signed events the presented log lacks",
			Latest: cur, LatestMessages: msgs, AlsoFaulty: alsoFaulty}
	case alsoFaulty != "":
		return proof{Kind: proofWatcherFaulty, Reason: alsoFaulty}
	}
	// The same events, another digest: the two sides digest different renderings
	// of them. Nothing is proven against either, so it is shown, not flagged.
	return proof{Kind: proofUnprovable, Reason: "its digest differs from the presented log's, " +
		"yet its own log holds exactly the presented events"}
}

// recoveryRetires says whether recovery, applied to the log made of prefix and
// the event retired, replaces retired: the recovery rotation sits at the same
// place and KERI's rule lets it supersede an interaction there. Both are signed
// messages and are verified here, so nothing is taken on the caller's word.
func recoveryRetires(prefix [][]byte, retired, recovery []byte) bool {
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
